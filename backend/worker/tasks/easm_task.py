"""
External Attack Surface Management (EASM)
- Discovers externally-visible assets for an organization domain
- Combines: subdomain enumeration, port scanning, certificate transparency, shodan-style checks
- Tracks new assets discovered vs previous runs and alerts on changes
- Periodic Celery beat task (daily)
"""
import subprocess
import json
import re
import requests
from datetime import datetime, timezone
from typing import Optional
import psycopg2
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)
from core.config import settings


def _get_conn():
    return psycopg2.connect(settings.DATABASE_URL_SYNC)


def _discover_subdomains_ct(domain: str) -> list:
    """Discover subdomains via Certificate Transparency logs (crt.sh)."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, headers={"User-Agent": "Leruo-EASM/1.0"}
        )
        data = resp.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub.lower())
        return sorted(subs)
    except Exception:
        return []


def _discover_subdomains_dns(domain: str, scan_id: str) -> list:
    """Discover subdomains via amass/subfinder/theHarvester."""
    subs = []

    # Try subfinder first (fast)
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-o", "/dev/stdout"],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            subs += [s.strip() for s in result.stdout.splitlines() if s.strip()]
            publish_output(scan_id, f"[easm] subfinder found {len(subs)} subdomains")
    except FileNotFoundError:
        pass

    # Try theHarvester
    if not subs:
        try:
            result = subprocess.run(
                ["theHarvester", "-d", domain, "-l", "100", "-b", "bing,duckduckgo,certspotter", "-f", "/tmp/harvester_easm"],
                capture_output=True, text=True, timeout=60
            )
            # Parse IPs and hosts from output
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.endswith(f".{domain}"):
                    subs.append(line.lower())
        except FileNotFoundError:
            pass

    # Fallback: DNS brute force with dnsrecon
    if not subs:
        try:
            result = subprocess.run(
                ["dnsrecon", "-d", domain, "-t", "brt", "--lifetime", "1", "-j", "/tmp/dnsrecon_easm.json"],
                capture_output=True, text=True, timeout=60
            )
            try:
                with open("/tmp/dnsrecon_easm.json") as f:
                    data = json.load(f)
                for record in data:
                    if record.get("name", "").endswith(f".{domain}"):
                        subs.append(record["name"].lower())
            except Exception:
                pass
        except FileNotFoundError:
            pass

    return list(set(subs))


def _port_scan_host(host: str, quick: bool = True) -> list:
    """Quick port scan of a host, return list of open ports."""
    ports = "80,443,8080,8443,22,21,25,587,3389,3306,5432,6379,27017" if quick else "1-1024"
    try:
        result = subprocess.run(
            ["nmap", "-p", ports, "--open", "-Pn", "-T4", "--host-timeout", "10s", host, "-oX", "-"],
            capture_output=True, text=True, timeout=30
        )
        open_ports = re.findall(r'portid="(\d+)"[^>]*state="open"', result.stdout)
        return [int(p) for p in open_ports]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP."""
    try:
        result = subprocess.run(["dig", "+short", host, "A"], capture_output=True, text=True, timeout=5)
        ips = [l.strip() for l in result.stdout.splitlines() if re.match(r"\d+\.\d+\.\d+\.\d+", l.strip())]
        return ips[0] if ips else None
    except Exception:
        return None


def _check_new_assets(org_id: str, discovered: list) -> list:
    """Return list of hosts not already in assets table for this org."""
    if not discovered:
        return []
    conn = _get_conn()
    cur = conn.cursor()
    # Build tuple of hostnames for IN clause
    placeholders = ",".join(["%s"] * len(discovered))
    cur.execute(
        f"SELECT hostname, domain FROM assets WHERE org_id = %s AND (hostname IN ({placeholders}) OR domain IN ({placeholders}))",
        [org_id] + discovered + discovered
    )
    existing = set()
    for row in cur.fetchall():
        if row[0]:
            existing.add(row[0].lower())
        if row[1]:
            existing.add(row[1].lower())
    cur.close()
    conn.close()
    return [h for h in discovered if h.lower() not in existing]


def _auto_create_asset(org_id: str, hostname: str, ip: Optional[str], asset_type: str = "server"):
    """Insert a newly discovered external asset into the assets table."""
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO assets (org_id, name, hostname, ip_address, asset_type, is_active, tags, created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, TRUE, %s, NOW(), NOW())
               ON CONFLICT DO NOTHING""",
            (org_id, hostname, hostname, ip, asset_type, json.dumps(["easm-discovered"]))
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


@celery_app.task(bind=True, name="worker.tasks.easm_task.run_easm", max_retries=0)
def run_easm(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    """
    External Attack Surface Management scan for a domain.
    Options:
      - domain: primary domain to enumerate (defaults to target)
      - auto_add_assets: bool - auto-add newly found assets to DB
      - port_scan: bool - quick port scan each discovered host
      - alert_new: bool - create findings for newly discovered hosts
    """
    domain = options.get("domain", target)
    auto_add = options.get("auto_add_assets", True)
    do_port_scan = options.get("port_scan", True)
    alert_new = options.get("alert_new", True)

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[easm] Starting external attack surface discovery for {domain}")

    findings = []
    raw_lines = [f"EASM Scan: {domain}", f"Started: {datetime.now(timezone.utc).isoformat()}"]

    # ── Phase 1: Subdomain Discovery ────────────────────────────────────────
    publish_output(scan_id, "[easm] Phase 1: Certificate Transparency log enumeration...")
    ct_subs = _discover_subdomains_ct(domain)
    publish_output(scan_id, f"[easm] CT logs: {len(ct_subs)} subdomains found")

    publish_output(scan_id, "[easm] Phase 2: Active DNS subdomain enumeration...")
    dns_subs = _discover_subdomains_dns(domain, scan_id)
    publish_output(scan_id, f"[easm] DNS brute: {len(dns_subs)} subdomains found")

    all_subdomains = list(set(ct_subs + dns_subs + [domain]))
    publish_output(scan_id, f"[easm] Total unique subdomains: {len(all_subdomains)}")
    raw_lines.append(f"\n=== DISCOVERED SUBDOMAINS ({len(all_subdomains)}) ===")
    raw_lines.extend(all_subdomains[:100])

    # ── Phase 2: Resolve + Port Scan ────────────────────────────────────────
    host_data = []
    for sub in all_subdomains[:50]:  # cap at 50 for performance
        ip = _resolve_host(sub)
        open_ports = []
        if ip and do_port_scan:
            open_ports = _port_scan_host(sub, quick=True)
            if open_ports:
                publish_output(scan_id, f"[easm] {sub} ({ip}): open ports {open_ports}")

        host_data.append({"host": sub, "ip": ip, "ports": open_ports})

        # Check for risky exposed services
        risky = {
            3389: ("critical", "RDP", "RDP (port 3389) exposed to the internet enables brute-force and BlueKeep-style attacks"),
            22: ("medium", "SSH", "SSH exposed to internet. Ensure strong key-based auth and no root login."),
            3306: ("high", "MySQL", "MySQL (port 3306) directly exposed to internet — database should not be publicly accessible"),
            5432: ("high", "PostgreSQL", "PostgreSQL (port 5432) directly exposed to internet"),
            6379: ("critical", "Redis", "Redis (port 6379) exposed to internet — unauthenticated Redis allows arbitrary code execution"),
            27017: ("high", "MongoDB", "MongoDB (port 27017) exposed to internet — may allow unauthorized data access"),
            21: ("medium", "FTP", "FTP (port 21) exposed — cleartext protocol, use SFTP instead"),
            23: ("high", "Telnet", "Telnet (port 23) exposed — unencrypted remote access"),
            25: ("medium", "SMTP", "SMTP (port 25) exposed — check for open relay"),
            8080: ("low", "HTTP-alt", "Alternate HTTP port 8080 exposed — may be a development/admin service"),
            8443: ("low", "HTTPS-alt", "Alternate HTTPS port 8443 exposed"),
        }
        for port in open_ports:
            if port in risky:
                sev, svc_name, desc = risky[port]
                findings.append({
                    "title": f"Exposed {svc_name} service on {sub}:{port}",
                    "description": f"{desc}. Discovered during EASM scan of {domain}.",
                    "severity": sev,
                    "affected_component": f"{sub}:{port}",
                    "affected_port": port,
                    "affected_service": svc_name.lower(),
                    "remediation": f"Restrict access to port {port} using firewall rules. Only allow known IP ranges.",
                })

    # ── Phase 3: New Asset Detection ────────────────────────────────────────
    all_hosts = [h["host"] for h in host_data if h["ip"]]
    new_hosts = _check_new_assets(org_id, all_hosts)

    if new_hosts:
        publish_output(scan_id, f"[easm] {len(new_hosts)} NEW assets discovered (not in asset inventory)")
        raw_lines.append(f"\n=== NEW ASSETS ({len(new_hosts)}) ===")
        raw_lines.extend(new_hosts)

        for host in new_hosts:
            hdata = next((h for h in host_data if h["host"] == host), {})
            ip = hdata.get("ip")

            if auto_add:
                _auto_create_asset(org_id, host, ip)
                publish_output(scan_id, f"[easm] Auto-added asset: {host}")

            if alert_new:
                findings.append({
                    "title": f"New external asset discovered: {host}",
                    "description": (
                        f"A previously unknown external asset '{host}' (IP: {ip or 'unresolved'}) was discovered "
                        f"during EASM scanning of {domain}. This asset was not in your inventory. "
                        f"Open ports: {hdata.get('ports', [])}"
                    ),
                    "severity": "medium",
                    "affected_component": host,
                    "affected_service": "external-asset",
                    "remediation": (
                        "Review this asset: confirm it is authorized, add to asset inventory, "
                        "and apply appropriate monitoring and hardening."
                    ),
                })

    # ── Phase 4: HTTPS/TLS Check on Web Assets ──────────────────────────────
    for hdata in host_data[:20]:
        host = hdata["host"]
        ports = hdata["ports"]
        if 80 in ports and 443 not in ports:
            findings.append({
                "title": f"HTTP without HTTPS: {host}",
                "description": f"External asset {host} serves HTTP (port 80) but HTTPS (port 443) is not detected.",
                "severity": "medium",
                "affected_component": host,
                "affected_port": 80,
                "affected_service": "http",
                "remediation": "Deploy TLS certificate and redirect all HTTP to HTTPS. Use Let's Encrypt for free certs.",
            })

    summary = (
        f"EASM complete for {domain}: {len(all_subdomains)} subdomains found, "
        f"{len(new_hosts)} new assets, {len(findings)} findings"
    )
    raw_lines.append(f"\n{summary}")
    publish_output(scan_id, f"[easm] {summary}")

    update_scan_raw_output(scan_id, "\n".join(raw_lines))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[easm] {count} findings saved.")
    update_scan_status(scan_id, "completed")


@celery_app.task(name="worker.tasks.easm_task.run_easm_scheduled")
def run_easm_scheduled():
    """Daily EASM scan for all organizations with domains configured."""
    conn = _get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT DISTINCT org_id, domain FROM assets WHERE domain IS NOT NULL AND is_active = TRUE GROUP BY org_id, domain LIMIT 50"
        )
        rows = cur.fetchall()
    except Exception:
        rows = []
    finally:
        cur.close()
        conn.close()

    import uuid as _uuid
    for org_id, domain in rows:
        scan_id = str(_uuid.uuid4())
        run_easm.apply_async(
            args=[scan_id, str(org_id), None, domain, {"domain": domain, "auto_add_assets": True, "port_scan": True}]
        )
