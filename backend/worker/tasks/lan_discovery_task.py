import subprocess
import re
import uuid
import psycopg2
from typing import Optional
from datetime import datetime, timezone
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)
from core.config import settings

# netdiscover output:
#   192.168.1.1     00:11:22:33:44:55     1      42  VENDOR NAME
NETDISCOVER_RE = re.compile(
    r"^\s*([\d.]+)\s+([\da-fA-F:]{17})\s+\d+\s+\d+\s+(.+?)\s*$"
)

# arp-scan output:
#   192.168.1.1    00:11:22:33:44:55    VENDOR NAME
ARP_SCAN_RE = re.compile(
    r"^\s*([\d.]+)\s+([\da-fA-F:]{17})\s+(.+?)\s*$"
)


def _save_asset_to_db(org_id: str, ip: str, mac: str, vendor: str) -> Optional[str]:
    """
    Upsert discovered host as an Asset record.
    Returns the asset UUID string.
    """
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        now = datetime.now(timezone.utc)
        asset_id = str(uuid.uuid4())

        cur.execute(
            """
            INSERT INTO assets (id, org_id, name, type, value, metadata_, is_active, created_at, updated_at)
            VALUES (%s, %s, %s, 'host', %s, %s::jsonb, true, %s, %s)
            ON CONFLICT (org_id, value) DO UPDATE
                SET last_scanned_at = EXCLUDED.updated_at,
                    updated_at = EXCLUDED.updated_at
            RETURNING id
            """,
            (
                asset_id,
                org_id,
                vendor or ip,
                ip,
                f'{{"mac": "{mac}", "vendor": "{vendor}"}}',
                now,
                now,
            ),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return str(row[0]) if row else asset_id
    except Exception as e:
        print(f"[lan_discovery] asset upsert error: {e}")
        return None


@celery_app.task(bind=True, name="worker.tasks.lan_discovery_task.run_lan_discovery", max_retries=1)
def run_lan_discovery(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    update_scan_status(scan_id, "running")

    interface = options.get("interface", "eth0")
    ip_range = options.get("ip_range", target or "192.168.1.0/24")
    passive = options.get("passive", False)

    if passive:
        cmd = ["netdiscover", "-i", interface, "-r", ip_range, "-P", "-N"]
        parser_re = NETDISCOVER_RE
        tool_name = "netdiscover"
    else:
        cmd = ["arp-scan", f"--interface={interface}", ip_range]
        parser_re = ARP_SCAN_RE
        tool_name = "arp-scan"

    publish_output(scan_id, f"[lan_discovery] Starting {tool_name}: {' '.join(cmd)}")

    raw_lines = []
    discovered_hosts = []  # list of (ip, mac, vendor)

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue

            raw_lines.append(line)

            match = parser_re.match(line)
            if not match:
                continue

            ip = match.group(1).strip()
            mac = match.group(2).strip().lower()
            vendor = match.group(3).strip()

            # Skip duplicates
            if any(h[0] == ip for h in discovered_hosts):
                continue

            discovered_hosts.append((ip, mac, vendor))
            publish_output(
                scan_id,
                f"[lan_discovery] Found: {ip}  {mac}  {vendor or 'Unknown vendor'}"
            )

        process.wait()
        raw_output = "\n".join(raw_lines)
        update_scan_raw_output(scan_id, raw_output)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"{tool_name} exited with code {process.returncode}")

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", f"{tool_name} binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Create Asset records and INFO findings for each discovered host
    findings = []
    for ip, mac, vendor in discovered_hosts:
        # Upsert asset
        discovered_asset_id = _save_asset_to_db(org_id, ip, mac, vendor)

        findings.append({
            "title": f"Host discovered: {ip} ({vendor or 'Unknown'})",
            "description": (
                f"Network host discovered via {'passive ARP (netdiscover)' if passive else 'active ARP scan (arp-scan)'}.\n\n"
                f"IP Address: {ip}\n"
                f"MAC Address: {mac}\n"
                f"Vendor: {vendor or 'Unknown'}\n"
                f"Network: {ip_range}\n"
                f"Interface: {interface}"
            ),
            "severity": "info",
            "affected_component": ip,
            "raw_output": f"{ip}\t{mac}\t{vendor}",
            "remediation": (
                "Review whether this host is authorized on the network. "
                "Unexpected devices should be investigated and may need to be isolated."
            ),
        })

    publish_output(
        scan_id,
        f"[lan_discovery] Discovered {len(discovered_hosts)} host(s) in {ip_range}."
    )

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[lan_discovery] Complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
