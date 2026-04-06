"""
Fix Verification / Remediation Rescan
- Takes a finding and re-runs the exact scan that produced it
- Compares results to determine if the issue is resolved
- Updates finding status to 'verified_fixed' or 're-opened'
"""
import subprocess
import json
import re
from typing import Optional
import psycopg2
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
)
from core.config import settings


def _get_finding_and_scan(finding_id: str) -> tuple:
    """Fetch finding + originating scan details."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        cur.execute(
            """SELECT f.id, f.title, f.severity, f.cve_id, f.affected_component,
                      f.affected_port, f.affected_service, f.status,
                      f.asset_id, f.org_id, f.scan_id,
                      a.ip_address, a.hostname, a.domain,
                      sj.tool_name, sj.target
               FROM findings f
               LEFT JOIN assets a ON a.id = f.asset_id
               LEFT JOIN scan_jobs sj ON sj.id = f.scan_id
               WHERE f.id = %s""",
            (finding_id,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return None, None
        cols = ["id", "title", "severity", "cve_id", "affected_component",
                "affected_port", "affected_service", "status",
                "asset_id", "org_id", "scan_id",
                "ip_address", "hostname", "domain",
                "tool_name", "scan_target"]
        finding = dict(zip(cols, row))
        target = finding["scan_target"] or finding["ip_address"] or finding["hostname"] or finding["domain"]
        return finding, target
    except Exception as e:
        return None, None


def _update_finding_status(finding_id: str, status: str, notes_addition: str):
    """Update finding status and append verification notes."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        resolved_at = "NOW()" if status == "resolved" else "NULL"
        cur.execute(
            f"""UPDATE findings
               SET status = %s,
                   {'resolved_at = NOW(),' if status == 'resolved' else ''}
                   notes = COALESCE(notes, '') || '\n\n[Fix Verification] ' || %s,
                   updated_at = NOW()
               WHERE id = %s""",
            (status, notes_addition, finding_id)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


def _verify_with_nuclei(target: str, cve_id: str, port: Optional[int], scan_id: str) -> bool:
    """Return True if nuclei still detects the CVE (not fixed)."""
    if not cve_id:
        return None  # unknown
    template_id = cve_id.lower()
    cmd = ["nuclei", "-u", f"{target}:{port}" if port else target,
           "-id", template_id, "-silent", "-j", "-timeout", "15"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        still_vulnerable = bool(result.stdout.strip())
        return still_vulnerable
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _verify_with_nmap(target: str, port: int, service: str, scan_id: str) -> bool:
    """Return True if port/service still exposed (not fixed)."""
    if not port:
        return None
    try:
        result = subprocess.run(
            ["nmap", "-p", str(port), "--open", "-Pn", target, "-oX", "-"],
            capture_output=True, text=True, timeout=30
        )
        still_open = f'portid="{port}"' in result.stdout and 'state="open"' in result.stdout
        return still_open
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _verify_header(target: str, port: int, header_name: str, scan_id: str) -> bool:
    """Return True if security header still missing (not fixed)."""
    try:
        import urllib.request
        schema = "https" if port == 443 else "http"
        resp = urllib.request.urlopen(f"{schema}://{target}:{port or 80}/", timeout=10)
        still_missing = header_name not in dict(resp.headers)
        return still_missing
    except Exception:
        return None


def _verify_ssl(target: str, port: int, scan_id: str) -> bool:
    """Return True if SSL issue still present."""
    try:
        result = subprocess.run(
            ["sslscan", "--no-colour", f"{target}:{port or 443}"],
            capture_output=True, text=True, timeout=30
        )
        # Check for known-bad indicators
        still_vuln = any(kw in result.stdout for kw in
                         ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "Heartbleed", "POODLE"])
        return still_vuln
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


@celery_app.task(bind=True, name="worker.tasks.remediation_verify_task.verify_fix", max_retries=0)
def verify_fix(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    finding_id: str,
    options: dict,
):
    """
    Re-run the appropriate check for a finding to see if it's been fixed.
    Updates finding status: 'resolved' if fixed, 'open' (re-opened) if still present.
    """
    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[fix-verify] Starting fix verification for finding {finding_id}")

    finding, target = _get_finding_and_scan(finding_id)
    if not finding:
        update_scan_status(scan_id, "failed", f"Finding {finding_id} not found")
        return

    if not target:
        update_scan_status(scan_id, "failed", "No target host found for this finding")
        return

    publish_output(scan_id, f"[fix-verify] Finding: {finding['title']}")
    publish_output(scan_id, f"[fix-verify] Target: {target} | Tool: {finding.get('tool_name', 'unknown')}")

    title_lower = finding["title"].lower()
    service = finding.get("affected_service", "") or ""
    port = finding.get("affected_port")
    cve_id = finding.get("cve_id")

    still_vulnerable = None

    # Strategy 1: nuclei CVE check
    if cve_id:
        publish_output(scan_id, f"[fix-verify] Running nuclei CVE check for {cve_id}...")
        still_vulnerable = _verify_with_nuclei(target, cve_id, port, scan_id)

    # Strategy 2: open port check (for "exposed service" type findings)
    if still_vulnerable is None and port and any(
        kw in title_lower for kw in ["exposed", "open port", "service detected", "accessible"]
    ):
        publish_output(scan_id, f"[fix-verify] Checking if port {port} still open...")
        still_vulnerable = _verify_with_nmap(target, port, service, scan_id)

    # Strategy 3: security header check
    if still_vulnerable is None and "missing security header" in title_lower:
        header_match = re.search(r"header:\s*(\S+)", finding["title"], re.IGNORECASE)
        if header_match:
            header_name = header_match.group(1)
            publish_output(scan_id, f"[fix-verify] Checking if {header_name} header now present...")
            still_vulnerable = _verify_header(target, port or 80, header_name, scan_id)

    # Strategy 4: SSL/TLS check
    if still_vulnerable is None and service in ("ssl", "tls", "https") or "ssl" in title_lower or "tls" in title_lower:
        publish_output(scan_id, f"[fix-verify] Re-running SSL/TLS check...")
        still_vulnerable = _verify_ssl(target, port, scan_id)

    # Strategy 5: generic nmap version check
    if still_vulnerable is None and port:
        publish_output(scan_id, f"[fix-verify] Generic service version check on port {port}...")
        try:
            result = subprocess.run(
                ["nmap", "-p", str(port), "-sV", "--version-intensity", "5", "-Pn", target, "-oX", "-"],
                capture_output=True, text=True, timeout=30
            )
            # If port is closed/filtered, consider it potentially fixed
            port_open = f'portid="{port}"' in result.stdout and 'state="open"' in result.stdout
            if not port_open:
                still_vulnerable = False
                publish_output(scan_id, f"[fix-verify] Port {port} no longer open — likely fixed")
        except Exception:
            pass

    # ── Determine result ────────────────────────────────────────────────────
    if still_vulnerable is True:
        new_status = "open"
        result_msg = f"Finding re-verified: vulnerability still present on {target}. Fix was NOT effective."
        publish_output(scan_id, f"[fix-verify] STILL VULNERABLE — fix not effective")
    elif still_vulnerable is False:
        new_status = "resolved"
        result_msg = f"Fix VERIFIED: vulnerability no longer detected on {target} as of {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}."
        publish_output(scan_id, f"[fix-verify] FIXED — vulnerability no longer detected")
    else:
        new_status = finding["status"]  # unchanged
        result_msg = "Automated verification inconclusive — manual review required. No matching verification strategy could confirm fix status."
        publish_output(scan_id, f"[fix-verify] INCONCLUSIVE — manual verification needed")

    _update_finding_status(finding_id, new_status, result_msg)
    update_scan_raw_output(scan_id, result_msg)
    update_scan_status(scan_id, "completed")
