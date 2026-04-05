import subprocess
import os
import json
from typing import Optional
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)
from core.config import settings


def _map_nikto_severity(osvdb_id: Optional[str], msg: str) -> str:
    """Map Nikto findings to severity based on keywords."""
    msg_lower = msg.lower()
    if any(kw in msg_lower for kw in ["remote code", "rce", "sql injection", "command injection"]):
        return "critical"
    if any(kw in msg_lower for kw in ["xss", "cross-site scripting", "directory traversal", "lfi", "rfi"]):
        return "high"
    if any(kw in msg_lower for kw in ["csrf", "information disclosure", "default password", "backup"]):
        return "medium"
    if any(kw in msg_lower for kw in ["version", "header", "cookie", "clickjacking"]):
        return "low"
    return "info"


@celery_app.task(bind=True, name="worker.tasks.nikto_task.run_nikto", max_retries=1)
def run_nikto(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_nikto.json")
    update_scan_status(scan_id, "running")

    cmd = ["nikto", "-h", target, "-Format", "json", "-o", output_file, "-nointeractive"]

    # Append optional args
    if options.get("port"):
        cmd.extend(["-port", str(options["port"])])
    if options.get("ssl"):
        cmd.append("-ssl")
    if options.get("useragent"):
        cmd.extend(["-useragent", options["useragent"]])

    publish_output(scan_id, f"[nikto] Starting scan: {' '.join(cmd)}")

    raw_lines = []
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in process.stdout:
            line = line.rstrip()
            if line:
                publish_output(scan_id, line)
                raw_lines.append(line)

        process.wait()
        update_scan_raw_output(scan_id, "\n".join(raw_lines))

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "nikto binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Parse JSON output
    findings = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                data = json.load(f)

            # Nikto JSON format: {"vulnerabilities": [...]}
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                # Try hosts > issues format
                for host_entry in data.get("host", []):
                    vulns.extend(host_entry.get("vulnerabilities", []))

            for v in vulns:
                msg = v.get("msg", v.get("message", "Unknown finding"))
                osvdb = v.get("osvdbid", v.get("OSVDB", ""))
                url = v.get("url", v.get("uri", target))
                method = v.get("method", "GET")
                severity = _map_nikto_severity(osvdb, msg)

                refs = []
                if osvdb and str(osvdb) != "0":
                    refs.append(f"https://www.osvdb.org/{osvdb}")

                findings.append({
                    "title": msg[:200],
                    "description": f"Nikto finding on {url} [{method}]: {msg}",
                    "severity": severity,
                    "affected_component": url,
                    "remediation": "Review the finding and apply appropriate hardening or patches.",
                    "references": refs,
                    "raw_output": json.dumps(v),
                })

        except (json.JSONDecodeError, KeyError) as e:
            publish_output(scan_id, f"[nikto] JSON parse error: {e}. Falling back to raw output parsing.")

            # Fallback: parse raw text
            for line in raw_lines:
                if "+ OSVDB" in line or ("+ " in line and ":" in line):
                    findings.append({
                        "title": line.strip()[:200],
                        "description": line.strip(),
                        "severity": _map_nikto_severity(None, line),
                        "affected_component": target,
                        "raw_output": line,
                    })

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[nikto] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
