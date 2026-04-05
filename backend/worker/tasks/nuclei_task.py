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

NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _extract_cve(template_id: str) -> Optional[str]:
    """Extract CVE ID from template ID like cve-2021-44228."""
    import re
    match = re.search(r"(CVE-\d{4}-\d+)", template_id, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return None


@celery_app.task(bind=True, name="worker.tasks.nuclei_task.run_nuclei", max_retries=1)
def run_nuclei(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_nuclei.jsonl")
    update_scan_status(scan_id, "running")

    templates = options.get("templates", ["cve", "misconfig", "exposure"])
    severity_filter = options.get("severity_filter", ["critical", "high", "medium"])
    rate_limit = options.get("rate_limit", 150)
    tags = options.get("tags", [])

    cmd = [
        "nuclei",
        "-u", target,
        "-rate-limit", str(rate_limit),
        "-json-export", output_file,
        "-silent",
    ]

    for tmpl in templates:
        cmd.extend(["-t", tmpl])

    if severity_filter:
        cmd.extend(["-severity", ",".join(severity_filter)])

    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    publish_output(scan_id, f"[nuclei] Starting scan: {' '.join(cmd)}")

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

        if process.returncode not in (0, 1):
            raise RuntimeError(f"nuclei exited with code {process.returncode}")

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "nuclei binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Parse JSONL output
    findings = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                template_id = item.get("template-id", "")
                info = item.get("info", {})
                name = info.get("name", template_id)
                severity = NUCLEI_SEVERITY_MAP.get(info.get("severity", "info").lower(), "info")
                matched_at = item.get("matched-at", target)
                description = info.get("description", "")
                remediation = info.get("remediation", "")
                refs = info.get("reference", [])
                if isinstance(refs, str):
                    refs = [refs]
                cvss = info.get("classification", {}).get("cvss-score")
                cve_id = _extract_cve(template_id)
                if not cve_id:
                    cve_ids = info.get("classification", {}).get("cve-id", [])
                    if isinstance(cve_ids, list) and cve_ids:
                        cve_id = cve_ids[0].upper()
                    elif isinstance(cve_ids, str) and cve_ids:
                        cve_id = cve_ids.upper()

                cwe_ids = info.get("classification", {}).get("cwe-id", [])
                cwe_id = cwe_ids[0] if isinstance(cwe_ids, list) and cwe_ids else None

                findings.append({
                    "title": f"{name} ({template_id})",
                    "description": description or f"Nuclei template {template_id} matched at {matched_at}",
                    "severity": severity,
                    "cvss_score": cvss,
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "affected_component": matched_at,
                    "remediation": remediation,
                    "references": refs[:10],
                    "raw_output": line,
                })

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[nuclei] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
