import subprocess
import re
import os
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

# Lynis log line patterns
# 2024-01-01 12:00:00 Warning: CATEGORY - Description [test-id]
WARNING_RE = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+)?Warning\s*[:\-]\s*(.+?)(?:\s+\[(\w+)\])?$",
    re.IGNORECASE,
)
SUGGESTION_RE = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+)?Suggestion\s*[:\-]\s*(.+?)(?:\s+\[(\w+)\])?$",
    re.IGNORECASE,
)
# Hardening index: "Hardening index : 67 [#############       ]"
HARDENING_INDEX_RE = re.compile(r"Hardening\s+index\s*[:\|]\s*(\d+)")

# Category extraction from log: category names appear in section headers
CATEGORY_RE = re.compile(r"=====\s*(.+?)\s*=====")


@celery_app.task(bind=True, name="worker.tasks.lynis_task.run_lynis", max_retries=1)
def run_lynis(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    update_scan_status(scan_id, "running")

    host = options.get("host", "localhost")
    ssh_user = options.get("ssh_user")
    ssh_key_path = options.get("ssh_key_path")
    is_remote = host != "localhost" and ssh_user

    os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
    log_file = f"/tmp/{scan_id}_lynis.log"

    if is_remote:
        # Remote SSH execution
        lynis_cmd = (
            f"lynis audit system --quick --no-colors --log-file {log_file} 2>&1"
        )
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
        ]
        if ssh_key_path:
            ssh_opts.extend(["-i", ssh_key_path])

        cmd = ["ssh"] + ssh_opts + [f"{ssh_user}@{host}", lynis_cmd]
        publish_output(scan_id, f"[lynis] Remote audit on {host} via SSH")
    else:
        # Local execution
        cmd = [
            "lynis", "audit", "system",
            "--quick",
            "--no-colors",
            "--log-file", log_file,
        ]
        publish_output(scan_id, "[lynis] Local system audit")

    publish_output(scan_id, f"[lynis] Running: {' '.join(cmd)}")

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
        raw_output = "\n".join(raw_lines)
        update_scan_raw_output(scan_id, raw_output)

        if process.returncode not in (0, 1, 2):
            raise RuntimeError(f"lynis exited with code {process.returncode}")

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "lynis binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Parse log file for warnings and suggestions
    findings = []
    hardening_index = None
    current_category = "General"

    log_content = ""
    if os.path.exists(log_file):
        with open(log_file, "r", errors="replace") as f:
            log_content = f.read()
        log_lines = log_content.splitlines()
    else:
        # Fall back to stdout output
        log_lines = raw_lines

    for line in log_lines:
        line = line.strip()

        # Track current category from section headers
        cat_match = CATEGORY_RE.search(line)
        if cat_match:
            current_category = cat_match.group(1).strip()

        # Extract hardening index
        if hardening_index is None:
            hi_match = HARDENING_INDEX_RE.search(line)
            if hi_match:
                hardening_index = int(hi_match.group(1))
                publish_output(scan_id, f"[lynis] Hardening index: {hardening_index}/100")

        # Parse warnings
        warn_match = WARNING_RE.match(line)
        if warn_match:
            description_text = warn_match.group(1).strip()
            test_id = warn_match.group(2) or ""
            title = f"Lynis Warning [{current_category}]: {description_text[:100]}"
            findings.append({
                "title": title,
                "description": (
                    f"Lynis audit warning in category '{current_category}'.\n\n"
                    f"Details: {description_text}\n"
                    + (f"Test ID: {test_id}" if test_id else "")
                ),
                "severity": "medium",
                "affected_component": host,
                "raw_output": line,
                "remediation": (
                    f"Address the security warning identified by Lynis in the '{current_category}' "
                    "category. Review the Lynis documentation for the specific test for remediation steps."
                ),
            })
            continue

        # Parse suggestions
        sugg_match = SUGGESTION_RE.match(line)
        if sugg_match:
            description_text = sugg_match.group(1).strip()
            test_id = sugg_match.group(2) or ""
            title = f"Lynis Suggestion [{current_category}]: {description_text[:100]}"
            findings.append({
                "title": title,
                "description": (
                    f"Lynis audit suggestion in category '{current_category}'.\n\n"
                    f"Details: {description_text}\n"
                    + (f"Test ID: {test_id}" if test_id else "")
                ),
                "severity": "low",
                "affected_component": host,
                "raw_output": line,
                "remediation": (
                    f"Consider implementing the Lynis suggestion for '{current_category}' "
                    "to improve system hardening."
                ),
            })

    # Add hardening index as an info finding
    if hardening_index is not None:
        hi_severity = "info"
        if hardening_index < 40:
            hi_severity = "high"
        elif hardening_index < 60:
            hi_severity = "medium"
        elif hardening_index < 75:
            hi_severity = "low"

        findings.insert(0, {
            "title": f"Lynis Hardening Index: {hardening_index}/100 on {host}",
            "description": (
                f"Lynis system audit completed for {host}.\n\n"
                f"Hardening Index: {hardening_index}/100\n"
                f"Total findings: {len(findings)} (warnings + suggestions)\n\n"
                f"Score interpretation:\n"
                f"  0-39: Poor hardening (immediate action required)\n"
                f"  40-59: Below average (significant improvements needed)\n"
                f"  60-74: Average (improvements recommended)\n"
                f"  75-100: Good to excellent hardening"
            ),
            "severity": hi_severity,
            "affected_component": host,
            "raw_output": f"Hardening index: {hardening_index}",
            "remediation": (
                "Review all Lynis warnings and suggestions to improve the hardening index. "
                "Prioritize warnings first, then implement suggestions."
            ),
        })
    else:
        publish_output(scan_id, "[lynis] Could not extract hardening index from log.")

    # Cleanup log file
    try:
        os.unlink(log_file)
    except OSError:
        pass

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[lynis] Audit complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
