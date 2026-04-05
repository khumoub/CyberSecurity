import subprocess
import os
import re
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


@celery_app.task(bind=True, name="worker.tasks.sqlmap_task.run_sqlmap", max_retries=0)
def run_sqlmap(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    # AUTHORIZATION GATE — hard fail if not explicitly authorized
    if options.get("authorized") is not True:
        error_msg = "Authorization required. Set authorized=true in options to confirm permission."
        publish_output(scan_id, f"[sqlmap] BLOCKED: {error_msg}")
        update_scan_status(scan_id, "failed", error_msg)
        return

    output_dir = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_sqlmap")
    os.makedirs(output_dir, exist_ok=True)
    update_scan_status(scan_id, "running")

    level = options.get("level", 1)
    risk = options.get("risk", 1)
    data = options.get("data")
    cookies = options.get("cookies")

    cmd = [
        "sqlmap",
        "-u", target,
        f"--level={level}",
        f"--risk={risk}",
        "--batch",
        "--output-dir", output_dir,
        "--forms",
        "--crawl=2",
    ]

    if data:
        cmd.extend(["--data", data])
    if cookies:
        cmd.extend(["--cookie", cookies])

    publish_output(scan_id, f"[sqlmap] Starting SQL injection test: {' '.join(cmd)}")
    publish_output(scan_id, f"[sqlmap] AUTHORIZED scan - target: {target}")

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

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "sqlmap binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Parse output for injections
    findings = []
    injectable_params = []
    current_param = None
    injection_type = None

    for line in raw_lines:
        # Detect injectable parameters
        param_match = re.search(r"Parameter: (.+?) \(", line)
        if param_match:
            current_param = param_match.group(1).strip()

        type_match = re.search(r"Type: (.+)", line)
        if type_match and current_param:
            injection_type = type_match.group(1).strip()

        if "is vulnerable" in line.lower() or "sqlmap identified the following injection point" in line.lower():
            if current_param and current_param not in injectable_params:
                injectable_params.append(current_param)

        # DBMS detection
        dbms_match = re.search(r"back-end DBMS: (.+)", line)
        if dbms_match:
            dbms = dbms_match.group(1).strip()
            findings.append({
                "title": f"DBMS identified: {dbms} on {target}",
                "description": f"SQLMap identified the database management system as {dbms}",
                "severity": "info",
                "affected_component": target,
                "raw_output": line,
            })

    for param in injectable_params:
        findings.append({
            "title": f"SQL Injection vulnerability in parameter '{param}'",
            "description": (
                f"SQL injection was confirmed in the '{param}' parameter of {target}. "
                f"Injection type: {injection_type or 'unknown'}. "
                "An attacker can extract, modify or delete database contents, potentially achieving full system compromise."
            ),
            "severity": "critical",
            "affected_component": target,
            "cwe_id": "CWE-89",
            "remediation": (
                "Use parameterized queries or prepared statements. "
                "Never concatenate user input into SQL queries. "
                "Apply principle of least privilege to database accounts."
            ),
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            "raw_output": f"sqlmap: injectable parameter '{param}' on {target}",
        })

    if not injectable_params:
        # Check if no vulnerability was found
        no_vuln = any("not injectable" in l.lower() or "all tested parameters appear" in l.lower() for l in raw_lines)
        if no_vuln:
            findings.append({
                "title": f"No SQL injection found on {target}",
                "description": "SQLMap did not identify SQL injection vulnerabilities at the tested endpoints.",
                "severity": "info",
                "affected_component": target,
                "raw_output": "sqlmap: no injection found",
            })

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[sqlmap] Scan complete. {len(injectable_params)} injectable parameters found. {count} findings saved.")
    update_scan_status(scan_id, "completed")
