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

# Patterns that indicate sensitive findings
SENSITIVE_PATTERNS = {
    "backup": ("high", ["backup", ".bak", ".old", ".orig", ".copy", "~", ".swp"]),
    "config": ("high", ["config", ".conf", ".cfg", ".ini", ".env", ".htaccess", "web.config", "settings"]),
    "admin": ("medium", ["admin", "administrator", "manager", "dashboard", "control", "panel"]),
    "auth": ("medium", ["login", "signin", "auth", "password", "passwd", "credentials"]),
    "api": ("low", ["api", "v1", "v2", "v3", "graphql", "swagger", "openapi"]),
    "debug": ("medium", ["debug", "test", "dev", "staging", "phpinfo", "info.php"]),
    "db": ("high", ["db", "database", "phpmyadmin", "adminer", "mysqladmin"]),
    "git": ("high", [".git", ".svn", ".hg", ".bzr"]),
    "log": ("medium", ["log", "logs", "error.log", "access.log", "debug.log"]),
}

WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/wordlists/common.txt",
]


def _get_wordlist(requested: Optional[str]) -> Optional[str]:
    if requested and os.path.exists(requested):
        return requested
    for path in WORDLIST_PATHS:
        if os.path.exists(path):
            return path
    return None


def _classify_path(path: str) -> tuple:
    """Return (category, severity) for a found path."""
    path_lower = path.lower()
    for category, (severity, patterns) in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            if pattern in path_lower:
                return category, severity
    return "directory", "info"


@celery_app.task(bind=True, name="worker.tasks.gobuster_task.run_gobuster")
def run_gobuster(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_gobuster.txt")
    update_scan_status(scan_id, "running")

    wordlist = _get_wordlist(options.get("wordlist"))
    if not wordlist:
        update_scan_status(scan_id, "failed", "No wordlist found. Install dirb or seclists.")
        return

    extensions = options.get("extensions", ["php", "html", "js", "txt", "bak"])
    threads = options.get("threads", 10)
    ext_str = ",".join(extensions)

    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-o", output_file,
        "-q",
        "-x", ext_str,
        "-t", str(threads),
        "--no-error",
    ]

    publish_output(scan_id, f"[gobuster] Starting directory enumeration: {' '.join(cmd)}")

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
        update_scan_status(scan_id, "failed", "gobuster binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Parse results from output file
    findings = []
    found_paths = []

    result_source = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            result_source = f.readlines()
    else:
        result_source = raw_lines

    for line in result_source:
        line = line.strip()
        if not line:
            continue

        # Gobuster output format: /path (Status: 200) [Size: 1234]
        match = re.match(r"^(/[^\s]*)\s+\(Status:\s*(\d+)\)", line)
        if not match:
            # Try alternate format: /path                 (Status: 200) [Size: 1234]
            match = re.match(r"^(/\S+)\s+.*Status:\s*(\d+)", line)

        if match:
            path = match.group(1)
            status_code = int(match.group(2))

            if status_code in (404, 400, 500):
                continue

            found_paths.append((path, status_code))
            category, severity = _classify_path(path)
            full_url = target.rstrip("/") + path

            title_map = {
                "backup": f"Backup file accessible: {path}",
                "config": f"Configuration file exposed: {path}",
                "admin": f"Admin panel discovered: {path}",
                "auth": f"Authentication endpoint found: {path}",
                "db": f"Database management interface found: {path}",
                "git": f"Version control directory exposed: {path}",
                "log": f"Log file accessible: {path}",
                "debug": f"Debug/test endpoint found: {path}",
                "api": f"API endpoint discovered: {path}",
                "directory": f"Directory/file found: {path}",
            }

            findings.append({
                "title": title_map.get(category, f"Path found: {path}"),
                "description": (
                    f"Gobuster found {path} on {target} with HTTP status {status_code}. "
                    f"Category: {category}."
                ),
                "severity": severity,
                "affected_component": full_url,
                "affected_service": "http",
                "remediation": (
                    "Review whether this path should be publicly accessible. "
                    "Remove backup/config files, restrict admin panels with authentication, "
                    "and apply appropriate access controls."
                ),
                "raw_output": line,
            })

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[gobuster] Scan complete. {len(found_paths)} paths found. {count} findings saved.")
    update_scan_status(scan_id, "completed")
