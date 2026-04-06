import subprocess
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

SUPPORTED_PROTOCOLS = {
    "ssh", "ftp", "http-get", "http-post-form",
    "rdp", "smtp", "smb",
}

# Regex to parse Hydra's success line:
# [22][ssh] host: 192.168.1.1   login: admin   password: secret
HYDRA_SUCCESS_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<protocol>[^\]]+)\]\s+host:\s+(?P<host>\S+)"
    r"\s+login:\s+(?P<login>\S+)\s+password:\s+(?P<password>\S+)"
)


@celery_app.task(
    bind=True,
    name="worker.tasks.hydra_task.run_hydra",
    max_retries=0,  # never retry auth testing
)
def run_hydra(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    # ---- HARD AUTHORIZATION GATE ----
    if options.get("authorized") is not True:
        raise ValueError(
            "Hydra task requires explicit authorization. "
            "Set options['authorized'] = True to confirm you have written permission."
        )

    update_scan_status(scan_id, "running")

    protocol = options.get("protocol", "ssh")
    port = options.get("port")
    username = options.get("username")
    username_file = options.get("username_file")
    password_file = options.get("password_file", "/usr/share/wordlists/rockyou.txt")
    threads = options.get("threads", 4)
    delay_ms = options.get("delay_ms", 0)

    if protocol not in SUPPORTED_PROTOCOLS:
        update_scan_status(
            scan_id, "failed",
            f"Unsupported protocol: {protocol}. Supported: {', '.join(sorted(SUPPORTED_PROTOCOLS))}"
        )
        return

    if not username and not username_file:
        update_scan_status(scan_id, "failed", "Either 'username' or 'username_file' must be provided.")
        return

    # Build command
    cmd = ["hydra"]

    if username:
        cmd.extend(["-l", username])
    elif username_file:
        cmd.extend(["-L", username_file])

    cmd.extend(["-P", password_file])
    cmd.extend(["-t", str(threads)])

    if delay_ms and int(delay_ms) > 0:
        delay_secs = max(1, int(delay_ms) // 1000)
        cmd.extend(["-W", str(delay_secs)])

    # Build target specification
    service_target = f"{protocol}://{target}"
    if port:
        service_target += f":{port}"

    cmd.append(service_target)

    publish_output(scan_id, f"[hydra] Starting: {' '.join(cmd)}")

    raw_lines = []
    findings = []

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

            publish_output(scan_id, line)
            raw_lines.append(line)

            # Parse successful login
            match = HYDRA_SUCCESS_RE.search(line)
            if match:
                found_port = match.group("port")
                found_protocol = match.group("protocol")
                found_host = match.group("host")
                found_login = match.group("login")
                found_password = match.group("password")

                findings.append({
                    "title": (
                        f"Valid credentials found: {found_login}@{found_host} "
                        f"via {found_protocol}/{found_port}"
                    ),
                    "description": (
                        f"Hydra discovered valid credentials for {found_protocol} service.\n\n"
                        f"Host: {found_host}\n"
                        f"Port: {found_port}\n"
                        f"Protocol: {found_protocol}\n"
                        f"Username: {found_login}\n"
                        f"Password: {found_password}\n\n"
                        f"This credential pair allows unauthorized access."
                    ),
                    "severity": "critical",
                    "affected_component": f"{found_host}:{found_port}",
                    "affected_port": int(found_port) if found_port.isdigit() else None,
                    "affected_service": found_protocol,
                    "raw_output": line,
                    "remediation": (
                        "Immediately change this password. Enforce strong password policies, "
                        "implement account lockout mechanisms, use multi-factor authentication, "
                        "and restrict service access to trusted IP ranges."
                    ),
                })

        process.wait()
        raw_output = "\n".join(raw_lines)
        update_scan_raw_output(scan_id, raw_output)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"hydra exited with code {process.returncode}")

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "hydra binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[hydra] Scan complete. {count} credential findings saved.")
    update_scan_status(scan_id, "completed")
