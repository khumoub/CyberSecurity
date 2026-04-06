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

# Paths considered sensitive — findings on these paths get elevated to MEDIUM
SENSITIVE_PATH_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"admin", r"login", r"config", r"backup", r"\.env", r"\.git",
        r"wp-admin", r"phpmyadmin", r"\.htaccess", r"\.htpasswd",
        r"secret", r"private", r"passwd", r"password", r"credentials",
        r"\.bak$", r"\.sql$", r"\.zip$", r"\.tar$", r"debug",
        r"console", r"actuator", r"swagger", r"api/v", r"graphql",
    ]
]

# Status codes that are interesting for security testing
INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 403, 405, 500}


def _is_sensitive_path(path: str) -> bool:
    for pat in SENSITIVE_PATH_PATTERNS:
        if pat.search(path):
            return True
    return False


def _parse_wfuzz_line(line: str) -> Optional[dict]:
    """
    Parse a wfuzz output line.
    Typical wfuzz -c output format:
      000000001:   200        9 L      21 W     337 Ch     "index"
    Returns a dict with status, lines, words, chars, payload or None.
    """
    # Match wfuzz output: ID: STATUS  LINES  L  WORDS  W  CHARS  Ch  "PAYLOAD"
    match = re.search(
        r"(\d+):\s+(\d+)\s+(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch\s+\"(.+?)\"",
        line,
    )
    if match:
        return {
            "id": match.group(1),
            "status": int(match.group(2)),
            "lines": int(match.group(3)),
            "words": int(match.group(4)),
            "chars": int(match.group(5)),
            "payload": match.group(6),
        }
    return None


@celery_app.task(bind=True, name="worker.tasks.wfuzz_task.run_wfuzz", max_retries=1)
def run_wfuzz(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    update_scan_status(scan_id, "running")

    url = options.get("url", target)
    wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    filter_code = options.get("filter_code", "404")
    filter_lines = options.get("filter_lines")
    threads = options.get("threads", 10)

    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    cmd = ["wfuzz", "-c", "-z", f"file,{wordlist}"]

    if filter_code:
        cmd.extend(["--hc", str(filter_code)])
    if filter_lines:
        cmd.extend(["--hl", str(filter_lines)])

    cmd.extend(["-t", str(threads), url])

    publish_output(scan_id, f"[wfuzz] Starting: {' '.join(cmd)}")

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

            parsed = _parse_wfuzz_line(line)
            if not parsed:
                continue

            status_code = parsed["status"]
            payload = parsed["payload"]
            chars = parsed["chars"]
            words = parsed["words"]

            if status_code not in INTERESTING_CODES:
                continue

            # Reconstruct the found URL
            found_url = url.replace("FUZZ", payload)
            is_sensitive = _is_sensitive_path(payload)

            # Determine severity
            if status_code in (200, 403) and is_sensitive:
                severity = "medium"
                title = f"Sensitive path accessible: /{payload} ({status_code})"
                description = (
                    f"Sensitive path '/{payload}' returned HTTP {status_code} on {target}. "
                    f"Response size: {chars} bytes, {words} words. "
                    f"URL: {found_url}"
                )
                remediation = (
                    "Restrict access to sensitive paths via authentication, "
                    "firewall rules, or by removing the resource if not needed."
                )
            elif status_code in (301, 302) and is_sensitive:
                severity = "medium"
                title = f"Sensitive path redirects: /{payload} ({status_code})"
                description = (
                    f"Sensitive path '/{payload}' redirects (HTTP {status_code}) on {target}. "
                    f"URL: {found_url}"
                )
                remediation = "Verify this redirect is intentional and does not expose sensitive resources."
            else:
                severity = "info"
                title = f"Directory/file found: /{payload} ({status_code})"
                description = (
                    f"Path '/{payload}' returned HTTP {status_code} on {target}. "
                    f"Response size: {chars} bytes, {words} words. "
                    f"URL: {found_url}"
                )
                remediation = "Review whether this resource should be publicly accessible."

            findings.append({
                "title": title,
                "description": description,
                "severity": severity,
                "affected_component": found_url,
                "raw_output": line,
                "remediation": remediation,
            })

        process.wait()
        raw_output = "\n".join(raw_lines)
        update_scan_raw_output(scan_id, raw_output)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"wfuzz exited with code {process.returncode}")

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "wfuzz binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[wfuzz] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
