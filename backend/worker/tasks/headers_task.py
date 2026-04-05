import requests
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

# Header name -> (severity, description, remediation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "high",
        "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    "Content-Security-Policy": (
        "medium",
        "Content Security Policy (CSP) header is missing. This increases XSS risk.",
        "Add a Content-Security-Policy header with appropriate directives for your application.",
    ),
    "X-Frame-Options": (
        "medium",
        "X-Frame-Options header is missing. This allows clickjacking attacks.",
        "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    ),
    "X-Content-Type-Options": (
        "low",
        "X-Content-Type-Options header is missing. This enables MIME type sniffing.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": (
        "low",
        "Referrer-Policy header is missing. Full referrer URLs may be sent to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "info",
        "Permissions-Policy header is missing. Browser features are not restricted.",
        "Add a Permissions-Policy header to restrict unnecessary browser feature access.",
    ),
}


@celery_app.task(bind=True, name="worker.tasks.headers_task.check_headers")
def check_headers(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    url: str,
    options: dict,
):
    update_scan_status(scan_id, "running")
    findings = []

    follow_redirects = options.get("follow_redirects", True)

    publish_output(scan_id, f"[headers] Checking security headers for {url}")

    try:
        # Disable SSL warnings for scanning purposes
        requests.packages.urllib3.disable_warnings()
        response = requests.get(
            url,
            allow_redirects=follow_redirects,
            timeout=15,
            verify=False,
            headers={"User-Agent": "Leruo-Security-Scanner/1.0"},
        )
        headers = response.headers
        raw_output = f"HTTP/{response.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        update_scan_raw_output(scan_id, raw_output)
        publish_output(scan_id, f"[headers] Got response: HTTP {response.status_code}")

    except requests.exceptions.ConnectionError as e:
        update_scan_status(scan_id, "failed", f"Connection error: {e}")
        return
    except requests.exceptions.Timeout:
        update_scan_status(scan_id, "failed", "Request timed out")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Check missing security headers
    for header_name, (severity, description, remediation) in SECURITY_HEADERS.items():
        if header_name not in headers:
            publish_output(scan_id, f"[headers] MISSING: {header_name}")
            findings.append({
                "title": f"Missing security header: {header_name}",
                "description": description,
                "severity": severity,
                "affected_component": url,
                "affected_service": "http",
                "remediation": remediation,
                "references": [
                    "https://owasp.org/www-project-secure-headers/",
                    f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                ],
                "raw_output": f"Header '{header_name}' not present in response from {url}",
            })
        else:
            publish_output(scan_id, f"[headers] OK: {header_name}: {headers[header_name][:100]}")

    # Check X-Powered-By info disclosure
    xpb = headers.get("X-Powered-By")
    if xpb:
        findings.append({
            "title": f"Information disclosure via X-Powered-By header",
            "description": f"The server is exposing technology information: X-Powered-By: {xpb}",
            "severity": "info",
            "affected_component": url,
            "affected_service": "http",
            "remediation": "Remove the X-Powered-By header to reduce information leakage.",
            "raw_output": f"X-Powered-By: {xpb}",
        })

    # Check Server header version disclosure
    server_header = headers.get("Server", "")
    if server_header:
        import re
        version_pattern = re.compile(r"[\d]+\.[\d]+", re.IGNORECASE)
        if version_pattern.search(server_header) or any(kw in server_header.lower() for kw in ["apache/", "nginx/", "iis/"]):
            findings.append({
                "title": f"Server version disclosed in Server header",
                "description": f"The Server header reveals version information: {server_header}",
                "severity": "low",
                "affected_component": url,
                "affected_service": "http",
                "remediation": "Configure the web server to suppress version information in the Server header.",
                "raw_output": f"Server: {server_header}",
            })

    # Check for HTTPS on HTTP page
    if url.startswith("http://"):
        findings.append({
            "title": f"Plain HTTP (non-HTTPS) endpoint detected",
            "description": f"The URL {url} is accessible over unencrypted HTTP.",
            "severity": "medium",
            "affected_component": url,
            "affected_service": "http",
            "remediation": "Redirect all HTTP traffic to HTTPS and set up HSTS.",
        })

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[headers] Check complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
