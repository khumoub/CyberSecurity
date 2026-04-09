import subprocess, os, json
from worker.celery_app import celery_app as celery
from worker.tasks.base import publish_output, update_scan_status, save_findings_to_db
from core.config import settings


@celery.task(bind=True, name="worker.tasks.wpscan_task.run_wpscan", max_retries=1)
def run_wpscan(self, scan_id: str, org_id: str, asset_id: str, target: str, options: dict):
    """
    WordPress security audit with WPScan.
    Options:
      - api_token: str  WPScan API token for vulnerability database
      - enumerate: list e.g. ["users", "plugins", "themes", "config-backups"]
    """
    os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_wpscan.json")
    enumerate_flags = options.get("enumerate", ["plugins", "themes", "users"])
    enum_str = ",".join({"users": "u", "plugins": "ap", "themes": "at",
                          "config-backups": "cb", "db-exports": "dbe"}.get(e, e)
                         for e in enumerate_flags)

    cmd = ["wpscan", "--url", target, "--enumerate", enum_str,
           "--format", "json", "--output", output_file, "--no-banner"]

    api_token = options.get("api_token", "")
    if api_token:
        cmd.extend(["--api-token", api_token])

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[wpscan] Auditing WordPress site: {target}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                publish_output(scan_id, line)
        proc.wait()

        findings = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                data = json.load(f)

            # WordPress version
            wp_version = data.get("version", {})
            if wp_version:
                ver = wp_version.get("number", "unknown")
                vulns = wp_version.get("vulnerabilities", [])
                if vulns:
                    for v in vulns:
                        cve = next((r for r in v.get("references", {}).get("cve", [])), None)
                        findings.append({
                            "title": f"WordPress {ver} — {v.get('title', 'Vulnerability')}",
                            "description": v.get("title", ""),
                            "severity": "high",
                            "affected_component": f"WordPress {ver}",
                            "cve_id": f"CVE-{cve}" if cve else None,
                            "remediation": "Update WordPress core to the latest version.",
                        })
                else:
                    findings.append({
                        "title": f"WordPress version {ver} detected",
                        "description": f"WordPress {ver} is installed. No known vulnerabilities found for this version.",
                        "severity": "info",
                        "affected_component": f"WordPress {ver}",
                        "remediation": "Keep WordPress updated to the latest version.",
                    })

            # Plugins
            for plugin_name, plugin_data in data.get("plugins", {}).items():
                for vuln in plugin_data.get("vulnerabilities", []):
                    cve = next((r for r in vuln.get("references", {}).get("cve", [])), None)
                    findings.append({
                        "title": f"Vulnerable plugin: {plugin_name} — {vuln.get('title', '')}",
                        "description": vuln.get("title", ""),
                        "severity": "high",
                        "affected_component": f"WordPress plugin: {plugin_name}",
                        "cve_id": f"CVE-{cve}" if cve else None,
                        "remediation": f"Update or remove the plugin '{plugin_name}'.",
                    })

            # Users enumerated
            users = data.get("users", {})
            if users:
                user_list = ", ".join(users.keys())
                findings.append({
                    "title": f"WordPress user enumeration: {len(users)} user(s) found",
                    "description": f"The following WordPress usernames were enumerated: {user_list}",
                    "severity": "medium",
                    "affected_component": "WordPress user enumeration",
                    "remediation": "Disable user enumeration by blocking /?author= requests and REST API /users endpoint.",
                })

        save_findings_to_db(scan_id, org_id, asset_id, findings)
        publish_output(scan_id, f"[wpscan] Complete. {len(findings)} findings.")
        update_scan_status(scan_id, "completed")

    except Exception as exc:
        update_scan_status(scan_id, "failed", str(exc))
        raise self.retry(exc=exc, countdown=10)
