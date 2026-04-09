import subprocess, os, json
from worker.celery_app import celery_app as celery
from worker.tasks.base import publish_output, update_scan_status, save_findings_to_db
from core.config import settings


@celery.task(bind=True, name="worker.tasks.whatweb_task.run_whatweb", max_retries=1)
def run_whatweb(self, scan_id: str, org_id: str, asset_id: str, target: str, options: dict):
    """
    Web technology fingerprinting with WhatWeb.
    Options:
      - aggression: int 1-4 (default 1 — stealthy)
    """
    os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_whatweb.json")
    aggression = min(int(options.get("aggression", 1)), 3)

    cmd = ["whatweb", f"--aggression={aggression}", "--log-json", output_file, target]

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[whatweb] Fingerprinting: {target}")

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
            if isinstance(data, list):
                for entry in data:
                    plugins = entry.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        versions = []
                        if isinstance(plugin_data, dict):
                            versions = plugin_data.get("version", [])
                        if versions:
                            ver_str = ", ".join(str(v) for v in versions)
                            publish_output(scan_id, f"[whatweb] Detected: {plugin_name} {ver_str}")
                            findings.append({
                                "title": f"Technology detected: {plugin_name} {ver_str}",
                                "description": (
                                    f"{plugin_name} version {ver_str} detected on {target}. "
                                    f"Verify this version is current and supported."
                                ),
                                "severity": "info",
                                "affected_component": plugin_name,
                                "remediation": f"Ensure {plugin_name} is updated to the latest supported version and unnecessary version banners are suppressed.",
                            })

        save_findings_to_db(scan_id, org_id, asset_id, findings)
        publish_output(scan_id, f"[whatweb] Complete. {len(findings)} technologies identified.")
        update_scan_status(scan_id, "completed")

    except Exception as exc:
        update_scan_status(scan_id, "failed", str(exc))
        raise self.retry(exc=exc, countdown=10)
