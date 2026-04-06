import subprocess, os, json, re
from worker.celery_app import celery_app
from worker.tasks.base import publish_output, update_scan_status, save_findings_to_db
from core.config import settings


@celery_app.task(bind=True, name="worker.tasks.recon_ng_task.run_recon_ng", max_retries=1)
def run_recon_ng(self, scan_id: str, org_id: str, asset_id: str, target: str, options: dict):
    """
    Modular reconnaissance with recon-ng.
    Options:
      - workspace: str  recon-ng workspace name
      - modules: list   module paths to run e.g. ['recon/domains-hosts/google_site_web']
    """
    os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
    workspace = options.get("workspace", scan_id)
    modules = options.get("modules", ["recon/domains-hosts/google_site_web"])
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_recon_ng.json")

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[recon-ng] Starting workspace '{workspace}' for target: {target}")

    findings = []
    try:
        for module in modules:
            publish_output(scan_id, f"[recon-ng] Loading module: {module}")
            # Build recon-ng resource file
            resource_cmds = [
                f"workspaces create {workspace}",
                f"modules load {module}",
                f"options set SOURCE {target}",
                "run",
                f"loot export json --filename {output_file}",
                "exit",
            ]
            resource_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_recon.rc")
            with open(resource_file, "w") as rf:
                rf.write("\n".join(resource_cmds))

            proc = subprocess.Popen(
                ["recon-ng", "-r", resource_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    publish_output(scan_id, line)
            proc.wait()

            # Parse JSON loot output
            if os.path.exists(output_file):
                with open(output_file) as f:
                    try:
                        loot = json.load(f)
                        hosts = loot.get("hosts", [])
                        contacts = loot.get("contacts", [])
                        credentials = loot.get("credentials", [])

                        for host in hosts:
                            host_val = host.get("host") or host.get("ip_address", "")
                            if host_val:
                                publish_output(scan_id, f"[recon-ng] Discovered host: {host_val}")
                                findings.append({
                                    "title": f"Discovered host: {host_val}",
                                    "description": f"Host '{host_val}' discovered via recon-ng module {module}.",
                                    "severity": "info",
                                    "affected_component": host_val,
                                    "remediation": "Review whether this host is expected to be publicly visible.",
                                })

                        for contact in contacts:
                            email = contact.get("email", "")
                            if email:
                                publish_output(scan_id, f"[recon-ng] Contact found: {email}")
                                findings.append({
                                    "title": f"Email address exposed: {email}",
                                    "description": f"Email address '{email}' found via OSINT recon for {target}.",
                                    "severity": "low",
                                    "affected_component": email,
                                    "remediation": "Consider email harvesting risk. Enable DMARC to reduce phishing surface.",
                                })

                        for cred in credentials:
                            publish_output(scan_id, f"[recon-ng] Credential found!")
                            findings.append({
                                "title": "Credential found via OSINT",
                                "description": f"Credential data discovered: {json.dumps(cred)}",
                                "severity": "critical",
                                "affected_component": target,
                                "remediation": "Immediately rotate any exposed credentials.",
                            })
                    except json.JSONDecodeError:
                        publish_output(scan_id, "[recon-ng] Could not parse JSON loot output")

    except FileNotFoundError:
        publish_output(scan_id, "[recon-ng] recon-ng not found — skipping. Install with: pip install recon-ng")
        update_scan_status(scan_id, "failed", "recon-ng binary not found")
        return

    except Exception as exc:
        update_scan_status(scan_id, "failed", str(exc))
        raise self.retry(exc=exc, countdown=15)

    save_findings_to_db(scan_id, org_id, asset_id, findings)
    publish_output(scan_id, f"[recon-ng] Complete. {len(findings)} findings.")
    update_scan_status(scan_id, "completed")
