import subprocess, os, re
from worker.celery_app import celery
from worker.tasks.base import publish_output, update_scan_status, save_findings_to_db
from core.config import settings


@celery.task(bind=True, name="worker.tasks.masscan_task.run_masscan", max_retries=1)
def run_masscan(self, scan_id: str, org_id: str, asset_id: str, target: str, options: dict):
    """
    Large-scale port scanning with masscan.
    Options:
      - ports: str  e.g. "1-65535" or "0-1023,8080,8443"
      - rate: int   packets/sec (default 1000, max 10000)
    """
    os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_masscan.txt")
    ports = options.get("ports", "1-1024,8080,8443,8888")
    rate = min(int(options.get("rate", 1000)), 10000)

    cmd = [
        "masscan", target,
        "-p", ports,
        "--rate", str(rate),
        "--open",
        "-oL", output_file,
    ]

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[masscan] Starting scan: {' '.join(cmd)}")

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
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Format: open tcp 80 1.2.3.4 1234567890
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "open":
                        proto, port = parts[1], parts[2]
                        ip = parts[3]
                        risky = {
                            "21": ("FTP open", "MEDIUM"),
                            "23": ("Telnet open — unencrypted", "HIGH"),
                            "445": ("SMB open — potential lateral movement vector", "HIGH"),
                            "3389": ("RDP open", "MEDIUM"),
                            "1433": ("MSSQL open", "MEDIUM"),
                            "3306": ("MySQL open", "MEDIUM"),
                            "5432": ("PostgreSQL open", "MEDIUM"),
                            "6379": ("Redis open (unauthenticated?)", "HIGH"),
                            "27017": ("MongoDB open", "HIGH"),
                            "9200": ("Elasticsearch open", "HIGH"),
                        }
                        title, sev = risky.get(port, (f"Open {proto.upper()} port {port}", "INFO"))
                        findings.append({
                            "title": title,
                            "description": f"Port {port}/{proto} is open on {ip}.",
                            "severity": sev.lower(),
                            "affected_port": int(port),
                            "affected_service": proto,
                            "remediation": "Restrict access to this port with firewall rules if not required.",
                        })
                        publish_output(scan_id, f"[masscan] Found: {ip}:{port}/{proto}")

        save_findings_to_db(scan_id, org_id, asset_id, findings)
        publish_output(scan_id, f"[masscan] Complete. {len(findings)} findings.")
        update_scan_status(scan_id, "completed")

    except Exception as exc:
        update_scan_status(scan_id, "failed", str(exc))
        raise self.retry(exc=exc, countdown=10)
