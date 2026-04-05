import subprocess
import os
import json
import uuid
import psycopg2
from datetime import datetime, timezone
from typing import Optional, Set
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)
from core.config import settings


def _create_subdomain_asset(org_id: str, subdomain: str):
    """Create an Asset record for a discovered subdomain."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        # Check if already exists
        cur.execute(
            "SELECT id FROM assets WHERE org_id = %s AND value = %s",
            (org_id, subdomain),
        )
        if cur.fetchone():
            cur.close()
            conn.close()
            return

        asset_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        cur.execute(
            """
            INSERT INTO assets (id, org_id, name, type, value, is_active, created_at, updated_at)
            VALUES (%s, %s, %s, 'domain', %s, true, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (asset_id, org_id, subdomain, subdomain, now, now),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[subdomain] asset creation error: {e}")


@celery_app.task(bind=True, name="worker.tasks.subdomain_task.run_subdomain_enum")
def run_subdomain_enum(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    domain: str,
    options: dict,
):
    harvest_output = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_harvest")
    dnsrecon_output = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_dnsrecon.json")
    update_scan_status(scan_id, "running")

    sources = options.get("sources", ["google", "bing", "crtsh", "dnsdumpster"])
    limit = options.get("limit", 500)

    discovered: Set[str] = set()
    raw_lines = []

    # --- theHarvester ---
    sources_str = ",".join(sources)
    cmd_harvest = [
        "theHarvester",
        "-d", domain,
        "-b", sources_str,
        "-l", str(limit),
        "-f", harvest_output,
    ]
    publish_output(scan_id, f"[subdomain] Running theHarvester: {' '.join(cmd_harvest)}")

    try:
        process = subprocess.Popen(
            cmd_harvest,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in process.stdout:
            line = line.rstrip()
            if line:
                publish_output(scan_id, line)
                raw_lines.append(line)
                # Extract subdomains from output
                if "." in line and domain in line and not line.startswith("[") and not line.startswith("-"):
                    candidate = line.strip().split()[-1] if line.strip().split() else ""
                    if domain in candidate and candidate.startswith(("."+domain).lstrip(".")):
                        discovered.add(candidate.lower().strip("."))

        process.wait()
    except FileNotFoundError:
        publish_output(scan_id, "[subdomain] theHarvester not found, skipping.")

    # Parse theHarvester JSON output if it exists
    for ext in [".json", "_hosts.json"]:
        harvest_json = harvest_output + ext
        if os.path.exists(harvest_json):
            try:
                with open(harvest_json, "r") as f:
                    harvest_data = json.load(f)
                hosts = harvest_data.get("hosts", [])
                for h in hosts:
                    subdomain = h.split(":")[0].strip() if ":" in h else h.strip()
                    if domain in subdomain:
                        discovered.add(subdomain.lower())
            except Exception:
                pass

    # --- dnsrecon ---
    cmd_dnsrecon = [
        "dnsrecon",
        "-d", domain,
        "-t", "std",
        "-j", dnsrecon_output,
    ]
    publish_output(scan_id, f"[subdomain] Running dnsrecon: {' '.join(cmd_dnsrecon)}")

    try:
        process = subprocess.Popen(
            cmd_dnsrecon,
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
    except FileNotFoundError:
        publish_output(scan_id, "[subdomain] dnsrecon not found, skipping.")

    if os.path.exists(dnsrecon_output):
        try:
            with open(dnsrecon_output, "r") as f:
                dnsrecon_data = json.load(f)
            for record in dnsrecon_data:
                if isinstance(record, dict):
                    name = record.get("name", "")
                    if domain in name:
                        discovered.add(name.lower().strip("."))
        except Exception:
            pass

    update_scan_raw_output(scan_id, "\n".join(raw_lines))

    # Remove base domain itself
    discovered.discard(domain.lower())
    discovered.discard(f"www.{domain}".lower())

    # Create findings + assets for discovered subdomains
    findings = []
    for subdomain in sorted(discovered):
        findings.append({
            "title": f"Subdomain discovered: {subdomain}",
            "description": f"Subdomain {subdomain} was discovered during enumeration of {domain}.",
            "severity": "info",
            "affected_component": subdomain,
            "raw_output": f"theHarvester/dnsrecon: {subdomain}",
            "remediation": "Review whether this subdomain is expected. Ensure dangling DNS entries are removed.",
        })
        _create_subdomain_asset(org_id, subdomain)

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[subdomain] Enumeration complete. {len(discovered)} subdomains found, {count} findings saved.")
    update_scan_status(scan_id, "completed")
