import subprocess
import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)

# WHOIS field patterns (case-insensitive, handles different registrar formats)
REGISTRAR_RE = re.compile(r"^registrar\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
CREATION_RE = re.compile(
    r"^(?:creation date|created|registered|registration date)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
EXPIRY_RE = re.compile(
    r"^(?:expiry date|expiration date|expire[sd]?|registry expiry date|paid-till)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
NAMESERVER_RE = re.compile(r"^name\s*server\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
REGISTRANT_ORG_RE = re.compile(
    r"^(?:registrant\s*org(?:anization)?|org(?:anization)?)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
REGISTRANT_NAME_RE = re.compile(
    r"^registrant\s*(?:name)?\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)

# Date format candidates
DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d.%m.%Y",
    "%Y/%m/%d",
    "%d/%m/%Y",
    "%B %d, %Y",
]

EXPIRY_THRESHOLD_DAYS = 30


def _parse_date(date_str: str) -> Optional[datetime]:
    """Attempt to parse a date string using multiple formats."""
    date_str = date_str.strip()
    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(date_str[:len(fmt) + 5], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _first_match(pattern: re.Pattern, text: str) -> Optional[str]:
    m = pattern.search(text)
    return m.group(1).strip() if m else None


def _all_matches(pattern: re.Pattern, text: str) -> list:
    return [m.group(1).strip() for m in pattern.finditer(text)]


@celery_app.task(bind=True, name="worker.tasks.whois_task.run_whois", max_retries=2)
def run_whois(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    update_scan_status(scan_id, "running")

    whois_target = options.get("target", target)
    publish_output(scan_id, f"[whois] Querying: {whois_target}")

    try:
        result = subprocess.run(
            ["whois", whois_target],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw_output = result.stdout + result.stderr
    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "whois binary not found")
        return
    except subprocess.TimeoutExpired:
        update_scan_status(scan_id, "failed", "whois query timed out")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    update_scan_raw_output(scan_id, raw_output)

    # Parse fields
    registrar = _first_match(REGISTRAR_RE, raw_output)
    creation_str = _first_match(CREATION_RE, raw_output)
    expiry_str = _first_match(EXPIRY_RE, raw_output)
    name_servers = _all_matches(NAMESERVER_RE, raw_output)
    registrant_org = _first_match(REGISTRANT_ORG_RE, raw_output)
    registrant_name = _first_match(REGISTRANT_NAME_RE, raw_output)

    creation_date = _parse_date(creation_str) if creation_str else None
    expiry_date = _parse_date(expiry_str) if expiry_str else None

    ns_list = "\n".join(f"  - {ns}" for ns in name_servers[:10]) if name_servers else "  - Not found"

    # Build ownership description
    description_parts = [
        f"WHOIS lookup for: {whois_target}\n",
        f"Registrar: {registrar or 'Not found'}",
        f"Registrant: {registrant_org or registrant_name or 'Not found'}",
        f"Creation Date: {creation_str or 'Not found'}",
        f"Expiry Date: {expiry_str or 'Not found'}",
        f"Name Servers:\n{ns_list}",
    ]
    description = "\n".join(description_parts)

    publish_output(scan_id, f"[whois] Registrar: {registrar or 'N/A'}")
    publish_output(scan_id, f"[whois] Expiry: {expiry_str or 'N/A'}")

    findings = []

    # Primary INFO finding with ownership data
    findings.append({
        "title": f"WHOIS record for {whois_target}",
        "description": description,
        "severity": "info",
        "affected_component": whois_target,
        "raw_output": raw_output[:5000],
        "remediation": (
            "Ensure domain registration information is accurate and up to date. "
            "Consider using domain privacy protection if registrant contact details should not be public."
        ),
    })

    # Expiry proximity warning
    if expiry_date:
        now = datetime.now(timezone.utc)
        days_until_expiry = (expiry_date - now).days

        if days_until_expiry < 0:
            findings.append({
                "title": f"Domain EXPIRED: {whois_target}",
                "description": (
                    f"The domain {whois_target} expired on {expiry_str}. "
                    f"An expired domain may be subject to squatting or takeover."
                ),
                "severity": "high",
                "affected_component": whois_target,
                "raw_output": f"Expiry: {expiry_str}",
                "remediation": (
                    "Immediately renew this domain to prevent unauthorized takeover. "
                    "Contact your registrar as soon as possible."
                ),
            })
            publish_output(scan_id, f"[whois] ALERT: Domain {whois_target} has EXPIRED!")

        elif days_until_expiry <= EXPIRY_THRESHOLD_DAYS:
            findings.append({
                "title": f"Domain expiring soon ({days_until_expiry} days): {whois_target}",
                "description": (
                    f"The domain {whois_target} will expire in {days_until_expiry} day(s) on {expiry_str}.\n\n"
                    f"Domains expiring within {EXPIRY_THRESHOLD_DAYS} days are at risk of service disruption "
                    f"or domain hijacking if not renewed promptly."
                ),
                "severity": "medium",
                "affected_component": whois_target,
                "raw_output": f"Expiry: {expiry_str} ({days_until_expiry} days remaining)",
                "remediation": (
                    f"Renew the domain {whois_target} before it expires. "
                    "Enable auto-renewal where possible to prevent accidental expiry."
                ),
            })
            publish_output(
                scan_id,
                f"[whois] WARNING: {whois_target} expires in {days_until_expiry} days!"
            )

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[whois] Complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
