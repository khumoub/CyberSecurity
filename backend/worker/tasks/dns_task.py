import subprocess
from typing import Optional
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)


def _run_dig(args: list, timeout: int = 15) -> str:
    """Run dig with given args and return stdout."""
    try:
        result = subprocess.run(
            ["dig"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


@celery_app.task(bind=True, name="worker.tasks.dns_task.run_dns_analysis")
def run_dns_analysis(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    domain: str,
    options: dict,
):
    update_scan_status(scan_id, "running")
    findings = []
    raw_lines = []

    # --- SPF check ---
    publish_output(scan_id, f"[dns] Checking SPF for {domain}")
    spf_output = _run_dig([domain, "TXT", "+short"])
    raw_lines.append(f"SPF check:\n{spf_output}")

    if "v=spf1" not in spf_output.lower():
        findings.append({
            "title": f"SPF record missing for {domain}",
            "description": (
                f"No SPF (Sender Policy Framework) record was found for {domain}. "
                "SPF prevents email spoofing by defining authorized mail senders."
            ),
            "severity": "medium",
            "affected_component": domain,
            "affected_service": "dns",
            "remediation": (
                "Add an SPF TXT record to your DNS. Example: "
                '"v=spf1 include:_spf.google.com ~all"'
            ),
            "references": ["https://www.rfc-editor.org/rfc/rfc7208"],
        })
    else:
        publish_output(scan_id, f"[dns] SPF found: OK")

    # --- DMARC check ---
    publish_output(scan_id, f"[dns] Checking DMARC for {domain}")
    dmarc_output = _run_dig([f"_dmarc.{domain}", "TXT", "+short"])
    raw_lines.append(f"DMARC check:\n{dmarc_output}")

    if "v=dmarc1" not in dmarc_output.lower():
        findings.append({
            "title": f"DMARC record missing for {domain}",
            "description": (
                f"No DMARC (Domain-based Message Authentication) record found for {domain}. "
                "DMARC ensures that SPF and DKIM are properly aligned and specifies policy for failing emails."
            ),
            "severity": "high",
            "affected_component": domain,
            "affected_service": "dns",
            "remediation": (
                "Add a DMARC TXT record: "
                '"v=DMARC1; p=quarantine; rua=mailto:dmarc@' + domain + '"'
            ),
            "references": ["https://www.rfc-editor.org/rfc/rfc7489"],
        })
    else:
        publish_output(scan_id, f"[dns] DMARC found: OK")

    # --- DKIM check ---
    dkim_selector = options.get("dkim_selector")
    if dkim_selector:
        publish_output(scan_id, f"[dns] Checking DKIM selector {dkim_selector}")
        dkim_output = _run_dig([f"{dkim_selector}._domainkey.{domain}", "TXT", "+short"])
        raw_lines.append(f"DKIM check:\n{dkim_output}")
        if "v=dkim1" not in dkim_output.lower() and "p=" not in dkim_output.lower():
            findings.append({
                "title": f"DKIM key not found for selector {dkim_selector}",
                "description": f"No DKIM key found for selector {dkim_selector}._domainkey.{domain}",
                "severity": "medium",
                "affected_component": domain,
                "affected_service": "dns",
                "remediation": "Configure DKIM signing for your email provider and publish the public key in DNS.",
            })

    # --- DNSSEC check ---
    publish_output(scan_id, f"[dns] Checking DNSSEC for {domain}")
    dnssec_output = _run_dig([domain, "+dnssec", "A"])
    raw_lines.append(f"DNSSEC check:\n{dnssec_output}")

    if "ad" not in dnssec_output.lower() and "rrsig" not in dnssec_output.lower():
        findings.append({
            "title": f"DNSSEC not enabled for {domain}",
            "description": (
                f"DNSSEC (DNS Security Extensions) is not enabled for {domain}. "
                "DNSSEC protects against DNS spoofing and cache poisoning attacks."
            ),
            "severity": "low",
            "affected_component": domain,
            "affected_service": "dns",
            "remediation": "Enable DNSSEC signing with your DNS registrar and hosting provider.",
            "references": ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"],
        })

    # --- MX records ---
    publish_output(scan_id, f"[dns] Checking MX records for {domain}")
    mx_output = _run_dig([domain, "MX", "+short"])
    raw_lines.append(f"MX check:\n{mx_output}")

    if mx_output.strip():
        mx_records = [line.strip() for line in mx_output.strip().splitlines() if line.strip()]
        findings.append({
            "title": f"MX records found for {domain}",
            "description": f"Mail exchange records: {', '.join(mx_records)}",
            "severity": "info",
            "affected_component": domain,
            "affected_service": "dns",
            "remediation": "Verify MX records are pointing to your authorized mail servers.",
        })

    # --- Zone transfer attempt ---
    publish_output(scan_id, f"[dns] Attempting zone transfer (AXFR) for {domain}")
    axfr_output = _run_dig([domain, "AXFR", f"@{domain}"])
    raw_lines.append(f"AXFR check:\n{axfr_output}")

    if axfr_output and "Transfer failed" not in axfr_output and "connection refused" not in axfr_output.lower():
        # Count record lines (non-comment, non-empty)
        record_lines = [l for l in axfr_output.splitlines() if l.strip() and not l.startswith(";")]
        if len(record_lines) > 5:
            findings.append({
                "title": f"DNS zone transfer possible for {domain}",
                "description": (
                    f"The DNS server for {domain} allows zone transfers (AXFR). "
                    "This exposes all DNS records to unauthorized parties, aiding reconnaissance."
                ),
                "severity": "critical",
                "affected_component": domain,
                "affected_service": "dns",
                "remediation": "Restrict DNS zone transfers to authorized secondary DNS servers only.",
                "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
                "raw_output": axfr_output[:3000],
            })

    update_scan_raw_output(scan_id, "\n\n".join(raw_lines))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[dns] DNS analysis complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
