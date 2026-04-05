import subprocess
import os
import xml.etree.ElementTree as ET
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
from core.config import settings

WEAK_CIPHERS = {
    "RC4": ("medium", "RC4 cipher is considered weak"),
    "DES": ("high", "DES cipher is cryptographically broken"),
    "3DES": ("medium", "Triple DES is being deprecated"),
    "MD5": ("medium", "MD5-based cipher suites are weak"),
    "EXPORT": ("critical", "EXPORT grade ciphers are cryptographically broken (FREAK/LOGJAM)"),
    "NULL": ("critical", "NULL cipher provides no encryption"),
    "anon": ("critical", "Anonymous cipher suites provide no authentication"),
}

INSECURE_PROTOCOLS = {
    "SSLv2": ("critical", "SSLv2 is completely broken and should be disabled"),
    "SSLv3": ("critical", "SSLv3 is vulnerable to POODLE attack"),
    "TLSv1.0": ("high", "TLS 1.0 is deprecated and vulnerable to BEAST attack"),
    "TLSv1.1": ("medium", "TLS 1.1 is deprecated"),
}


@celery_app.task(bind=True, name="worker.tasks.ssl_task.run_sslscan")
def run_sslscan(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    port = options.get("port", 443)
    xml_output = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_ssl.xml")
    update_scan_status(scan_id, "running")

    target_with_port = f"{target}:{port}" if ":" not in str(target) else target
    cmd = ["sslscan", f"--xml={xml_output}", "--no-colour", target_with_port]

    publish_output(scan_id, f"[sslscan] Starting scan: {' '.join(cmd)}")

    raw_lines = []
    try:
        process = subprocess.Popen(
            cmd,
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
        update_scan_raw_output(scan_id, "\n".join(raw_lines))

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "sslscan binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    findings = []
    now = datetime.now(timezone.utc)

    try:
        if os.path.exists(xml_output):
            tree = ET.parse(xml_output)
            root = tree.getroot()

            for ssltest in root.findall(".//ssltest"):
                host = ssltest.get("host", target)
                port_num = ssltest.get("port", str(port))

                # --- Certificate checks ---
                cert = ssltest.find("certificate")
                if cert is not None:
                    # Expiry
                    not_after_el = cert.find("not-valid-after")
                    if not_after_el is not None and not_after_el.text:
                        try:
                            expiry_str = not_after_el.text.strip()
                            # sslscan format: "May 15 12:00:00 2025 GMT"
                            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            days_remaining = (expiry - now).days

                            if days_remaining < 0:
                                findings.append({
                                    "title": f"SSL/TLS certificate expired on {host}",
                                    "description": f"Certificate expired on {expiry_str}. Expired by {abs(days_remaining)} days.",
                                    "severity": "critical",
                                    "affected_component": f"{host}:{port_num}",
                                    "affected_port": int(port_num),
                                    "affected_service": "ssl/tls",
                                    "remediation": "Renew the SSL/TLS certificate immediately.",
                                })
                            elif days_remaining < 30:
                                findings.append({
                                    "title": f"SSL/TLS certificate expiring soon on {host}",
                                    "description": f"Certificate expires in {days_remaining} days ({expiry_str}).",
                                    "severity": "high",
                                    "affected_component": f"{host}:{port_num}",
                                    "affected_port": int(port_num),
                                    "affected_service": "ssl/tls",
                                    "remediation": "Renew the SSL/TLS certificate within the next 30 days.",
                                })
                            elif days_remaining < 90:
                                findings.append({
                                    "title": f"SSL/TLS certificate expiring in {days_remaining} days on {host}",
                                    "description": f"Certificate expires on {expiry_str}.",
                                    "severity": "medium",
                                    "affected_component": f"{host}:{port_num}",
                                    "affected_port": int(port_num),
                                    "affected_service": "ssl/tls",
                                    "remediation": "Plan SSL/TLS certificate renewal.",
                                })
                        except (ValueError, AttributeError):
                            pass

                    # Self-signed check
                    self_signed_el = cert.find("self-signed")
                    if self_signed_el is not None and self_signed_el.text == "true":
                        findings.append({
                            "title": f"Self-signed SSL/TLS certificate on {host}",
                            "description": "The server is using a self-signed certificate not trusted by browsers.",
                            "severity": "medium",
                            "affected_component": f"{host}:{port_num}",
                            "affected_port": int(port_num),
                            "affected_service": "ssl/tls",
                            "remediation": "Replace with a certificate from a trusted Certificate Authority (CA).",
                        })

                # --- Protocol checks ---
                for proto_el in ssltest.findall("protocol"):
                    proto_name = proto_el.get("type", "")
                    proto_version = proto_el.get("version", "")
                    proto_label = f"{proto_name}v{proto_version}" if proto_version else proto_name
                    enabled = proto_el.get("enabled", "0")

                    if enabled == "1":
                        for insecure_label, (severity, reason) in INSECURE_PROTOCOLS.items():
                            if insecure_label.replace("v", "").replace(".", "").lower() in proto_label.replace(".", "").lower():
                                findings.append({
                                    "title": f"Insecure protocol {proto_label} enabled on {host}",
                                    "description": reason,
                                    "severity": severity,
                                    "affected_component": f"{host}:{port_num}",
                                    "affected_port": int(port_num),
                                    "affected_service": "ssl/tls",
                                    "remediation": f"Disable {proto_label} and enforce TLS 1.2 or TLS 1.3 minimum.",
                                })

                # --- Cipher checks ---
                seen_weak_ciphers = set()
                for cipher_el in ssltest.findall("cipher"):
                    status = cipher_el.get("status", "")
                    if status not in ("accepted", "preferred"):
                        continue

                    cipher_name = cipher_el.get("cipher", "")
                    cipher_bits = cipher_el.get("bits", "")
                    sslversion = cipher_el.get("sslversion", "")

                    for weak_key, (severity, reason) in WEAK_CIPHERS.items():
                        if weak_key.lower() in cipher_name.lower() and weak_key not in seen_weak_ciphers:
                            seen_weak_ciphers.add(weak_key)
                            findings.append({
                                "title": f"Weak cipher suite {weak_key} supported on {host}",
                                "description": f"{reason}. Cipher: {cipher_name} ({cipher_bits}-bit) on {sslversion}.",
                                "severity": severity,
                                "affected_component": f"{host}:{port_num}",
                                "affected_port": int(port_num),
                                "affected_service": "ssl/tls",
                                "remediation": f"Disable {weak_key}-based cipher suites and configure only strong, modern ciphers.",
                            })

    except ET.ParseError as e:
        publish_output(scan_id, f"[sslscan] XML parse error: {e}")

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[sslscan] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
