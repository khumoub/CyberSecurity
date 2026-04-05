import subprocess
import os
import xml.etree.ElementTree as ET
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

# Ports/services considered risky with their severity
RISKY_SERVICES = {
    "telnet": ("high", "Telnet is an unencrypted remote access protocol"),
    "ftp": ("medium", "FTP transmits data and credentials in cleartext"),
    "rsh": ("high", "RSH is an insecure remote shell protocol"),
    "rlogin": ("high", "rlogin is an insecure remote login protocol"),
    "rexec": ("high", "rexec is an insecure remote execution protocol"),
    "tftp": ("medium", "TFTP has no authentication"),
    "vnc": ("medium", "VNC remote desktop may be exposed"),
    "rdp": ("medium", "RDP exposed to internet increases attack surface"),
    "smb": ("medium", "SMB/NetBIOS may be vulnerable to exploits"),
    "snmp": ("medium", "SNMP may expose sensitive system information"),
    "irc": ("low", "IRC service detected"),
    "finger": ("medium", "Finger protocol leaks user information"),
}

RISKY_PORTS = {
    23: ("high", "Telnet port open"),
    21: ("medium", "FTP port open"),
    512: ("high", "rexec port open"),
    513: ("high", "rlogin port open"),
    514: ("high", "rsh port open"),
    69: ("medium", "TFTP port open"),
    5900: ("medium", "VNC port open"),
    3389: ("medium", "RDP port open"),
    445: ("medium", "SMB port open"),
    139: ("medium", "NetBIOS port open"),
    161: ("medium", "SNMP port open"),
    194: ("low", "IRC port open"),
    79: ("medium", "Finger port open"),
}


@celery_app.task(bind=True, name="worker.tasks.nmap_task.run_nmap", max_retries=2)
def run_nmap(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    xml_output = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}.xml")
    update_scan_status(scan_id, "running")

    ports = options.get("ports", "1-65535")
    scan_type = options.get("scan_type", "tcp_syn")
    os_detection = options.get("os_detection", False)
    service_detection = options.get("service_detection", True)
    scripts = options.get("scripts", [])

    cmd = ["nmap"]

    if scan_type == "tcp_syn":
        cmd.append("-sS")
    elif scan_type == "udp":
        cmd.append("-sU")
    elif scan_type == "comprehensive":
        cmd.extend(["-sS", "-sU"])
    else:
        cmd.append("-sT")  # TCP connect fallback

    cmd.extend(["-p", ports])

    if service_detection:
        cmd.append("-sV")
    if os_detection:
        cmd.append("-O")
    if scripts:
        cmd.extend(["--script", ",".join(scripts)])

    cmd.extend(["-oX", xml_output, "--open", "-T4", target])

    publish_output(scan_id, f"[nmap] Starting scan: {' '.join(cmd)}")

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
        raw_output = "\n".join(raw_lines)
        update_scan_raw_output(scan_id, raw_output)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"nmap exited with code {process.returncode}")

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "nmap binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # Parse XML output
    findings = []
    try:
        if os.path.exists(xml_output):
            tree = ET.parse(xml_output)
            root = tree.getroot()

            for host in root.findall("host"):
                host_addr = ""
                hostname = ""

                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        host_addr = addr.get("addr", "")

                hostnames_el = host.find("hostnames")
                if hostnames_el is not None:
                    for hn in hostnames_el.findall("hostname"):
                        hostname = hn.get("name", "")
                        break

                host_label = hostname or host_addr or target

                # OS detection
                os_el = host.find("os")
                if os_el is not None:
                    for osmatch in os_el.findall("osmatch"):
                        os_name = osmatch.get("name", "")
                        os_acc = osmatch.get("accuracy", "")
                        publish_output(scan_id, f"[nmap] OS detected: {os_name} ({os_acc}% accuracy)")

                ports_el = host.find("ports")
                if ports_el is None:
                    continue

                for port_el in ports_el.findall("port"):
                    portid = int(port_el.get("portid", 0))
                    protocol = port_el.get("protocol", "tcp")

                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    service_el = port_el.find("service")
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    service_extra = ""

                    if service_el is not None:
                        service_name = service_el.get("name", "")
                        service_product = service_el.get("product", "")
                        service_version = service_el.get("version", "")
                        service_extra = service_el.get("extrainfo", "")

                    service_label = " ".join(filter(None, [service_product, service_version, service_extra]))

                    # Create INFO finding for open port
                    finding = {
                        "title": f"Open port {portid}/{protocol} on {host_label}",
                        "description": (
                            f"Port {portid}/{protocol} is open on {host_label}. "
                            f"Service: {service_name or 'unknown'}. "
                            f"{service_label}"
                        ).strip(),
                        "severity": "info",
                        "affected_component": host_label,
                        "affected_port": portid,
                        "affected_service": service_name or None,
                        "raw_output": f"nmap: {host_label}:{portid}/{protocol} open {service_name} {service_label}",
                        "remediation": "Review whether this port needs to be publicly accessible and apply firewall rules as appropriate.",
                    }
                    findings.append(finding)

                    # Upgrade severity for risky services
                    risky = RISKY_SERVICES.get(service_name.lower()) or RISKY_PORTS.get(portid)
                    if risky:
                        severity, reason = risky
                        findings.append({
                            "title": f"Risky service {service_name or str(portid)} exposed on {host_label}",
                            "description": f"{reason}. Detected on {host_label}:{portid}/{protocol}.",
                            "severity": severity,
                            "affected_component": host_label,
                            "affected_port": portid,
                            "affected_service": service_name or None,
                            "remediation": f"Disable or restrict access to {service_name or 'this service'} unless strictly required.",
                        })

                    # Script output findings
                    for script_el in port_el.findall("script"):
                        script_id = script_el.get("id", "")
                        script_output = script_el.get("output", "")
                        if script_output:
                            findings.append({
                                "title": f"Nmap script {script_id} result on {host_label}:{portid}",
                                "description": script_output[:2000],
                                "severity": "info",
                                "affected_component": host_label,
                                "affected_port": portid,
                                "raw_output": script_output,
                            })

    except ET.ParseError as e:
        publish_output(scan_id, f"[nmap] XML parse error: {e}")

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[nmap] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
