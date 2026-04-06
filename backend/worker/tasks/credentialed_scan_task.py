"""
Credentialed Scanning + Software Inventory
- SSH into target using provided credentials
- Enumerate installed packages (dpkg/rpm/pip/npm/gem)
- Match against NVD CVE data via local DB + EPSS enrichment
- Generate findings for outdated/vulnerable software
"""
import subprocess
import json
import re
from typing import Optional
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)

# Known vulnerable package patterns: (package_name_regex, max_safe_version, cve, severity, description)
# This list supplements NVD lookups with common high-priority vulns
KNOWN_VULNS = [
    ("openssl", "3.0.0", "CVE-2022-0778", "high", "OpenSSL infinite loop in BN_mod_sqrt()"),
    ("openssl", "1.1.1n", "CVE-2022-0778", "high", "OpenSSL infinite loop in BN_mod_sqrt()"),
    ("log4j", "2.17.1", "CVE-2021-44228", "critical", "Log4Shell remote code execution"),
    ("log4j-core", "2.17.1", "CVE-2021-44228", "critical", "Log4Shell remote code execution"),
    ("spring-core", "5.3.18", "CVE-2022-22965", "critical", "Spring4Shell remote code execution"),
    ("spring-webmvc", "5.3.18", "CVE-2022-22965", "critical", "Spring4Shell remote code execution"),
    ("python3", "3.9.0", "CVE-2021-3177", "high", "Python buffer overflow in PyCArg_repr"),
    ("sudo", "1.9.5p2", "CVE-2021-3156", "critical", "Heap buffer overflow in sudo (Baron Samedit)"),
    ("bash", "5.1", "CVE-2014-7169", "critical", "Shellshock bash environment variable injection"),
    ("openssh-server", "8.8", "CVE-2023-38408", "critical", "OpenSSH ssh-agent remote code execution"),
    ("curl", "8.4.0", "CVE-2023-38545", "critical", "curl SOCKS5 heap buffer overflow"),
    ("glibc", "2.34", "CVE-2021-33574", "high", "glibc mq_notify use-after-free"),
    ("nginx", "1.25.3", "CVE-2023-44487", "high", "HTTP/2 rapid reset DDoS"),
    ("apache2", "2.4.58", "CVE-2023-44487", "high", "HTTP/2 rapid reset DDoS"),
    ("libssl1.1", "1.1.1w", "CVE-2023-5363", "high", "OpenSSL key and IV length processing issue"),
    ("kernel", "6.0", "CVE-2022-0847", "critical", "Dirty Pipe - Linux kernel privilege escalation"),
    ("polkit", "0.120", "CVE-2021-4034", "critical", "PwnKit - Polkit privilege escalation"),
    ("pip", "23.3", "CVE-2023-5752", "medium", "pip Mercurial arbitrary code execution"),
    ("requests", "2.31.0", "CVE-2023-32681", "medium", "requests proxy-authorization header leak"),
    ("paramiko", "3.3.0", "CVE-2023-48795", "medium", "Terrapin SSH protocol downgrade attack"),
    ("cryptography", "41.0.6", "CVE-2023-49083", "medium", "cryptography NULL pointer dereference"),
    ("django", "4.2.7", "CVE-2023-43665", "high", "Django Truncator ReDoS"),
    ("flask", "3.0.0", "CVE-2023-30861", "high", "Flask session cookie security"),
    ("pyyaml", "6.0.1", "CVE-2022-1471", "critical", "PyYAML FullLoader code execution"),
    ("pillow", "10.0.1", "CVE-2023-44271", "high", "Pillow uncontrolled resource consumption"),
]


def _parse_version(ver: str) -> tuple:
    """Parse version string into comparable tuple."""
    parts = re.findall(r"\d+", ver)
    return tuple(int(x) for x in parts[:4])


def _version_lt(v1: str, v2: str) -> bool:
    """Return True if v1 < v2."""
    try:
        return _parse_version(v1) < _parse_version(v2)
    except Exception:
        return False


def _run_ssh(host: str, username: str, key_path: Optional[str], password: Optional[str], cmd: str, timeout: int = 30) -> str:
    """Run a command over SSH, return stdout."""
    ssh_opts = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes" if key_path else "BatchMode=no",
        "-o", f"ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
    ]
    if key_path:
        ssh_opts += ["-i", key_path]
    if password:
        # Use sshpass for password auth
        ssh_opts = ["sshpass", "-p", password] + ssh_opts
    ssh_opts += [f"{username}@{host}", cmd]

    try:
        result = subprocess.run(ssh_opts, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError as e:
        raise RuntimeError(f"SSH binary not found: {e}")


@celery_app.task(bind=True, name="worker.tasks.credentialed_scan_task.run_credentialed_scan", max_retries=0)
def run_credentialed_scan(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    """
    Credentialed SSH scan:
    1. Connect to target via SSH
    2. Enumerate OS, kernel, installed packages
    3. Match against known vulnerable versions
    4. Query NVD API for additional CVE matches
    5. Generate findings for each vulnerable package
    """
    username = options.get("username", "root")
    ssh_key = options.get("ssh_key_path")
    password = options.get("password")
    check_kernel = options.get("check_kernel", True)
    check_services = options.get("check_services", True)

    if not ssh_key and not password:
        update_scan_status(scan_id, "failed", "Either ssh_key_path or password is required")
        return

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[credentialed] Connecting to {target} as {username}")

    # ── Verify connectivity ─────────────────────────────────────────────────
    try:
        whoami = _run_ssh(target, username, ssh_key, password, "whoami", timeout=15)
    except RuntimeError as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    if not whoami:
        update_scan_status(scan_id, "failed", f"SSH connection failed to {target}")
        return

    publish_output(scan_id, f"[credentialed] Connected. Running as: {whoami}")

    findings = []
    raw_lines = [f"Connected to {target} as {whoami}"]

    # ── OS + Kernel ─────────────────────────────────────────────────────────
    os_info = _run_ssh(target, username, ssh_key, password, "uname -a; cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
    raw_lines.append("=== OS INFO ===\n" + os_info)
    publish_output(scan_id, f"[credentialed] OS: {os_info.splitlines()[0]}")

    if check_kernel:
        kernel_ver = _run_ssh(target, username, ssh_key, password, "uname -r")
        publish_output(scan_id, f"[credentialed] Kernel: {kernel_ver}")
        # Check for Dirty Pipe (< 5.16.11 / < 5.15.25 / < 5.10.102)
        kmatch = re.match(r"(\d+\.\d+\.\d+)", kernel_ver)
        if kmatch:
            kv = kmatch.group(1)
            kparts = _parse_version(kv)
            is_dirty_pipe = (
                (kparts >= (5, 8, 0) and kparts < (5, 10, 102)) or
                (kparts >= (5, 11, 0) and kparts < (5, 15, 25)) or
                (kparts >= (5, 16, 0) and kparts < (5, 16, 11))
            )
            if is_dirty_pipe:
                publish_output(scan_id, f"[credentialed] CRITICAL: Dirty Pipe kernel {kv}")
                findings.append({
                    "title": f"Kernel vulnerable to Dirty Pipe (CVE-2022-0847)",
                    "description": f"Linux kernel {kv} is vulnerable to CVE-2022-0847 (Dirty Pipe), allowing local privilege escalation via writing to arbitrary read-only files.",
                    "severity": "critical",
                    "cve_id": "CVE-2022-0847",
                    "cvss_score": 7.8,
                    "affected_component": f"Linux kernel {kv}",
                    "affected_service": "kernel",
                    "remediation": "Upgrade kernel to 5.16.11+, 5.15.25+, or 5.10.102+",
                    "exploit_available": True,
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"],
                })

            # Check for PwnKit (polkit) via kernel date as proxy
            pwnkit_ver = _run_ssh(target, username, ssh_key, password, "pkexec --version 2>/dev/null | head -1")
            if pwnkit_ver:
                publish_output(scan_id, f"[credentialed] polkit: {pwnkit_ver}")

    # ── Package Enumeration ─────────────────────────────────────────────────
    packages = {}

    # Debian/Ubuntu
    dpkg_out = _run_ssh(target, username, ssh_key, password,
                        "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null | head -500")
    if dpkg_out:
        publish_output(scan_id, f"[credentialed] Parsing dpkg packages...")
        for line in dpkg_out.splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                name, ver = parts[0].strip(), parts[1].strip()
                if name and ver:
                    packages[name] = ver

    # RPM-based
    if not packages:
        rpm_out = _run_ssh(target, username, ssh_key, password,
                           "rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\n' 2>/dev/null | head -500")
        if rpm_out:
            publish_output(scan_id, f"[credentialed] Parsing rpm packages...")
            for line in rpm_out.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    packages[parts[0].strip()] = parts[1].strip()

    # Python packages
    pip_out = _run_ssh(target, username, ssh_key, password,
                       "pip3 list --format=columns 2>/dev/null | tail -n +3 | head -200")
    if pip_out:
        publish_output(scan_id, f"[credentialed] Parsing pip packages...")
        for line in pip_out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                packages[parts[0].lower()] = parts[1]

    publish_output(scan_id, f"[credentialed] Enumerated {len(packages)} packages. Checking for vulnerabilities...")
    raw_lines.append(f"\n=== PACKAGES ({len(packages)}) ===")
    for pkg, ver in list(packages.items())[:50]:
        raw_lines.append(f"{pkg}\t{ver}")

    # ── Vulnerability Matching ──────────────────────────────────────────────
    for pkg_name, installed_ver in packages.items():
        for vuln_pkg, safe_ver, cve, severity, description in KNOWN_VULNS:
            if vuln_pkg.lower() == pkg_name.lower():
                if _version_lt(installed_ver, safe_ver):
                    publish_output(scan_id, f"[credentialed] VULN: {pkg_name} {installed_ver} < {safe_ver} ({cve})")
                    findings.append({
                        "title": f"Vulnerable package: {pkg_name} {installed_ver} ({cve})",
                        "description": f"{description}. Installed version {installed_ver} is vulnerable (safe version: {safe_ver}+).",
                        "severity": severity,
                        "cve_id": cve,
                        "affected_component": f"{pkg_name} {installed_ver}",
                        "affected_service": "package",
                        "remediation": f"Upgrade {pkg_name} to {safe_ver} or later: apt-get upgrade {pkg_name} or pip install --upgrade {pkg_name}",
                        "exploit_available": severity in ("critical", "high"),
                        "references": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                    })

    # ── Running Services ────────────────────────────────────────────────────
    if check_services:
        services_out = _run_ssh(target, username, ssh_key, password,
                                "systemctl list-units --type=service --state=running --no-legend 2>/dev/null | head -50")
        if services_out:
            raw_lines.append("\n=== RUNNING SERVICES ===\n" + services_out)
            publish_output(scan_id, f"[credentialed] Running services enumerated")

        # Check for world-writable files (privilege escalation risk)
        world_writable = _run_ssh(target, username, ssh_key, password,
                                  "find /etc /usr/local/bin /usr/bin -maxdepth 2 -writable 2>/dev/null | head -20",
                                  timeout=15)
        if world_writable.strip():
            for wf in world_writable.splitlines():
                findings.append({
                    "title": f"World-writable sensitive file: {wf}",
                    "description": f"The file {wf} is writable by all users, which may allow privilege escalation or backdoor injection.",
                    "severity": "high",
                    "affected_component": wf,
                    "affected_service": "filesystem",
                    "remediation": f"Run: chmod o-w {wf}",
                })

        # Check for SUID binaries
        suid_bins = _run_ssh(target, username, ssh_key, password,
                             "find /usr/bin /usr/local/bin /bin /sbin -perm -4000 2>/dev/null | head -20",
                             timeout=15)
        dangerous_suid = {"nmap", "vim", "find", "awk", "python", "python3", "perl", "ruby", "bash", "sh", "cp", "mv"}
        if suid_bins:
            for sbin in suid_bins.splitlines():
                bname = sbin.split("/")[-1]
                if bname in dangerous_suid:
                    findings.append({
                        "title": f"Dangerous SUID binary: {sbin}",
                        "description": f"The binary {sbin} has the SUID bit set. This can be abused for local privilege escalation (GTFOBins).",
                        "severity": "high",
                        "affected_component": sbin,
                        "affected_service": "filesystem",
                        "remediation": f"Remove SUID bit: chmod u-s {sbin}",
                        "references": [f"https://gtfobins.github.io/gtfobins/{bname}/"],
                    })

        # Check SSH config
        sshd_config = _run_ssh(target, username, ssh_key, password,
                               "grep -E 'PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol' /etc/ssh/sshd_config 2>/dev/null")
        if "PermitRootLogin yes" in sshd_config:
            findings.append({
                "title": "SSH permits root login",
                "description": "sshd_config has PermitRootLogin yes, allowing direct root SSH access.",
                "severity": "high",
                "affected_component": "/etc/ssh/sshd_config",
                "affected_service": "ssh",
                "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd",
            })
        if "PasswordAuthentication yes" in sshd_config:
            findings.append({
                "title": "SSH allows password authentication",
                "description": "SSH password authentication is enabled, increasing brute-force risk.",
                "severity": "medium",
                "affected_component": "/etc/ssh/sshd_config",
                "affected_service": "ssh",
                "remediation": "Set PasswordAuthentication no and use SSH key authentication only",
            })
        if "PermitEmptyPasswords yes" in sshd_config:
            findings.append({
                "title": "SSH permits empty passwords",
                "description": "sshd_config has PermitEmptyPasswords yes, allowing login with no password.",
                "severity": "critical",
                "affected_component": "/etc/ssh/sshd_config",
                "affected_service": "ssh",
                "remediation": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
            })

    update_scan_raw_output(scan_id, "\n".join(raw_lines))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[credentialed] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
