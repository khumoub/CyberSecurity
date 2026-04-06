"""
CIS Benchmark Compliance Auditing
- SSH-based host configuration audit against CIS benchmarks
- Covers: Ubuntu 22.04, RHEL/CentOS, Debian, generic Linux
- Checks: filesystem, network, logging, auth, services, kernel params
- Each failed check creates a finding with severity + remediation
"""
import subprocess
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


def _ssh_run(host: str, username: str, key_path: Optional[str], password: Optional[str], cmd: str, timeout: int = 20) -> str:
    """Run command over SSH, return stdout."""
    opts = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR"]
    if key_path:
        opts += ["-i", key_path]
    if password:
        opts = ["sshpass", "-p", password] + opts
    opts += [f"{username}@{host}", cmd]
    try:
        result = subprocess.run(opts, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


# ── CIS Check Definitions ────────────────────────────────────────────────────
# Each check: (check_id, title, severity, command, pass_condition, remediation)
# pass_condition: lambda output -> bool (True = PASS)

CIS_CHECKS = [
    # === Filesystem ===
    (
        "1.1.1", "Ensure /tmp is a separate partition", "low",
        "findmnt /tmp 2>/dev/null",
        lambda o: bool(o.strip()),
        "Configure /tmp as a separate partition in /etc/fstab"
    ),
    (
        "1.1.3", "Ensure noexec option set on /tmp partition", "medium",
        "findmnt -n -o OPTIONS /tmp 2>/dev/null",
        lambda o: "noexec" in o,
        "Add noexec to /tmp mount options in /etc/fstab: tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec 0 0"
    ),
    (
        "1.1.4", "Ensure nosuid option set on /tmp partition", "medium",
        "findmnt -n -o OPTIONS /tmp 2>/dev/null",
        lambda o: "nosuid" in o,
        "Add nosuid to /tmp mount options in /etc/fstab"
    ),
    # === Software Updates ===
    (
        "1.9", "Ensure updates/patches/additional security software are installed", "high",
        "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || yum check-update 2>/dev/null | grep -c '\\.' || echo '0'",
        lambda o: o.strip() == "0",
        "Run: apt-get upgrade -y or yum update -y to apply all pending patches"
    ),
    # === Filesystem Integrity ===
    (
        "1.3.1", "Ensure AIDE is installed", "medium",
        "which aide 2>/dev/null || dpkg -l aide 2>/dev/null | grep '^ii'",
        lambda o: bool(o.strip()),
        "Install AIDE: apt-get install aide && aideinit"
    ),
    # === Bootloader ===
    (
        "1.4.1", "Ensure bootloader password is set (GRUB)", "medium",
        "grep -E 'set superusers|password_pbkdf2' /boot/grub/grub.cfg 2>/dev/null /etc/grub.d/* 2>/dev/null",
        lambda o: "superusers" in o or "password_pbkdf2" in o,
        "Set GRUB bootloader password: grub-mkpasswd-pbkdf2 and add to /etc/grub.d/40_custom"
    ),
    # === Kernel Parameters ===
    (
        "3.1.1", "Ensure IP forwarding is disabled", "medium",
        "sysctl net.ipv4.ip_forward 2>/dev/null",
        lambda o: "= 0" in o,
        "Add 'net.ipv4.ip_forward = 0' to /etc/sysctl.d/99-cis.conf and run: sysctl -p"
    ),
    (
        "3.1.2", "Ensure packet redirect sending is disabled", "medium",
        "sysctl net.ipv4.conf.all.send_redirects 2>/dev/null",
        lambda o: "= 0" in o,
        "Add 'net.ipv4.conf.all.send_redirects = 0' to /etc/sysctl.d/99-cis.conf"
    ),
    (
        "3.2.1", "Ensure source routed packets are not accepted", "medium",
        "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null",
        lambda o: "= 0" in o,
        "Set net.ipv4.conf.all.accept_source_route = 0 in sysctl"
    ),
    (
        "3.2.2", "Ensure ICMP redirects are not accepted", "medium",
        "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null",
        lambda o: "= 0" in o,
        "Set net.ipv4.conf.all.accept_redirects = 0 in sysctl"
    ),
    (
        "3.3.1", "Ensure IPv6 router advertisements are not accepted", "low",
        "sysctl net.ipv6.conf.all.accept_ra 2>/dev/null",
        lambda o: "= 0" in o,
        "Set net.ipv6.conf.all.accept_ra = 0 in sysctl or disable IPv6 if not needed"
    ),
    # === Network Services ===
    (
        "2.1.1", "Ensure NIS client is not installed", "medium",
        "dpkg -l nis 2>/dev/null | grep '^ii' || rpm -q ypbind 2>/dev/null | grep -v 'not installed'",
        lambda o: not bool(o.strip()),
        "Remove NIS client: apt-get remove nis or yum remove ypbind"
    ),
    (
        "2.1.2", "Ensure rsh client is not installed", "high",
        "dpkg -l rsh-client 2>/dev/null | grep '^ii' || rpm -q rsh 2>/dev/null | grep -v 'not installed'",
        lambda o: not bool(o.strip()),
        "Remove rsh: apt-get remove rsh-client or yum remove rsh"
    ),
    (
        "2.1.3", "Ensure talk client is not installed", "low",
        "dpkg -l talk 2>/dev/null | grep '^ii' || rpm -q talk 2>/dev/null | grep -v 'not installed'",
        lambda o: not bool(o.strip()),
        "Remove talk: apt-get remove talk"
    ),
    (
        "2.2.1", "Ensure time synchronization is in use (NTP/chrony)", "low",
        "systemctl is-active ntpd 2>/dev/null || systemctl is-active chronyd 2>/dev/null || systemctl is-active systemd-timesyncd 2>/dev/null",
        lambda o: "active" in o,
        "Install and enable chrony: apt-get install chrony && systemctl enable chronyd"
    ),
    (
        "2.2.2", "Ensure X Window System is not installed", "low",
        "dpkg -l xserver-xorg* 2>/dev/null | grep '^ii' || rpm -qa xorg-x11-server* 2>/dev/null",
        lambda o: not bool(o.strip()),
        "Remove X Window System: apt-get remove xserver-xorg"
    ),
    (
        "2.2.3", "Ensure Avahi Server is not installed", "medium",
        "systemctl is-active avahi-daemon 2>/dev/null",
        lambda o: "inactive" in o or "not-found" in o,
        "Disable Avahi: systemctl disable avahi-daemon && apt-get remove avahi-daemon"
    ),
    (
        "2.2.7", "Ensure Samba is not enabled", "medium",
        "systemctl is-active smbd 2>/dev/null",
        lambda o: "inactive" in o or "not-found" in o,
        "Disable Samba if not needed: systemctl disable smbd"
    ),
    # === SSH Server Configuration ===
    (
        "5.2.4", "Ensure SSH Protocol is set to 2", "high",
        "grep -E '^Protocol' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "Protocol 2" in o or o.strip() == "",  # default is 2 now
        "Add 'Protocol 2' to /etc/ssh/sshd_config"
    ),
    (
        "5.2.5", "Ensure SSH MaxAuthTries is set to 4 or less", "medium",
        "grep -E '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: bool(re.search(r"MaxAuthTries\s+[1-4]$", o)),
        "Set MaxAuthTries 4 in /etc/ssh/sshd_config"
    ),
    (
        "5.2.6", "Ensure SSH IgnoreRhosts is enabled", "high",
        "grep -E '^IgnoreRhosts' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "IgnoreRhosts yes" in o or o.strip() == "",
        "Set 'IgnoreRhosts yes' in /etc/ssh/sshd_config"
    ),
    (
        "5.2.7", "Ensure SSH HostbasedAuthentication is disabled", "high",
        "grep -E '^HostbasedAuthentication' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "HostbasedAuthentication no" in o or o.strip() == "",
        "Set 'HostbasedAuthentication no' in /etc/ssh/sshd_config"
    ),
    (
        "5.2.8", "Ensure SSH root login is disabled", "high",
        "grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "PermitRootLogin no" in o or "PermitRootLogin prohibit-password" in o,
        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd"
    ),
    (
        "5.2.9", "Ensure SSH PermitEmptyPasswords is disabled", "critical",
        "grep -E '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "PermitEmptyPasswords no" in o or o.strip() == "",
        "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
    ),
    (
        "5.2.11", "Ensure SSH Idle Timeout is configured", "medium",
        "grep -E '^ClientAliveInterval|^ClientAliveCountMax' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "ClientAliveInterval" in o and "ClientAliveCountMax" in o,
        "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' in /etc/ssh/sshd_config"
    ),
    (
        "5.2.15", "Ensure SSH warning banner is configured", "low",
        "grep -E '^Banner' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "Banner" in o and "none" not in o.lower(),
        "Set 'Banner /etc/issue.net' in /etc/ssh/sshd_config"
    ),
    # === PAM / Authentication ===
    (
        "5.3.1", "Ensure password creation requirements are configured", "medium",
        "grep -E 'minlen|minclass|dcredit|ucredit|ocredit|lcredit' /etc/security/pwquality.conf 2>/dev/null",
        lambda o: "minlen" in o,
        "Configure /etc/security/pwquality.conf: minlen=14, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1"
    ),
    (
        "5.4.1", "Ensure password expiration is 365 days or less", "medium",
        "grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null",
        lambda o: bool(re.search(r"PASS_MAX_DAYS\s+(\d+)", o)) and int(re.search(r"PASS_MAX_DAYS\s+(\d+)", o).group(1)) <= 365 if re.search(r"PASS_MAX_DAYS\s+(\d+)", o) else False,
        "Set PASS_MAX_DAYS 365 in /etc/login.defs"
    ),
    (
        "5.4.2", "Ensure minimum days between password changes is 1 or more", "low",
        "grep -E '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null",
        lambda o: bool(re.search(r"PASS_MIN_DAYS\s+([1-9])", o)),
        "Set PASS_MIN_DAYS 1 in /etc/login.defs"
    ),
    (
        "5.4.4", "Ensure default umask is 027 or more restrictive", "medium",
        "grep -E '^UMASK' /etc/login.defs 2>/dev/null",
        lambda o: "027" in o or "077" in o,
        "Set UMASK 027 in /etc/login.defs and /etc/profile"
    ),
    # === Logging ===
    (
        "4.1.1", "Ensure auditd is installed and running", "high",
        "systemctl is-active auditd 2>/dev/null",
        lambda o: "active" in o,
        "Install and enable auditd: apt-get install auditd && systemctl enable auditd && systemctl start auditd"
    ),
    (
        "4.2.1", "Ensure rsyslog is installed and running", "medium",
        "systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null",
        lambda o: "active" in o,
        "Install rsyslog: apt-get install rsyslog && systemctl enable rsyslog"
    ),
    (
        "4.2.3", "Ensure rsyslog or syslog-ng log file permissions are configured", "medium",
        "stat -c '%a' /var/log/syslog 2>/dev/null || stat -c '%a' /var/log/messages 2>/dev/null",
        lambda o: o.strip() in ("600", "640", "660"),
        "Set log file permissions: chmod 640 /var/log/syslog"
    ),
    # === Cron ===
    (
        "5.1.1", "Ensure cron daemon is enabled", "low",
        "systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null",
        lambda o: "active" in o,
        "Enable cron: systemctl enable cron && systemctl start cron"
    ),
    (
        "5.1.8", "Ensure at/cron is restricted to authorized users", "medium",
        "ls /etc/cron.allow /etc/at.allow 2>/dev/null",
        lambda o: "cron.allow" in o,
        "Create /etc/cron.allow and /etc/at.allow with authorized users only"
    ),
    # === Firewall ===
    (
        "3.5.1", "Ensure firewall is active (ufw/iptables/firewalld)", "high",
        "ufw status 2>/dev/null | grep -i active || iptables -L INPUT 2>/dev/null | grep -c 'Chain INPUT' || firewall-cmd --state 2>/dev/null",
        lambda o: "active" in o.lower() or o.strip().isdigit(),
        "Enable firewall: ufw enable or systemctl enable --now firewalld"
    ),
]


@celery_app.task(bind=True, name="worker.tasks.cis_audit_task.run_cis_audit", max_retries=0)
def run_cis_audit(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    """
    CIS Benchmark compliance audit via SSH.
    Options:
      - username: SSH username
      - ssh_key_path: path to private key (preferred)
      - password: SSH password (alternative)
      - checks: list of check IDs to run (default: all)
      - benchmark: 'ubuntu22' | 'rhel8' | 'generic' (default: generic)
    """
    username = options.get("username", "root")
    ssh_key = options.get("ssh_key_path")
    password = options.get("password")
    check_filter = options.get("checks")  # optional list of check IDs

    if not ssh_key and not password:
        update_scan_status(scan_id, "failed", "Either ssh_key_path or password required for CIS audit")
        return

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[cis-audit] Connecting to {target} as {username}")

    # Test connectivity
    whoami = _ssh_run(target, username, ssh_key, password, "whoami", timeout=12)
    if not whoami:
        update_scan_status(scan_id, "failed", f"SSH connection failed to {target}")
        return

    publish_output(scan_id, f"[cis-audit] Connected. Running {len(CIS_CHECKS)} CIS benchmark checks...")

    findings = []
    raw_lines = [f"CIS Benchmark Audit: {target}", f"Running as: {whoami}", "=" * 60]
    passed = 0
    failed = 0

    for check_id, title, severity, cmd, pass_condition, remediation in CIS_CHECKS:
        if check_filter and check_id not in check_filter:
            continue

        output = _ssh_run(target, username, ssh_key, password, cmd, timeout=15)

        try:
            is_pass = pass_condition(output)
        except Exception:
            is_pass = False

        status_str = "PASS" if is_pass else "FAIL"
        raw_lines.append(f"[{status_str}] CIS {check_id}: {title}")
        if not is_pass:
            raw_lines.append(f"         Output: {output[:100]}")

        if is_pass:
            passed += 1
            publish_output(scan_id, f"[cis-audit] PASS: {check_id} {title}")
        else:
            failed += 1
            publish_output(scan_id, f"[cis-audit] FAIL: {check_id} {title}")
            findings.append({
                "title": f"CIS {check_id}: {title}",
                "description": (
                    f"CIS Benchmark check {check_id} failed on {target}.\n"
                    f"Check: {title}\n"
                    f"Current value/output: {output[:300] or '(no output)'}"
                ),
                "severity": severity,
                "affected_component": target,
                "affected_service": "configuration",
                "remediation": remediation,
                "references": [f"https://www.cisecurity.org/cis-benchmarks/"],
            })

    compliance_pct = round(passed / max(passed + failed, 1) * 100, 1)
    summary = f"CIS Audit complete: {passed} PASS, {failed} FAIL ({compliance_pct}% compliant)"
    raw_lines.append("=" * 60)
    raw_lines.append(summary)

    publish_output(scan_id, f"[cis-audit] {summary}")

    # Add a summary finding if compliance is low
    if compliance_pct < 50:
        findings.insert(0, {
            "title": f"Low CIS Benchmark compliance: {compliance_pct}%",
            "description": f"Host {target} is only {compliance_pct}% compliant with CIS Benchmarks ({passed}/{passed + failed} checks passed). Immediate hardening is required.",
            "severity": "high",
            "affected_component": target,
            "affected_service": "configuration",
            "remediation": "Review and remediate all FAIL checks. Consider running CIS-CAT Pro for automated remediation.",
        })

    update_scan_raw_output(scan_id, "\n".join(raw_lines))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[cis-audit] {count} findings saved.")
    update_scan_status(scan_id, "completed")
