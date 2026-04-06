import subprocess
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
from core.config import settings

# Hashcat attack modes
ATTACK_DICT = 0
ATTACK_BRUTE = 3

# Regex patterns for hashcat status output
STATUS_RE = re.compile(r"^Status\s*\.\.\.\.\.\.\.\.\.\.\s*(.+)$", re.MULTILINE)
SPEED_RE = re.compile(r"^Speed\.#\d+\s*\.\.\.\.\.\s*(.+)$", re.MULTILINE)
PROGRESS_RE = re.compile(r"^Progress\s*\.\.\.\.\.\.\.\.\s*(.+)$", re.MULTILINE)
ETA_RE = re.compile(r"^ETA\s*\.\.\.\.\.\.\.\.\.\.\.\.\s*(.+)$", re.MULTILINE)
CRACKED_RE = re.compile(r"^Recovered\s*\.\.\.\.\.\.\.\s*(\d+)/(\d+).+$", re.MULTILINE)

# Match a cracked line: hash:password  or  hash (password)
CRACKED_LINE_RE = re.compile(r"^(.+):(.+)$")

# Known hashcat mode mappings for common hash types
HASHCAT_MODES = {
    "MD5": 0,
    "MD4": 900,
    "NTLM": 1000,
    "SHA-1": 100,
    "SHA1": 100,
    "SHA-256": 1400,
    "SHA-512": 1700,
    "bcrypt": 3200,
    "WPA-PBKDF2-PMKID": 22000,
    "MySQL4.1/MySQL5+": 300,
    "MySQL323": 200,
    "LM": 3000,
    "SHA-512 Crypt": 1800,
    "MD5 Crypt": 500,
    "Blowfish(OpenBSD)": 3200,
    "Django (PBKDF2-SHA256)": 10000,
}


def _identify_hash_type(hash_value: str) -> tuple:
    """
    Run hashid to identify the hash type.
    Returns (type_name, hashcat_mode) or ("Unknown", None).
    """
    try:
        result = subprocess.run(
            ["hashid", "-e", "-m", hash_value],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                # Try to extract hashcat mode
                mode_match = re.search(r"\[Hashcat Mode:\s*(\d+)\]", line)
                type_match = re.search(r"\[\+\]\s+(.+?)(?:\s+\[|$)", line)
                hash_type = type_match.group(1).strip() if type_match else "Unknown"
                hc_mode = int(mode_match.group(1)) if mode_match else None
                return hash_type, hc_mode
    except Exception:
        pass
    return "Unknown", None


@celery_app.task(
    bind=True,
    name="worker.tasks.hashcat_task.run_hashcat",
    max_retries=0,  # never retry cracking tasks
)
def run_hashcat(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    # ---- HARD AUTHORIZATION GATE ----
    if options.get("authorized") is not True:
        raise ValueError(
            "Hashcat task requires explicit authorization. "
            "Set options['authorized'] = True to confirm you have written permission to test these hashes."
        )

    update_scan_status(scan_id, "running")

    hash_input = options.get("hash_input", target)
    manual_hash_type = options.get("hash_type")
    attack_mode = options.get("attack_mode", ATTACK_DICT)
    wordlist = options.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    rules = options.get("rules")

    hashes = [h.strip() for h in hash_input.splitlines() if h.strip()]
    if not hashes:
        update_scan_status(scan_id, "failed", "No hash input provided")
        return

    # Auto-detect hash type if not manually specified
    if manual_hash_type is not None:
        hc_mode = int(manual_hash_type)
        detected_type = f"Manual ({hc_mode})"
    else:
        publish_output(scan_id, "[hashcat] Running hashid to auto-detect hash type...")
        detected_type, hc_mode = _identify_hash_type(hashes[0])
        if hc_mode is None:
            # Try our known map
            hc_mode = HASHCAT_MODES.get(detected_type)
        publish_output(scan_id, f"[hashcat] Detected: {detected_type} (hashcat mode: {hc_mode})")

    if hc_mode is None:
        update_scan_status(scan_id, "failed", f"Cannot determine hashcat mode for hash type: {detected_type}")
        return

    # Write hashes to a temp file
    hash_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"{scan_id}_hashes.txt")
    os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)

    with open(hash_file, "w") as f:
        for h in hashes:
            f.write(h + "\n")

    cmd = [
        "hashcat",
        "-m", str(hc_mode),
        "-a", str(attack_mode),
        hash_file,
        wordlist,
        "--status",
        "--status-timer=5",
        "--runtime=60",
        "--potfile-disable",  # don't cache results to potfile for isolated run
        "--quiet",
    ]

    if rules:
        cmd.extend(["-r", rules])

    publish_output(scan_id, f"[hashcat] Starting: {' '.join(cmd)}")

    raw_lines = []
    findings = []
    cracked_hashes = []

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        buffer = []
        for line in process.stdout:
            line = line.rstrip()
            raw_lines.append(line)

            # Detect status block separator
            if line.strip() == "" and buffer:
                block = "\n".join(buffer)

                # Extract status fields
                status_match = STATUS_RE.search(block)
                speed_match = SPEED_RE.search(block)
                progress_match = PROGRESS_RE.search(block)
                eta_match = ETA_RE.search(block)
                cracked_match = CRACKED_RE.search(block)

                status_str = status_match.group(1) if status_match else "Unknown"
                speed_str = speed_match.group(1) if speed_match else "?"
                progress_str = progress_match.group(1) if progress_match else "?"
                eta_str = eta_match.group(1) if eta_match else "?"
                recovered = cracked_match.group(1) if cracked_match else "0"
                total = cracked_match.group(2) if cracked_match else str(len(hashes))

                publish_output(
                    scan_id,
                    f"[hashcat] Status={status_str} Speed={speed_str} "
                    f"Progress={progress_str} ETA={eta_str} Cracked={recovered}/{total}"
                )
                buffer = []
            else:
                buffer.append(line)

                # Check for cracked hash output (hash:password format)
                crack_match = CRACKED_LINE_RE.match(line.strip())
                if crack_match and ":" in line and "Status" not in line:
                    cracked_hash = crack_match.group(1).strip()
                    cracked_pass = crack_match.group(2).strip()
                    # Basic sanity: looks like an actual result
                    if len(cracked_hash) >= 8 and cracked_hash in hash_input:
                        cracked_hashes.append((cracked_hash, cracked_pass))
                        publish_output(scan_id, f"[hashcat] CRACKED: {cracked_hash[:20]}... = {cracked_pass}")

        # Process remaining buffer
        if buffer:
            block = "\n".join(buffer)
            # Re-scan for cracked entries in final block
            for bline in buffer:
                crack_match = CRACKED_LINE_RE.match(bline.strip())
                if crack_match and ":" in bline and "Status" not in bline:
                    cracked_hash = crack_match.group(1).strip()
                    cracked_pass = crack_match.group(2).strip()
                    if len(cracked_hash) >= 8 and cracked_hash in hash_input:
                        if (cracked_hash, cracked_pass) not in cracked_hashes:
                            cracked_hashes.append((cracked_hash, cracked_pass))

        process.wait()

    except FileNotFoundError:
        update_scan_status(scan_id, "failed", "hashcat binary not found")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return
    finally:
        # Clean up hash file
        try:
            os.unlink(hash_file)
        except OSError:
            pass

    raw_output = "\n".join(raw_lines)
    update_scan_raw_output(scan_id, raw_output)

    # Create findings for cracked hashes
    for cracked_hash, cracked_pass in cracked_hashes:
        findings.append({
            "title": f"Hash cracked ({detected_type}): {cracked_hash[:32]}{'...' if len(cracked_hash) > 32 else ''}",
            "description": (
                f"hashcat successfully cracked a {detected_type} hash.\n\n"
                f"Hash: {cracked_hash}\n"
                f"Plaintext: {cracked_pass}\n"
                f"Hash mode: {hc_mode}\n"
                f"Attack mode: {'Dictionary' if attack_mode == ATTACK_DICT else 'Brute-force'}\n\n"
                f"This plaintext password should be considered compromised."
            ),
            "severity": "high",
            "affected_component": target,
            "raw_output": f"{cracked_hash}:{cracked_pass}",
            "remediation": (
                "Immediately invalidate and reset this credential. "
                "Migrate to a strong, salted hashing algorithm (bcrypt, Argon2, scrypt). "
                "Enforce minimum password complexity policies."
            ),
        })

    # Summary finding if nothing cracked
    if not cracked_hashes:
        findings.append({
            "title": f"Hash cracking attempt: no passwords recovered ({detected_type})",
            "description": (
                f"hashcat ran against {len(hashes)} hash(es) of type {detected_type} "
                f"using {'dictionary' if attack_mode == ATTACK_DICT else 'brute-force'} attack. "
                f"No passwords were recovered within the 60-second runtime limit."
            ),
            "severity": "info",
            "affected_component": target,
            "raw_output": raw_output[-2000:] if raw_output else "",
            "remediation": "Hashes withstood short cracking attempt. Ensure strong algorithms and salting are used.",
        })

    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(
        scan_id,
        f"[hashcat] Complete. {len(cracked_hashes)} hash(es) cracked. {count} findings saved."
    )
    update_scan_status(scan_id, "completed")
