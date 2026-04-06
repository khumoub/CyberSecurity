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

# Regex to parse hashid output lines:
# [+] MD5
# [+] MD4
# or with extended/modes:
# [+] MD5 [Hashcat Mode: 0]
HASHID_LINE_RE = re.compile(r"\[.\]\s+(.+?)(?:\s+\[Hashcat Mode:\s*(\d+)\])?$")

# Known dangerous hash types (weak/broken algorithms)
WEAK_HASH_TYPES = {
    "MD5", "MD4", "LM", "NTLM", "SHA-1", "SHA1", "MySQL323",
    "MySQL41", "DES", "CRC32", "Adler-32",
}


def _run_hashid(hash_value: str) -> list:
    """
    Run hashid -e -m on a single hash value.
    Returns a list of (hash_type, hashcat_mode_or_None) tuples.
    """
    try:
        result = subprocess.run(
            ["hashid", "-e", "-m", hash_value],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        identified = []
        for line in output.splitlines():
            match = HASHID_LINE_RE.search(line.strip())
            if match:
                hash_type = match.group(1).strip()
                hc_mode = match.group(2)
                identified.append((hash_type, hc_mode))
        return identified
    except FileNotFoundError:
        raise RuntimeError("hashid binary not found")
    except subprocess.TimeoutExpired:
        return []


@celery_app.task(
    bind=True,
    name="worker.tasks.hashid_task.run_hashid",
    max_retries=2,
)
def run_hashid(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    update_scan_status(scan_id, "running")

    hash_input = options.get("hash_input", target)

    # Support batch: newline-separated hashes
    hashes = [h.strip() for h in hash_input.splitlines() if h.strip()]

    if not hashes:
        update_scan_status(scan_id, "failed", "No hash input provided")
        return

    publish_output(scan_id, f"[hashid] Identifying {len(hashes)} hash(es)...")

    findings = []
    raw_log = []

    for hash_value in hashes:
        publish_output(scan_id, f"[hashid] Processing: {hash_value[:64]}{'...' if len(hash_value) > 64 else ''}")

        try:
            identified = _run_hashid(hash_value)
        except RuntimeError as e:
            update_scan_status(scan_id, "failed", str(e))
            return

        if not identified:
            raw_log.append(f"Hash: {hash_value} → No match found")
            findings.append({
                "title": f"Hash not identified: {hash_value[:32]}...",
                "description": (
                    f"hashid could not identify the hash type for:\n{hash_value}\n\n"
                    "This may be a custom, obfuscated, or unsupported hash format."
                ),
                "severity": "info",
                "affected_component": target,
                "raw_output": f"hashid: no match for {hash_value}",
                "remediation": "Manual analysis may be required to determine the hash algorithm.",
            })
            continue

        # The most likely type is the first match
        top_type, top_mode = identified[0]
        all_types = ", ".join(t for t, _ in identified[:10])

        is_weak = any(t in WEAK_HASH_TYPES for t, _ in identified[:3])
        severity = "medium" if is_weak else "info"

        hashcat_info = f"\nHashcat mode: {top_mode}" if top_mode else ""
        weak_note = (
            "\n\nWARNING: This appears to be a weak/broken hash algorithm. "
            "Passwords hashed with this algorithm are at high risk of cracking."
        ) if is_weak else ""

        description = (
            f"Hash: {hash_value}\n\n"
            f"Most likely type: {top_type}{hashcat_info}\n"
            f"All possible types: {all_types}"
            f"{weak_note}"
        )

        raw_log.append(f"Hash: {hash_value} → {all_types}")

        title_hash = hash_value[:20] + ("..." if len(hash_value) > 20 else "")
        findings.append({
            "title": f"Hash identified as {top_type}: {title_hash}",
            "description": description,
            "severity": severity,
            "affected_component": target,
            "raw_output": f"hashid -e -m {hash_value}",
            "remediation": (
                "Ensure passwords are hashed using modern algorithms (bcrypt, Argon2, scrypt) "
                "with appropriate work factors. Avoid MD5, SHA-1, and other weak algorithms."
                if is_weak else
                "Review hash usage and ensure appropriate algorithm selection for the use case."
            ),
        })

        publish_output(scan_id, f"[hashid] {hash_value[:32]}... → {top_type} (and {len(identified) - 1} others)")

    update_scan_raw_output(scan_id, "\n".join(raw_log))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[hashid] Complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
