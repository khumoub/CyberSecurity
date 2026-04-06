"""
Claude AI integration for:
1. AI-powered vulnerability questionnaires (TPRM Module 6)
2. AI-ranked patch priority with contextual remediation advice (Module 5)
"""
from core.config import settings


async def generate_vendor_questionnaire(vendor_name: str, findings: list[dict]) -> list[dict]:
    """
    Generate a security questionnaire for a vendor based on their scan findings.
    Returns a list of question objects with category and guidance.
    """
    if not settings.CLAUDE_API_KEY:
        return _fallback_questionnaire(vendor_name, findings)

    import anthropic
    client = anthropic.AsyncAnthropic(api_key=settings.CLAUDE_API_KEY)

    findings_summary = "\n".join(
        f"- [{f.get('severity','?').upper()}] {f.get('title','?')} "
        f"(CVE: {f.get('cve_id') or 'N/A'}, Component: {f.get('affected_component') or 'N/A'})"
        for f in findings[:20]
    )

    prompt = f"""You are a cybersecurity assessor creating a vendor security questionnaire for {vendor_name}.

Based on these findings from their technical scan:
{findings_summary}

Generate 12 targeted security questionnaire questions. For each question provide:
1. The question text (specific to the findings where relevant)
2. Category (Access Control / Patch Management / Encryption / Incident Response / Data Protection / Network Security / Backup & Recovery / Vendor Management)
3. Why it matters (1 sentence)
4. Expected good answer (brief)

Format as JSON array:
[
  {{
    "question": "...",
    "category": "...",
    "rationale": "...",
    "expected_answer": "..."
  }}
]

Return ONLY the JSON array, no other text."""

    message = await client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )
    import json
    text = message.content[0].text.strip()
    # Extract JSON array
    start = text.find("[")
    end = text.rfind("]") + 1
    if start >= 0 and end > start:
        return json.loads(text[start:end])
    return _fallback_questionnaire(vendor_name, findings)


def _fallback_questionnaire(vendor_name: str, findings: list[dict]) -> list[dict]:
    """Default questionnaire when Claude API is not configured."""
    has_ssl = any("ssl" in f.get("title", "").lower() or "tls" in f.get("title", "").lower() for f in findings)
    has_cve = any(f.get("cve_id") for f in findings)
    has_auth = any("auth" in f.get("title", "").lower() or "password" in f.get("title", "").lower() for f in findings)

    questions = [
        {"question": "What is your patch management cycle for critical vulnerabilities?", "category": "Patch Management", "rationale": "Critical patches should be applied within 7 days.", "expected_answer": "Critical patches applied within 7 days, high within 30 days."},
        {"question": "Describe your vulnerability scanning programme and frequency.", "category": "Patch Management", "rationale": "Regular scanning is foundational to security posture.", "expected_answer": "Weekly automated scans with monthly manual assessments."},
        {"question": "How do you manage third-party software dependencies and SBOMs?", "category": "Patch Management", "rationale": "Supply chain attacks target outdated dependencies.", "expected_answer": "SBOM maintained, automated dependency scanning in CI/CD."},
        {"question": "What MFA mechanisms are enforced for all user and admin access?", "category": "Access Control", "rationale": "MFA prevents credential-based attacks.", "expected_answer": "TOTP or hardware tokens enforced for all accounts."},
        {"question": "How do you implement the principle of least privilege?", "category": "Access Control", "rationale": "Excess permissions increase blast radius of breaches.", "expected_answer": "Role-based access control with quarterly access reviews."},
        {"question": "Describe your incident response plan and RTO/RPO targets.", "category": "Incident Response", "rationale": "Preparedness reduces breach impact.", "expected_answer": "Documented IRP, tested annually, RTO <4h for critical systems."},
        {"question": "How is data encrypted at rest and in transit?", "category": "Encryption", "rationale": "Encryption protects data confidentiality.", "expected_answer": "AES-256 at rest, TLS 1.2+ in transit, no weak ciphers."},
        {"question": "What is your backup strategy and how often are restores tested?", "category": "Backup & Recovery", "rationale": "Untested backups fail when needed most.", "expected_answer": "Daily encrypted backups, quarterly restore tests, offsite copies."},
        {"question": "How do you handle data subject requests under applicable privacy law?", "category": "Data Protection", "rationale": "Regulatory compliance is a shared responsibility.", "expected_answer": "Documented process, responses within 30 days, DPO appointed."},
        {"question": "Describe your network segmentation strategy.", "category": "Network Security", "rationale": "Segmentation limits lateral movement.", "expected_answer": "Production, dev, and admin networks isolated with firewall rules."},
        {"question": "How do you manage security of your own third-party vendors?", "category": "Vendor Management", "rationale": "Supply chain risk extends to sub-vendors.", "expected_answer": "Annual vendor assessments, contractual security requirements."},
        {"question": "What security training cadence do you maintain for all staff?", "category": "Access Control", "rationale": "Human error is the leading cause of breaches.", "expected_answer": "Annual training plus phishing simulations quarterly."},
    ]

    if has_ssl:
        questions.insert(2, {"question": "What is your process for managing TLS certificate expiry and cipher suites?", "category": "Encryption", "rationale": "Expired or weak TLS exposes data in transit.", "expected_answer": "Automated cert renewal, TLS 1.3 preferred, weak ciphers disabled."})
    if has_cve:
        questions.insert(2, {"question": f"Several CVEs were identified in your internet-facing systems. What is your remediation timeline for these specific findings?", "category": "Patch Management", "rationale": "Identified CVEs represent confirmed risk.", "expected_answer": "Critical CVEs patched within 7 days, all findings tracked in vulnerability management system."})

    return questions[:12]


async def get_ai_patch_priority(findings: list[dict]) -> list[dict]:
    """
    Use Claude to rank findings by patch priority with contextual remediation advice.
    Returns findings list with 'ai_rank' and 'ai_recommendation' fields added.
    """
    if not settings.CLAUDE_API_KEY or not findings:
        # Add basic ranking without AI
        for i, f in enumerate(findings):
            f["ai_recommendation"] = f.get("remediation") or f"Remediate {f.get('title','this finding')} as soon as possible."
        return findings

    import anthropic, json
    client = anthropic.AsyncAnthropic(api_key=settings.CLAUDE_API_KEY)

    findings_list = "\n".join(
        f"{i+1}. [{f.get('severity','?').upper()}] {f.get('title','?')} | "
        f"CVE: {f.get('cve_id') or 'N/A'} | CVSS: {f.get('cvss_score') or 'N/A'} | "
        f"KEV: {'YES' if f.get('is_known_exploited') else 'no'} | "
        f"Exploit: {'YES' if f.get('exploit_available') else 'no'} | "
        f"Asset: {f.get('asset_value','?')}"
        for i, f in enumerate(findings[:25])
    )

    prompt = f"""You are a senior cybersecurity consultant. Rank these {len(findings[:25])} vulnerabilities by patch priority and provide a one-sentence remediation recommendation for each.

Findings:
{findings_list}

Consider: CISA KEV status (most critical), exploit availability, CVSS score, severity, and business impact.

Return a JSON array with objects {{\"original_rank\": 1-N, \"priority_rank\": 1-N, \"recommendation\": \"...\"}}.
Return ONLY the JSON array."""

    try:
        message = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            ai_data = json.loads(text[start:end])
            rank_map = {item["original_rank"]: item for item in ai_data}
            for i, f in enumerate(findings):
                item = rank_map.get(i + 1, {})
                f["ai_rank"] = item.get("priority_rank", i + 1)
                f["ai_recommendation"] = item.get("recommendation", f.get("remediation", ""))
            findings.sort(key=lambda x: x.get("ai_rank", 999))
    except Exception:
        for i, f in enumerate(findings):
            f["ai_recommendation"] = f.get("remediation") or f"Remediate this {f.get('severity','?')} finding promptly."

    return findings
