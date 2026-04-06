"""
Container Image Security Scanning
- Uses Trivy (primary) with Grype as fallback
- Scans Docker images for OS package CVEs, language library CVEs, misconfigs
- Also supports scanning running containers and Dockerfiles
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

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NEGLIGIBLE": "info",
    "UNKNOWN": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
}


def _trivy_scan(image: str, scan_type: str, scan_id: str) -> tuple:
    """Run trivy image scan, return (findings_list, raw_output)."""
    publish_output(scan_id, f"[container] Running Trivy {scan_type} scan on {image}...")
    cmd = [
        "trivy", scan_type, "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--no-progress", "--quiet",
        image
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw = result.stdout
        if not raw.strip():
            return [], result.stderr[:500]

        data = json.loads(raw)
        findings = []

        results = data.get("Results", [])
        for result_block in results:
            target_name = result_block.get("Target", image)
            vulns = result_block.get("Vulnerabilities") or []
            misconfigs = result_block.get("Misconfigurations") or []

            for v in vulns:
                sev = SEVERITY_MAP.get(v.get("Severity", ""), "info")
                cve = v.get("VulnerabilityID", "")
                pkg = v.get("PkgName", "")
                installed = v.get("InstalledVersion", "")
                fixed = v.get("FixedVersion", "")
                title = v.get("Title") or f"{cve} in {pkg}"
                desc = v.get("Description") or f"Vulnerability {cve} detected in {pkg} {installed}"
                refs = [r for r in v.get("References", []) if "nvd.nist.gov" in r or "cve.mitre.org" in r][:3]
                cvss = None
                for cvss_data in (v.get("CVSS") or {}).values():
                    if isinstance(cvss_data, dict):
                        cvss = cvss_data.get("V3Score") or cvss_data.get("V2Score")
                        if cvss:
                            break

                findings.append({
                    "title": f"Container vuln: {title}",
                    "description": desc,
                    "severity": sev,
                    "cve_id": cve if cve.startswith("CVE-") else None,
                    "cvss_score": cvss,
                    "affected_component": f"{pkg} {installed} in {target_name}",
                    "affected_service": "container",
                    "remediation": f"Upgrade {pkg} to {fixed}" if fixed else "Update base image and rebuild container",
                    "exploit_available": sev == "critical",
                    "references": refs,
                })

            for mc in misconfigs:
                sev = SEVERITY_MAP.get(mc.get("Severity", ""), "medium")
                findings.append({
                    "title": f"Container misconfiguration: {mc.get('Title', 'Unknown')}",
                    "description": mc.get("Description", "") + "\n" + mc.get("Message", ""),
                    "severity": sev,
                    "affected_component": target_name,
                    "affected_service": "container",
                    "remediation": mc.get("Resolution", "Follow container security best practices"),
                    "references": [mc.get("PrimaryURL", "")] if mc.get("PrimaryURL") else [],
                })

        return findings, raw[:3000]
    except FileNotFoundError:
        return None, "trivy not installed"
    except json.JSONDecodeError:
        return [], result.stdout[:500]
    except subprocess.TimeoutExpired:
        return [], "trivy timed out (300s)"


def _grype_scan(image: str, scan_id: str) -> tuple:
    """Fallback: run grype scan, return (findings_list, raw_output)."""
    publish_output(scan_id, f"[container] Running Grype scan on {image} (fallback)...")
    try:
        result = subprocess.run(
            ["grype", image, "-o", "json", "--quiet"],
            capture_output=True, text=True, timeout=180
        )
        if not result.stdout.strip():
            return [], result.stderr[:300]

        data = json.loads(result.stdout)
        findings = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            sev = SEVERITY_MAP.get(vuln.get("severity", ""), "info")
            cve = vuln.get("id", "")
            pkg = artifact.get("name", "")
            installed = artifact.get("version", "")
            fixed_versions = vuln.get("fix", {}).get("versions", [])
            fixed = ", ".join(fixed_versions) if fixed_versions else ""

            findings.append({
                "title": f"Container vuln: {cve} in {pkg}",
                "description": vuln.get("description") or f"{cve} detected in {pkg} {installed}",
                "severity": sev,
                "cve_id": cve if cve.startswith("CVE-") else None,
                "cvss_score": vuln.get("cvss", [{}])[0].get("metrics", {}).get("baseScore") if vuln.get("cvss") else None,
                "affected_component": f"{pkg} {installed}",
                "affected_service": "container",
                "remediation": f"Upgrade {pkg} to {fixed}" if fixed else "Update base image",
                "references": vuln.get("urls", [])[:3],
            })
        return findings, result.stdout[:2000]
    except FileNotFoundError:
        return None, "grype not installed"
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return [], ""


def _scan_dockerfile(path: str, scan_id: str) -> list:
    """Scan a Dockerfile for security misconfigurations."""
    findings = []
    publish_output(scan_id, f"[container] Scanning Dockerfile: {path}")
    try:
        result = subprocess.run(
            ["trivy", "config", "--format", "json", "--quiet", path],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            for block in data.get("Results", []):
                for mc in block.get("Misconfigurations", []):
                    sev = SEVERITY_MAP.get(mc.get("Severity", ""), "medium")
                    findings.append({
                        "title": f"Dockerfile issue: {mc.get('Title', 'Unknown')}",
                        "description": mc.get("Description", ""),
                        "severity": sev,
                        "affected_component": path,
                        "affected_service": "dockerfile",
                        "remediation": mc.get("Resolution", "Follow Dockerfile best practices"),
                    })
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass
    return findings


@celery_app.task(bind=True, name="worker.tasks.container_scan_task.run_container_scan", max_retries=0)
def run_container_scan(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    """
    Scan a container image or Dockerfile for vulnerabilities.
    Options:
      - image: Docker image name (e.g. 'nginx:1.21', 'ubuntu:22.04')
      - scan_type: 'image' | 'fs' | 'repo' | 'dockerfile' (default: image)
      - dockerfile_path: path to Dockerfile (when scan_type=dockerfile)
      - include_dev_deps: include dev dependencies (default: False)
    """
    image = options.get("image", target)
    scan_type = options.get("scan_type", "image")
    dockerfile_path = options.get("dockerfile_path")

    if not image and scan_type != "dockerfile":
        update_scan_status(scan_id, "failed", "image name is required (e.g. nginx:latest)")
        return

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[container] Starting container scan: {image} (type: {scan_type})")

    findings = []
    raw_output = ""

    if scan_type == "dockerfile" and dockerfile_path:
        findings = _scan_dockerfile(dockerfile_path, scan_id)
        raw_output = f"Dockerfile scan: {dockerfile_path}"
    else:
        # Try Trivy first
        trivy_findings, raw_output = _trivy_scan(image, scan_type, scan_id)
        if trivy_findings is not None:
            findings = trivy_findings
            publish_output(scan_id, f"[container] Trivy found {len(findings)} issues")
        else:
            # Fallback to Grype
            grype_findings, raw_output = _grype_scan(image, scan_id)
            if grype_findings is not None:
                findings = grype_findings
                publish_output(scan_id, f"[container] Grype found {len(findings)} issues")
            else:
                update_scan_status(scan_id, "failed", "Neither trivy nor grype is installed")
                return

    # Summary by severity
    counts = {}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    publish_output(scan_id, f"[container] Summary: " + ", ".join(f"{k}:{v}" for k, v in counts.items()))

    update_scan_raw_output(scan_id, raw_output)
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[container] Scan complete. {count} findings saved.")
    update_scan_status(scan_id, "completed")
