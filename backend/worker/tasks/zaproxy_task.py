import time
import requests
from typing import Optional
from worker.celery_app import celery_app
from worker.tasks.base import (
    publish_output,
    update_scan_status,
    update_scan_raw_output,
    save_findings_to_db,
    update_asset_last_scanned,
)

ZAP_BASE_URL = "http://zap:8080"
ZAP_API_KEY = "leruo-zap-key"  # set via ZAP startup -config api.key=...

# Map ZAP risk strings to internal severity levels
RISK_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "Info": "info",
    "Informational ": "info",
}

POLL_INTERVAL = 5  # seconds between status polls
MAX_POLL_SECONDS = 1800  # 30 minutes max


def _zap_get(path: str, params: Optional[dict] = None) -> dict:
    params = params or {}
    params["apikey"] = ZAP_API_KEY
    resp = requests.get(f"{ZAP_BASE_URL}{path}", params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _zap_post(path: str, data: Optional[dict] = None) -> dict:
    data = data or {}
    data["apikey"] = ZAP_API_KEY
    resp = requests.post(f"{ZAP_BASE_URL}{path}", data=data, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _poll_until_complete(
    scan_id: str,
    status_path: str,
    status_params: dict,
    status_key: str,
    label: str,
    publish_prefix: str,
) -> bool:
    """Poll a ZAP status endpoint until progress == 100 or timeout. Returns True on success."""
    elapsed = 0
    while elapsed < MAX_POLL_SECONDS:
        try:
            result = _zap_get(status_path, dict(status_params))
            progress = int(result.get(status_key, 0))
            publish_output(scan_id, f"[zaproxy] {label} progress: {progress}%")
            if progress >= 100:
                return True
        except Exception as e:
            publish_output(scan_id, f"[zaproxy] Poll error: {e}")

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    publish_output(scan_id, f"[zaproxy] {label} timed out after {elapsed}s")
    return False


@celery_app.task(bind=True, name="worker.tasks.zaproxy_task.run_zaproxy", max_retries=1)
def run_zaproxy(
    self,
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    target: str,
    options: dict,
):
    update_scan_status(scan_id, "running")

    target_url = options.get("target_url", target)
    scan_type = options.get("scan_type", "passive")
    spider_depth = options.get("spider_depth", 3)

    raw_log = []

    try:
        # ----- Spider Phase -----
        publish_output(scan_id, f"[zaproxy] Starting spider on {target_url} (depth={spider_depth})")
        raw_log.append(f"Spider target: {target_url}")

        spider_resp = _zap_post(
            "/JSON/spider/action/scan/",
            {"url": target_url, "maxDepth": str(spider_depth), "recurse": "true"},
        )
        spider_scan_id = spider_resp.get("scan", "0")
        publish_output(scan_id, f"[zaproxy] Spider scan ID: {spider_scan_id}")

        ok = _poll_until_complete(
            scan_id,
            "/JSON/spider/view/status/",
            {"scanId": spider_scan_id},
            "status",
            "Spider",
            "[zaproxy]",
        )
        if not ok:
            publish_output(scan_id, "[zaproxy] Spider did not complete in time, continuing anyway.")

        publish_output(scan_id, "[zaproxy] Spider complete.")

        # ----- Active Scan Phase (if requested) -----
        if scan_type == "active":
            publish_output(scan_id, f"[zaproxy] Starting active scan on {target_url}")
            ascan_resp = _zap_post(
                "/JSON/ascan/action/scan/",
                {"url": target_url, "recurse": "true", "inScopeOnly": "false"},
            )
            ascan_id = ascan_resp.get("scan", "0")
            publish_output(scan_id, f"[zaproxy] Active scan ID: {ascan_id}")

            ok = _poll_until_complete(
                scan_id,
                "/JSON/ascan/view/status/",
                {"scanId": ascan_id},
                "status",
                "Active scan",
                "[zaproxy]",
            )
            if not ok:
                publish_output(scan_id, "[zaproxy] Active scan timed out, collecting partial results.")

            publish_output(scan_id, "[zaproxy] Active scan complete.")

        # ----- Collect Alerts -----
        publish_output(scan_id, "[zaproxy] Fetching alerts...")
        alerts_resp = _zap_get("/JSON/alert/view/alerts/", {"baseurl": target_url, "start": "0", "count": "5000"})
        alerts = alerts_resp.get("alerts", [])
        publish_output(scan_id, f"[zaproxy] {len(alerts)} alerts retrieved.")

    except requests.ConnectionError:
        update_scan_status(scan_id, "failed", "Cannot connect to ZAP at http://zap:8080")
        return
    except Exception as e:
        update_scan_status(scan_id, "failed", str(e))
        return

    # ----- Map Alerts to Findings -----
    findings = []
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        severity = RISK_MAP.get(risk, "info")

        name = alert.get("name", "Unknown Alert")
        description = alert.get("description", "")
        solution = alert.get("solution", "")
        evidence = alert.get("evidence", "")
        url_affected = alert.get("url", target_url)
        cwe_id = alert.get("cweid", "")
        plugin_id = alert.get("pluginId", "")
        other_info = alert.get("otherinfo", "")
        refs = [r.strip() for r in alert.get("reference", "").split("\n") if r.strip()]

        full_desc = description
        if evidence:
            full_desc += f"\n\nEvidence: {evidence}"
        if other_info:
            full_desc += f"\n\nAdditional Info: {other_info}"

        cwe_str = f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else None

        raw_line = f"[{risk}] {name} at {url_affected} (plugin: {plugin_id})"
        raw_log.append(raw_line)

        findings.append({
            "title": f"{name} [{risk}] on {url_affected}",
            "description": full_desc.strip(),
            "severity": severity,
            "affected_component": url_affected,
            "cwe_id": cwe_str,
            "remediation": solution.strip() if solution else None,
            "references": refs[:10],  # cap reference list
            "raw_output": raw_line,
        })

    update_scan_raw_output(scan_id, "\n".join(raw_log))
    count = save_findings_to_db(scan_id, org_id, asset_id, findings)
    update_asset_last_scanned(asset_id)
    publish_output(scan_id, f"[zaproxy] Done. {count} findings saved.")
    update_scan_status(scan_id, "completed")
