import httpx
import hmac
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional
import psycopg2
from core.config import settings


class WebhookService:
    """Dispatches signed webhook events to registered URLs."""

    def _build_signature(self, secret: str, timestamp: str, payload_bytes: bytes) -> str:
        """Generate HMAC-SHA256 signature over timestamp + payload."""
        signing_input = f"{timestamp}.".encode() + payload_bytes
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
        return f"sha256={sig}"

    async def dispatch(
        self,
        webhook_url: str,
        secret: str,
        event_type: str,
        payload: dict,
    ) -> bool:
        """
        POST payload to webhook URL with HMAC-SHA256 signature header.
        Headers: X-Leruo-Event, X-Leruo-Signature, X-Leruo-Timestamp.
        Returns True on success (2xx response), False otherwise.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        payload_bytes = json.dumps(payload, default=str).encode()
        signature = self._build_signature(secret, timestamp, payload_bytes)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Leruo-Security-Platform/1.0",
            "X-Leruo-Event": event_type,
            "X-Leruo-Signature": signature,
            "X-Leruo-Timestamp": timestamp,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(
                    webhook_url,
                    content=payload_bytes,
                    headers=headers,
                )
                return resp.is_success
            except httpx.RequestError:
                return False

    def _get_org_webhooks(self, org_id: str, event_type: str) -> list:
        """Fetch active webhooks for an org that subscribe to event_type."""
        try:
            conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, url, secret
                FROM webhooks
                WHERE org_id = %s
                  AND is_active = true
                  AND (events @> ARRAY[%s] OR events @> ARRAY['*'])
                """,
                (org_id, event_type),
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return [{"id": str(r[0]), "url": r[1], "secret": r[2]} for r in rows]
        except Exception as e:
            print(f"[webhook_service] DB error fetching webhooks: {e}")
            return []

    def _record_delivery(self, webhook_id: str, event_type: str, success: bool, payload: dict):
        """Record webhook delivery attempt in the DB."""
        try:
            conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
            cur = conn.cursor()
            now = datetime.now(timezone.utc)
            cur.execute(
                """
                INSERT INTO webhook_deliveries
                    (webhook_id, event_type, payload, success, created_at)
                VALUES (%s, %s, %s::jsonb, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    webhook_id,
                    event_type,
                    json.dumps(payload, default=str),
                    success,
                    now,
                ),
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            # Non-fatal: delivery logging failure should not break the dispatch
            print(f"[webhook_service] delivery record error: {e}")

    async def dispatch_finding(self, org_id: str, finding: dict, db=None):
        """Look up org webhooks, dispatch to all active ones for 'finding.created' event."""
        event_type = "finding.created"
        webhooks = self._get_org_webhooks(org_id, event_type)

        payload = {
            "event": event_type,
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "id": str(finding.get("id", "")),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "cve_id": finding.get("cve_id"),
                "cvss_score": finding.get("cvss_score"),
                "affected_component": finding.get("affected_component"),
                "status": finding.get("status", "open"),
            },
        }

        for wh in webhooks:
            success = await self.dispatch(
                webhook_url=wh["url"],
                secret=wh.get("secret", ""),
                event_type=event_type,
                payload=payload,
            )
            self._record_delivery(wh["id"], event_type, success, payload)

    async def dispatch_scan_complete(self, org_id: str, scan_job: dict, db=None):
        """Dispatch scan.completed event to all active webhooks."""
        event_type = "scan.completed"
        webhooks = self._get_org_webhooks(org_id, event_type)

        payload = {
            "event": event_type,
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "id": str(scan_job.get("id", "")),
                "scan_type": scan_job.get("scan_type"),
                "target": scan_job.get("target"),
                "status": scan_job.get("status"),
                "findings_count": scan_job.get("findings_count", 0),
                "started_at": str(scan_job.get("started_at", "")),
                "completed_at": str(scan_job.get("completed_at", "")),
            },
        }

        for wh in webhooks:
            success = await self.dispatch(
                webhook_url=wh["url"],
                secret=wh.get("secret", ""),
                event_type=event_type,
                payload=payload,
            )
            self._record_delivery(wh["id"], event_type, success, payload)
