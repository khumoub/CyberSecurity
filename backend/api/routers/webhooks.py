import uuid
import hmac
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
from core.security import get_current_user
from models.user import User

router = APIRouter()

# In-memory webhook store (replace with DB table in production)
_webhooks: dict = {}


class WebhookRequest(BaseModel):
    name: str
    url: str
    events: List[str]  # scan.completed, finding.created, finding.updated, sla.breach
    secret: Optional[str] = None
    is_active: bool = True


class WebhookUpdateRequest(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None
    is_active: Optional[bool] = None


class WebhookResponse(BaseModel):
    id: str
    org_id: str
    name: str
    url: str
    events: List[str]
    is_active: bool
    created_at: str
    last_triggered_at: Optional[str] = None
    delivery_count: int = 0
    failure_count: int = 0


ALLOWED_EVENTS = {
    "scan.completed",
    "scan.failed",
    "finding.created",
    "finding.updated",
    "finding.critical",
    "sla.breach",
    "asset.created",
}


@router.get("/", response_model=List[WebhookResponse])
async def list_webhooks(
    current_user: User = Depends(get_current_user),
):
    org_webhooks = [
        w for w in _webhooks.values()
        if w.get("org_id") == str(current_user.org_id)
    ]
    return org_webhooks


@router.post("/", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    request: WebhookRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    invalid_events = set(request.events) - ALLOWED_EVENTS
    if invalid_events:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event types: {invalid_events}. Allowed: {ALLOWED_EVENTS}",
        )

    webhook_id = str(uuid.uuid4())
    secret = request.secret or hmac.new(
        uuid.uuid4().bytes, digestmod=hashlib.sha256
    ).hexdigest()

    record = {
        "id": webhook_id,
        "org_id": str(current_user.org_id),
        "name": request.name,
        "url": request.url,
        "events": request.events,
        "secret": secret,
        "is_active": request.is_active,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_triggered_at": None,
        "delivery_count": 0,
        "failure_count": 0,
    }
    _webhooks[webhook_id] = record
    return record


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    current_user: User = Depends(get_current_user),
):
    webhook = _webhooks.get(webhook_id)
    if not webhook or webhook.get("org_id") != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return webhook


@router.put("/{webhook_id}", response_model=WebhookResponse)
@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    request: WebhookUpdateRequest,
    current_user: User = Depends(get_current_user),
):
    webhook = _webhooks.get(webhook_id)
    if not webhook or webhook.get("org_id") != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Webhook not found")

    update_data = request.model_dump(exclude_unset=True)
    if "events" in update_data:
        invalid_events = set(update_data["events"]) - ALLOWED_EVENTS
        if invalid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event types: {invalid_events}",
            )

    webhook.update(update_data)
    return webhook


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    current_user: User = Depends(get_current_user),
):
    webhook = _webhooks.get(webhook_id)
    if not webhook or webhook.get("org_id") != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    del _webhooks[webhook_id]


@router.post("/{webhook_id}/test", response_model=dict)
async def test_webhook(
    webhook_id: str,
    current_user: User = Depends(get_current_user),
):
    """Send a test payload to the webhook URL."""
    import requests as req_lib

    webhook = _webhooks.get(webhook_id)
    if not webhook or webhook.get("org_id") != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Webhook not found")

    payload = {
        "event": "webhook.test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "webhook_id": webhook_id,
        "org_id": str(current_user.org_id),
        "data": {"message": "This is a test webhook from Leruo Security Platform"},
    }
    payload_bytes = json.dumps(payload).encode()
    signature = hmac.new(
        webhook.get("secret", "").encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    try:
        response = req_lib.post(
            webhook["url"],
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Leruo-Signature": f"sha256={signature}",
                "X-Leruo-Event": "webhook.test",
            },
            timeout=10,
        )
        webhook["last_triggered_at"] = datetime.now(timezone.utc).isoformat()
        webhook["delivery_count"] = webhook.get("delivery_count", 0) + 1

        return {
            "success": response.status_code < 400,
            "status_code": response.status_code,
            "response_body": response.text[:500],
        }
    except Exception as e:
        webhook["failure_count"] = webhook.get("failure_count", 0) + 1
        return {"success": False, "error": str(e)}


def dispatch_webhook_event(org_id: str, event: str, data: dict):
    """Call this from tasks to fire webhooks for an event."""
    import requests as req_lib

    org_webhooks = [
        w for w in _webhooks.values()
        if w.get("org_id") == org_id
        and w.get("is_active")
        and event in w.get("events", [])
    ]

    for webhook in org_webhooks:
        payload = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "org_id": org_id,
            "data": data,
        }
        payload_bytes = json.dumps(payload).encode()
        signature = hmac.new(
            webhook.get("secret", "").encode(),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

        try:
            req_lib.post(
                webhook["url"],
                data=payload_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-Leruo-Signature": f"sha256={signature}",
                    "X-Leruo-Event": event,
                },
                timeout=10,
            )
            webhook["last_triggered_at"] = datetime.now(timezone.utc).isoformat()
            webhook["delivery_count"] = webhook.get("delivery_count", 0) + 1
        except Exception:
            webhook["failure_count"] = webhook.get("failure_count", 0) + 1
