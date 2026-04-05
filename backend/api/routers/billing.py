import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from core.database import get_db
from core.security import get_current_user
from core.config import settings
from models.organization import Organization
from models.user import User

router = APIRouter()

PLANS = {
    "community": {
        "name": "Community",
        "price_monthly": 0,
        "limits": {
            "assets": 10,
            "scans_per_month": 50,
            "users": 2,
            "reports": 5,
            "api_keys": 2,
        },
        "features": [
            "Basic vulnerability scanning",
            "Nmap & SSL scans",
            "5 report exports/month",
            "Community support",
        ],
    },
    "professional": {
        "name": "Professional",
        "price_monthly": 149,
        "stripe_price_id_env": "STRIPE_PRICE_PROFESSIONAL",
        "limits": {
            "assets": 500,
            "scans_per_month": 2000,
            "users": 10,
            "reports": -1,  # unlimited
            "api_keys": 20,
        },
        "features": [
            "All Community features",
            "Full tool suite (Nuclei, Nikto, SQLMap, etc.)",
            "Unlimited reports",
            "SLA tracking & alerts",
            "CISA KEV integration",
            "Priority support",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": 499,
        "stripe_price_id_env": "STRIPE_PRICE_ENTERPRISE",
        "limits": {
            "assets": -1,
            "scans_per_month": -1,
            "users": -1,
            "reports": -1,
            "api_keys": -1,
        },
        "features": [
            "All Professional features",
            "Unlimited assets & scans",
            "TPRM vendor risk management",
            "Custom integrations",
            "SSO/SAML",
            "Dedicated support",
            "SLA guarantee",
        ],
    },
}


class CheckoutRequest(BaseModel):
    plan: str  # professional/enterprise
    success_url: str
    cancel_url: str


@router.get("/plans")
async def get_plans():
    return {"plans": PLANS}


@router.post("/checkout", response_model=dict)
async def create_checkout_session(
    request: CheckoutRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can manage billing")

    if request.plan not in ("professional", "enterprise"):
        raise HTTPException(status_code=400, detail="Invalid plan. Choose: professional or enterprise")

    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing not configured")

    stripe.api_key = settings.STRIPE_SECRET_KEY

    price_id = (
        settings.STRIPE_PRICE_PROFESSIONAL
        if request.plan == "professional"
        else settings.STRIPE_PRICE_ENTERPRISE
    )
    if not price_id:
        raise HTTPException(status_code=503, detail=f"Stripe price ID for {request.plan} not configured")

    # Get or create Stripe customer
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    customer_id = org.stripe_customer_id
    if not customer_id:
        customer = stripe.Customer.create(
            email=current_user.email,
            name=org.name,
            metadata={"org_id": str(org.id), "org_slug": org.slug},
        )
        customer_id = customer.id
        org.stripe_customer_id = customer_id
        await db.commit()

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=request.success_url + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=request.cancel_url,
        metadata={"org_id": str(org.id), "plan": request.plan},
    )

    return {"checkout_url": session.url, "session_id": session.id}


@router.post("/webhook")
async def stripe_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Handle Stripe webhook events."""
    if not settings.STRIPE_SECRET_KEY or not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Billing not configured")

    stripe.api_key = settings.STRIPE_SECRET_KEY

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        org_id = session.get("metadata", {}).get("org_id")
        plan = session.get("metadata", {}).get("plan")
        subscription_id = session.get("subscription")

        if org_id and plan:
            org_result = await db.execute(
                select(Organization).where(Organization.id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if org:
                org.plan = plan
                org.stripe_subscription_id = subscription_id
                await db.commit()

    elif event_type == "customer.subscription.updated":
        subscription = event["data"]["object"]
        status_val = subscription.get("status")
        customer_id = subscription.get("customer")

        org_result = await db.execute(
            select(Organization).where(Organization.stripe_customer_id == customer_id)
        )
        org = org_result.scalar_one_or_none()
        if org and status_val in ("canceled", "unpaid", "past_due"):
            org.plan = "community"
            await db.commit()

    elif event_type == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer")

        org_result = await db.execute(
            select(Organization).where(Organization.stripe_customer_id == customer_id)
        )
        org = org_result.scalar_one_or_none()
        if org:
            org.plan = "community"
            org.stripe_subscription_id = None
            await db.commit()

    return {"received": True}


@router.get("/subscription", response_model=dict)
async def get_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    subscription_detail = None
    if org.stripe_subscription_id and settings.STRIPE_SECRET_KEY:
        try:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            sub = stripe.Subscription.retrieve(org.stripe_subscription_id)
            subscription_detail = {
                "status": sub.status,
                "current_period_end": sub.current_period_end,
                "cancel_at_period_end": sub.cancel_at_period_end,
            }
        except Exception:
            pass

    plan_info = PLANS.get(org.plan, PLANS["community"])

    return {
        "org_id": str(org.id),
        "plan": org.plan,
        "plan_details": plan_info,
        "stripe_customer_id": org.stripe_customer_id,
        "stripe_subscription_id": org.stripe_subscription_id,
        "subscription": subscription_detail,
    }
