from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from core.config import settings
from core.database import engine, Base
from api.routers import auth, assets, scans, findings, tools, reports, webhooks, billing
from api.routers import intel, scan_ws, dashboard, mitre, remediation, tprm


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="Leruo Security Platform API",
    description="Professional cybersecurity scanning, vulnerability management & threat intelligence",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
app.include_router(tools.router, prefix="/api/v1/tools", tags=["tools"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(webhooks.router, prefix="/api/v1/webhooks", tags=["webhooks"])
app.include_router(billing.router, prefix="/api/v1/billing", tags=["billing"])
app.include_router(intel.router, prefix="/api/v1/intel", tags=["intel"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(mitre.router, prefix="/api/v1/mitre", tags=["mitre"])
app.include_router(remediation.router, prefix="/api/v1/remediation", tags=["remediation"])
app.include_router(tprm.router, prefix="/api/v1/tprm", tags=["tprm"])
# WebSocket — no prefix, handled directly
app.include_router(scan_ws.router, tags=["websocket"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "leruo-security-platform", "version": "1.0.0"}
