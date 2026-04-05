from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://leruo_user:leruo_pass@postgres:5432/leruo_security"
    DATABASE_URL_SYNC: str = "postgresql://leruo_user:leruo_pass@postgres:5432/leruo_security"

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"

    # Auth
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Scanning
    SCAN_OUTPUT_DIR: str = "/tmp/leruo-scans"
    MAX_CONCURRENT_SCANS: int = 5

    # External APIs
    NVD_API_KEY: str = ""
    CLAUDE_API_KEY: str = ""

    # Billing
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_PROFESSIONAL: str = ""
    STRIPE_PRICE_ENTERPRISE: str = ""

    # Email
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "security@leruo.io"

    class Config:
        env_file = ".env"


settings = Settings()
