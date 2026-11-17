"""
PhishGuard AI — Application Configuration
Reads from environment variables (and .env in development).
"""
from functools import lru_cache
from typing import List

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    APP_ENV: str = "development"
    APP_VERSION: str = "1.0.0"
    APP_SECRET_KEY: str
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # --- Allowed Hosts & Origins ---
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3001",
        "http://localhost:3000",
        "http://localhost:80",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    # --- Database ---
    DATABASE_URL: str
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "phishguard"
    POSTGRES_USER: str = "phishguard"
    POSTGRES_PASSWORD: str

    # --- Redis ---
    REDIS_URL: str
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    # --- JWT ---
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ALGORITHM: str = "HS256"

    # --- File Upload ---
    MAX_UPLOAD_SIZE_MB: int = 25
    UPLOAD_TEMP_DIR: str = "/tmp/phishguard_uploads"

    @property
    def MAX_UPLOAD_SIZE_BYTES(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # --- AI Provider ---
    AI_PROVIDER: str = "mock"  # openai | google | mock
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    GOOGLE_API_KEY: str = ""
    GOOGLE_MODEL: str = "gemini-1.5-flash"

    # --- Threat Intelligence ---
    TI_DEMO_MODE: bool = True
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_ENABLED: bool = False
    URLHAUS_ENABLED: bool = True
    URLHAUS_BASE_URL: str = "https://urlhaus-api.abuse.ch/v1"
    ABUSEIPDB_API_KEY: str = ""
    ABUSEIPDB_ENABLED: bool = False

    # --- Security ---
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 30
    RATE_LIMIT_PER_MINUTE: int = 60

    # --- Encryption Key (for API keys at rest) ---
    ENCRYPTION_KEY: str = ""
    TOKEN_ENCRYPTION_KEY: str = ""  # If empty, defaults to ENCRYPTION_KEY

    # --- Google OAuth 2.0 & Gmail Integration ---
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:3001/integrations/gmail/callback"
    FRONTEND_URL: str = "http://localhost:3001"
    BACKEND_PUBLIC_URL: str = "http://localhost:8000"

    # --- Google Cloud Pub/Sub & Real-Time Monitoring (Milestone G3) ---
    GMAIL_PUBSUB_TOPIC: str = ""           # e.g., "projects/my-project/topics/gmail-notifications"
    GMAIL_PUBSUB_SUBSCRIPTION: str = ""    # e.g., "projects/my-project/subscriptions/gmail-inbox-push"
    GMAIL_PUBSUB_VERIFICATION_TOKEN: str = ""  # Shared verification secret for push endpoints
    GMAIL_PUBSUB_AUDIENCE: str = ""        # Expected JWT audience for Google OIDC verification

    @property
    def EFFECTIVE_TOKEN_ENCRYPTION_KEY(self) -> str:
        return self.TOKEN_ENCRYPTION_KEY.strip() if self.TOKEN_ENCRYPTION_KEY else self.ENCRYPTION_KEY.strip()

    # --- SMTP (optional) ---
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@phishguard.local"
    SMTP_USE_TLS: bool = True

    @model_validator(mode="after")
    def validate_production_requirements(self) -> "Settings":
        if self.APP_ENV == "production":
            if not self.APP_SECRET_KEY or self.APP_SECRET_KEY == "CHANGE_ME_TO_A_RANDOM_64_CHAR_HEX_STRING":
                raise ValueError("APP_SECRET_KEY must be set in production")
            if not self.ENCRYPTION_KEY or self.ENCRYPTION_KEY.startswith("CHANGE_ME"):
                raise ValueError("ENCRYPTION_KEY must be set in production")
        return self


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
