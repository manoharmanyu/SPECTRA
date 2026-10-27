from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    SPECTRA_API_BASE_URL: str = "http://localhost:8000"

    # Security
    SPECTRA_INTERNAL_TOKEN: str = "spectra_internal_dev_secret_token_change_in_production"
    SPECTRA_WEBHOOK_TOKEN: str = "spectra_webhook_dev_token_change_in_production"

    # Database
    DATABASE_URL: str = "sqlite:///./spectra_forensics.db"

    # CORS
    FRONTEND_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,https://thespectra.vercel.app,https://spectra-mobile.vercel.app"

    # Storage
    STORAGE_BACKEND: str = "local"  # "local" | "s3"
    LOCAL_STORAGE_PATH: str = "./storage_data"
    MAX_UPLOAD_SIZE_BYTES: int = 104857600  # 100 MB
    UPLOAD_RETENTION_DAYS: int = 7

    # S3 (Optional)
    S3_ENDPOINT_URL: Optional[str] = None
    S3_BUCKET_NAME: Optional[str] = None
    S3_ACCESS_KEY_ID: Optional[str] = None
    S3_SECRET_ACCESS_KEY: Optional[str] = None
    S3_REGION_NAME: str = "us-east-1"

    # n8n
    N8N_WEBHOOK_URL: Optional[str] = "http://localhost:5678/webhook/spectra-analysis"
    STANDALONE_PIPELINE: bool = True

    # Detector Provider API Keys
    HIVE_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def allowed_origins(self) -> List[str]:
        return [origin.strip() for origin in self.FRONTEND_ORIGINS.split(",") if origin.strip()]


settings = Settings()
