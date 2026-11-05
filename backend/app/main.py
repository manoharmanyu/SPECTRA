import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models.analysis import AnalysisJob
from app.api.v1.health import router as health_router
from app.api.v1.sessions import router as sessions_router
from app.api.v1.analyses import router as analyses_router
from app.api.v1.media import router as media_router
from app.api.internal.n8n import router as internal_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure DB tables exist and storage path is ready
    Base.metadata.create_all(bind=engine)
    if settings.STORAGE_BACKEND == "local":
        os.makedirs(os.path.abspath(settings.LOCAL_STORAGE_PATH), exist_ok=True)

    # Job Reliability & Crash Recovery: Recover jobs interrupted during unexpected shutdown
    db = SessionLocal()
    try:
        stranded_jobs = db.query(AnalysisJob).filter(AnalysisJob.status == "processing").all()
        for j in stranded_jobs:
            if j.retry_count < j.max_retries:
                j.status = "queued"
                j.retry_count += 1
            else:
                j.status = "failed"
                j.error_message = "Analysis timed out or worker process restarted while processing."
        if stranded_jobs:
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    yield
    # Graceful shutdown cleanup if needed


is_prod = settings.ENVIRONMENT.lower() == "production"

app = FastAPI(
    title="SPECTRA Media Forensics API",
    description="High-integrity media intake, technical provenance extraction, and AI/deepfake detection API.",
    version="1.0.0",
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
    lifespan=lifespan
)

# Apply strict CORS with Cloudflare & Vercel edge domain pattern matching
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_origin_regex=r"^https://.*(\.vercel\.app|\.pages\.dev|\.trycloudflare\.com|\.workers\.dev)$|http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Session-Id",
        "X-Device-Token",
        "X-Spectra-Internal-Token",
        "X-Spectra-Webhook-Token",
        "X-Requested-With",
        "X-User-Id"
    ],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if is_prod:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Mount Routers
app.include_router(health_router)  # /health, /ready
app.include_router(sessions_router)  # /api/v1/device-sessions
app.include_router(analyses_router)  # /api/v1/analyses
app.include_router(media_router)  # /api/v1/media (AI-Generated Media Detection Engine)
app.include_router(internal_router)  # /internal/analyses
