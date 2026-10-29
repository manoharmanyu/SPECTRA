import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base
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
    yield
    # Shutdown logic if needed


app = FastAPI(
    title="SPECTRA Media Forensics API",
    description="High-integrity media intake, technical provenance extraction, and AI/deepfake detection API.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Apply CORS only to configured frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(health_router)  # /health, /ready
app.include_router(sessions_router)  # /api/v1/device-sessions
app.include_router(analyses_router)  # /api/v1/analyses
app.include_router(media_router)  # /api/v1/media (AI-Generated Media Detection Engine)
app.include_router(internal_router)  # /internal/analyses
