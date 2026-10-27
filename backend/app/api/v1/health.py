from datetime import datetime, timezone
from fastapi import APIRouter, Response, status
from app.database import check_db_ready
from app.storage import get_storage

router = APIRouter(tags=["Health & Readiness"])


@router.get("/health")
def health_check():
    """
    Liveness check confirming the FastAPI service is active.
    """
    return {
        "status": "ok",
        "service": "spectra-backend",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/ready")
def readiness_check(response: Response):
    """
    Readiness check validating database and storage writability.
    """
    db_ok = check_db_ready()
    storage = get_storage()
    storage_ok = storage.check_ready()

    if not (db_ok and storage_ok):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "database": "connected" if db_ok else "unreachable",
            "storage": "ready" if storage_ok else "unwritable"
        }

    return {
        "status": "ready",
        "database": "connected",
        "storage": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
