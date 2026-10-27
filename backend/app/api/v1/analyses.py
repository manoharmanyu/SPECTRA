import os
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import (
    APIRouter,
    UploadFile,
    File,
    Form,
    Depends,
    HTTPException,
    BackgroundTasks,
    Response,
    Request,
    status
)
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.analysis import AnalysisJob
from app.schemas.analysis import (
    AnalysisCreateResponse,
    AnalysisStatusResponse,
    AssessmentSummary
)
from app.storage import get_storage
from app.media import detect_media_signature
from app.services.webhook_service import dispatch_n8n_webhook
from app.services.analysis_service import AnalysisService
from app.api.deps import get_client_ip

router = APIRouter(prefix="/api/v1/analyses", tags=["Analyses"])


async def run_standalone_pipeline(job_id: str, db: Session):
    """
    Background worker that executes stages locally when n8n is not active
    or as a fallback mechanism.
    """
    try:
        await AnalysisService.execute_metadata_stage(db, job_id)
        await AnalysisService.execute_detect_stage(db, job_id)
        await AnalysisService.execute_finalize_stage(db, job_id)
    except Exception as e:
        AnalysisService.execute_failed_stage(db, job_id, str(e), stage_name="standalone_runner")


@router.post("", response_model=AnalysisCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    capture_session_id: Optional[str] = Form(None),
    source_device_id: Optional[str] = Form(None),
    source_origin: Optional[str] = Form("web_upload"),
    client_captured_at: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Multipart upload of image, audio, or video media.
    Stores file safely under generated UUID key, computes SHA-256, validates signatures,
    creates DB record, and dispatches to n8n workflow. Returns HTTP 202 Accepted.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided in multipart request."
        )

    # Sanitize and assign generated UUID storage key
    job_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1].lower()
    storage_key = f"uploads/{job_id[:8]}/{job_id}{ext}"

    storage = get_storage()

    try:
        size_bytes, sha256_hash = await storage.save_stream(
            file=file,
            key=storage_key,
            max_bytes=settings.MAX_UPLOAD_SIZE_BYTES
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage streaming error: {str(e)}"
        )

    # Validate actual file signature/MIME
    local_path = storage.get_local_path(storage_key)
    try:
        media_type, detected_mime = detect_media_signature(local_path, file.filename)
    except ValueError as e:
        # Clean up stored file if signature validation fails
        await storage.delete(storage_key)
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(e))

    # Parse client capture timestamp if provided
    client_dt = None
    if client_captured_at:
        try:
            client_dt = datetime.fromisoformat(client_captured_at.replace("Z", "+00:00"))
        except Exception:
            pass

    # Create DB Job Record
    job = AnalysisJob(
        id=job_id,
        capture_session_id=capture_session_id if capture_session_id else None,
        source_origin=source_origin or "web_upload",
        source_device_id=source_device_id,
        client_captured_at=client_dt,
        media_type=media_type,
        detected_mime_type=detected_mime,
        original_filename=file.filename,
        storage_key=storage_key,
        size_bytes=size_bytes,
        sha256_hash=sha256_hash,
        status="queued"
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Log audit event
    AnalysisService.log_audit(
        db=db,
        job_id=job.id,
        event_type="upload",
        details={
            "original_filename": file.filename,
            "media_type": media_type,
            "mime": detected_mime,
            "size_bytes": size_bytes,
            "sha256": sha256_hash
        },
        ip_address=get_client_ip(request)
    )

    # Dispatch to n8n webhook
    dispatched = await dispatch_n8n_webhook(job.id, media_type)
    AnalysisService.log_audit(
        db=db,
        job_id=job.id,
        event_type="n8n_dispatched",
        details={"dispatched": dispatched, "n8n_url": settings.N8N_WEBHOOK_URL}
    )

    # If n8n was not dispatched or standalone pipeline is enabled, trigger background pipeline
    if not dispatched or settings.STANDALONE_PIPELINE:
        background_tasks.add_task(run_standalone_pipeline, job.id, db)

    status_url = f"/api/v1/analyses/{job.id}"
    report_url = f"/api/v1/analyses/{job.id}/report"

    return AnalysisCreateResponse(
        job_id=job.id,
        status=job.status,
        media_type=job.media_type,
        status_url=status_url,
        report_url=report_url
    )


@router.get("/{job_id}", response_model=AnalysisStatusResponse)
def get_analysis_status(job_id: str, db: Session = Depends(get_db)):
    """
    Get current processing status and safe summary of an analysis job.
    """
    job = AnalysisService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job '{job_id}' not found."
        )

    summary = None
    if job.assessment_label:
        summary = AssessmentSummary(
            label=job.assessment_label,
            score=job.assessment_score,
            score_type="model_score",
            explanation=job.final_report.get("assessment", {}).get("explanation") if job.final_report else None
        )

    return AnalysisStatusResponse(
        job_id=job.id,
        status=job.status,
        media_type=job.media_type,
        original_filename=job.original_filename,
        size_bytes=job.size_bytes,
        mime_type=job.detected_mime_type,
        sha256=job.sha256_hash,
        created_at=job.created_at,
        completed_at=job.completed_at,
        assessment_summary=summary,
        error_message=job.error_message
    )


@router.get("/{job_id}/report")
def get_analysis_report(job_id: str, response: Response, db: Session = Depends(get_db)):
    """
    Get the detailed forensic report. Returns HTTP 202 while queued or processing.
    """
    job = AnalysisService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job '{job_id}' not found."
        )

    if job.status in ("queued", "processing"):
        response.status_code = status.HTTP_202_ACCEPTED
        return {
            "job_id": job.id,
            "status": job.status,
            "message": "Forensic analysis is currently in progress.",
            "status_url": f"/api/v1/analyses/{job.id}"
        }

    if job.status == "failed":
        return {
            "job_id": job.id,
            "status": "failed",
            "error": job.error_message or "Analysis failed during execution stage.",
            "file": {
                "sha256": job.sha256_hash,
                "size_bytes": job.size_bytes,
                "mime_type": job.detected_mime_type,
                "original_filename": job.original_filename
            }
        }

    if job.final_report:
        return job.final_report

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Completed job has missing report data."
    )


@router.post("/{job_id}/retry", response_model=AnalysisCreateResponse)
async def retry_analysis(
    job_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Safely redispatch eligible queued/failed jobs.
    """
    try:
        job = await AnalysisService.retry_job(db, job_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Dispatch to webhook or standalone
    dispatched = await dispatch_n8n_webhook(job.id, job.media_type)
    if not dispatched or settings.STANDALONE_PIPELINE:
        background_tasks.add_task(run_standalone_pipeline, job.id, db)

    return AnalysisCreateResponse(
        job_id=job.id,
        status=job.status,
        media_type=job.media_type,
        status_url=f"/api/v1/analyses/{job.id}",
        report_url=f"/api/v1/analyses/{job.id}/report"
    )
