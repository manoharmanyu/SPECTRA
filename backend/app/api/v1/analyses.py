import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
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
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db, SessionLocal
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
from app.api.deps import get_client_ip, get_current_user_context, enforce_job_ownership

router = APIRouter(prefix="/api/v1/analyses", tags=["Analyses"])


async def run_standalone_pipeline_worker(job_id: str):
    """
    Durable background worker with independent DB session lifecycle.
    Executes stages locally when n8n is not active or as a fallback mechanism.
    Guarantees session cleanup and prevents connection leaks.
    """
    db = SessionLocal()
    try:
        await AnalysisService.execute_metadata_stage(db, job_id)
        await AnalysisService.execute_detect_stage(db, job_id)
        await AnalysisService.execute_finalize_stage(db, job_id)
    except Exception as e:
        AnalysisService.execute_failed_stage(db, job_id, str(e), stage_name="standalone_runner")
    finally:
        db.close()


@router.post("", response_model=AnalysisCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    capture_session_id: Optional[str] = Form(None),
    source_device_id: Optional[str] = Form(None),
    source_origin: Optional[str] = Form("web_upload"),
    client_captured_at: Optional[str] = Form(None),
    user_id: Optional[str] = Form(None),
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Multipart upload of image, audio, or video media.
    Stores file safely under generated UUID key, computes SHA-256, validates signatures,
    creates DB record, and dispatches to n8n workflow. Returns HTTP 202 Accepted.
    Object-level ownership is linked to authenticated investigator.
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

    # Resolve capture session and verify device trust
    valid_capture_session_id = None
    if capture_session_id:
        from app.models.session import DeviceSession
        dev_session = db.query(DeviceSession).filter(
            DeviceSession.id == capture_session_id,
            DeviceSession.is_active.is_(True)
        ).first()
        if not dev_session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Device capture session '{capture_session_id}' is invalid, expired, or disconnected."
            )
        valid_capture_session_id = dev_session.id

    # Resolve owner
    owner_id = user_id or (user_context.get("id") if user_context.get("id") != "anonymous_guest" else None)

    # Create DB Job Record with ownership
    job = AnalysisJob(
        id=job_id,
        user_id=owner_id,
        capture_session_id=valid_capture_session_id,
        source_origin=source_origin or "web_upload",
        source_device_id=source_device_id,
        client_captured_at=client_dt,
        media_type=media_type,
        detected_mime_type=detected_mime,
        original_filename=file.filename,
        storage_key=storage_key,
        size_bytes=size_bytes,
        sha256_hash=sha256_hash,
        status="queued",
        retry_count=0,
        max_retries=3
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Log initial tamper-evident intake audit event (Chain of Custody sequence 1)
    AnalysisService.log_audit(
        db=db,
        job_id=job.id,
        event_type="evidence_intake",
        details={
            "original_filename": file.filename,
            "media_type": media_type,
            "mime": detected_mime,
            "size_bytes": size_bytes,
            "sha256": sha256_hash,
            "storage_key": storage_key,
            "source_origin": source_origin
        },
        ip_address=get_client_ip(request),
        actor_id=owner_id or "system",
        actor_role=user_context.get("role", "investigator")
    )

    # Dispatch to n8n webhook
    dispatched = await dispatch_n8n_webhook(job.id, media_type)
    AnalysisService.log_audit(
        db=db,
        job_id=job.id,
        event_type="n8n_dispatched",
        details={"dispatched": dispatched, "n8n_url": settings.N8N_WEBHOOK_URL},
        actor_id="system_orchestrator",
        actor_role="service"
    )

    # Trigger background pipeline with independent session worker
    if not dispatched or settings.STANDALONE_PIPELINE:
        background_tasks.add_task(run_standalone_pipeline_worker, job.id)

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
def get_analysis_status(
    job_id: str,
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Get current processing status and safe summary of an analysis job.
    Object-level authorization enforced.
    """
    job = AnalysisService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job '{job_id}' not found."
        )

    # Enforce Object-Level Authorization
    enforce_job_ownership(job.user_id, user_context)

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
def get_analysis_report(
    job_id: str,
    response: Response,
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Get the detailed forensic report. Returns HTTP 202 while queued or processing.
    Object-level authorization enforced.
    """
    job = AnalysisService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job '{job_id}' not found."
        )

    # Enforce Object-Level Authorization
    enforce_job_ownership(job.user_id, user_context)

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


@router.get("/{job_id}/custody-chain")
def get_custody_chain(
    job_id: str,
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Cryptographically verifies and retrieves the tamper-evident chain of custody for this evidence.
    """
    job = AnalysisService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    enforce_job_ownership(job.user_id, user_context)
    return AnalysisService.verify_audit_chain(db, job.id)


@router.get("/{job_id}/evidence/download")
def download_evidence_file(
    job_id: str,
    request: Request,
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Secure, authorized download of original preserved evidence.
    Strictly enforces object-level access control and logs an access event in the chain of custody.
    """
    job = AnalysisService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    enforce_job_ownership(job.user_id, user_context)

    storage = get_storage()
    local_path = storage.get_local_path(job.storage_key)
    if not os.path.exists(local_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Preserved evidence file not found in storage.")

    # Record access in tamper-evident audit chain
    AnalysisService.log_audit(
        db=db,
        job_id=job.id,
        event_type="evidence_accessed",
        details={"action": "evidence_download", "filename": job.original_filename},
        ip_address=get_client_ip(request),
        actor_id=user_context.get("id"),
        actor_role=user_context.get("role")
    )

    return FileResponse(
        path=local_path,
        media_type=job.detected_mime_type,
        filename=job.original_filename
    )


@router.post("/{job_id}/retry", response_model=AnalysisCreateResponse)
async def retry_analysis(
    job_id: str,
    background_tasks: BackgroundTasks,
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Safely redispatch eligible queued/failed jobs.
    Object-level authorization enforced.
    """
    target_job = AnalysisService.get_job(db, job_id)
    if not target_job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")

    enforce_job_ownership(target_job.user_id, user_context)

    try:
        job = await AnalysisService.retry_job(db, job_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Dispatch to webhook or standalone
    dispatched = await dispatch_n8n_webhook(job.id, job.media_type)
    if not dispatched or settings.STANDALONE_PIPELINE:
        background_tasks.add_task(run_standalone_pipeline_worker, job.id)

    return AnalysisCreateResponse(
        job_id=job.id,
        status=job.status,
        media_type=job.media_type,
        status_url=f"/api/v1/analyses/{job.id}",
        report_url=f"/api/v1/analyses/{job.id}/report"
    )


@router.get("/admin/dashboard")
def get_admin_dashboard(
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Centralized Administrator Dashboard records persisted in PostgreSQL / DB.
    Strictly restricted to users with admin role or internal service authorization.
    """
    if not (user_context.get("is_admin") or user_context.get("is_internal")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative authorization required."
        )

    jobs = db.query(AnalysisJob).order_by(AnalysisJob.created_at.desc()).all()

    total = len(jobs)
    image_count = sum(1 for j in jobs if j.media_type.lower() == "image")
    audio_count = sum(1 for j in jobs if j.media_type.lower() == "audio")
    video_count = sum(1 for j in jobs if j.media_type.lower() == "video")
    failed_count = sum(1 for j in jobs if j.status == "failed")
    deepfakes_count = sum(1 for j in jobs if j.assessment_label in ("likely_ai_generated", "likely_ai_manipulated"))
    authentic_count = sum(1 for j in jobs if j.assessment_label == "likely_not_ai_detected")

    job_records = [
        {
            "id": j.id,
            "timestamp": j.created_at.isoformat() if j.created_at else None,
            "fileName": j.original_filename,
            "fileType": j.media_type.capitalize(),
            "sizeBytes": j.size_bytes,
            "sha256": j.sha256_hash,
            "status": j.status,
            "verdict": j.assessment_label or "PENDING",
            "score": j.assessment_score,
            "detectorName": "SPECTRA-FastAPI-Forensic-Engine",
            "modelVersion": "v2.2-Production",
            "errorMessage": j.error_message,
            "report": j.final_report
        }
        for j in jobs[:100]
    ]

    return {
        "success": True,
        "kpis": {
            "totalInvocations": total,
            "imageAnalyses": image_count,
            "audioAnalyses": audio_count,
            "videoAnalyses": video_count,
            "deepfakesFlagged": deepfakes_count,
            "authenticVerified": authentic_count,
            "failedJobs": failed_count
        },
        "logs": job_records
    }
