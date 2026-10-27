from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.session import DeviceSession
from app.models.analysis import AnalysisJob
from app.schemas.session import DeviceSessionCreate, DeviceSessionResponse
from app.schemas.analysis import AnalysisStatusResponse

router = APIRouter(prefix="/api/v1/device-sessions", tags=["Device Sessions"])


@router.post("", response_model=DeviceSessionResponse, status_code=status.HTTP_201_CREATED)
def create_device_session(payload: DeviceSessionCreate, db: Session = Depends(get_db)):
    """
    Create a phone capture session and return capture_session_id.
    """
    session = DeviceSession(
        device_name=payload.device_name,
        device_fingerprint=payload.device_fingerprint,
        client_metadata=payload.client_metadata or {}
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    return DeviceSessionResponse(
        capture_session_id=session.id,
        device_name=session.device_name,
        created_at=session.created_at,
        expires_at=session.expires_at,
        is_active=session.is_active
    )


@router.get("/{capture_session_id}/analyses", response_model=List[AnalysisStatusResponse])
def list_session_analyses(capture_session_id: str, db: Session = Depends(get_db)):
    """
    List uploads and reports associated with the specified phone simulation session.
    """
    session = db.query(DeviceSession).filter(DeviceSession.id == capture_session_id).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device session '{capture_session_id}' not found."
        )

    jobs = db.query(AnalysisJob).filter(
        AnalysisJob.capture_session_id == capture_session_id
    ).order_by(AnalysisJob.created_at.desc()).all()

    results = []
    for j in jobs:
        summary = None
        if j.assessment_label:
            summary = {
                "label": j.assessment_label,
                "score": j.assessment_score,
                "score_type": "model_score",
                "explanation": j.final_report.get("assessment", {}).get("explanation") if j.final_report else None
            }
        results.append(
            AnalysisStatusResponse(
                job_id=j.id,
                status=j.status,
                media_type=j.media_type,
                original_filename=j.original_filename,
                size_bytes=j.size_bytes,
                mime_type=j.detected_mime_type,
                sha256=j.sha256_hash,
                created_at=j.created_at,
                completed_at=j.completed_at,
                assessment_summary=summary,
                error_message=j.error_message
            )
        )

    return results
