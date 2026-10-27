from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.api.deps import verify_internal_token
from app.services.analysis_service import AnalysisService
from app.schemas.analysis import InternalStageResponse, InternalFailedRequest

router = APIRouter(
    prefix="/internal/analyses",
    tags=["Internal n8n Pipeline"],
    dependencies=[Depends(verify_internal_token)]
)


@router.post("/{job_id}/metadata", response_model=InternalStageResponse)
async def stage_metadata(job_id: str, db: Session = Depends(get_db)):
    """
    Stage 1: Extract technical metadata and provenance clues.
    Idempotent. Protected by SPECTRA_INTERNAL_TOKEN.
    """
    try:
        data = await AnalysisService.execute_metadata_stage(db, job_id)
        job = AnalysisService.get_job(db, job_id)
        return InternalStageResponse(
            job_id=job.id,
            media_type=job.media_type,
            status=job.status,
            stage="metadata",
            data=data
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{job_id}/detect", response_model=InternalStageResponse)
async def stage_detect(job_id: str, db: Session = Depends(get_db)):
    """
    Stage 2: Execute configured AI/deepfake detector providers.
    Idempotent. Protected by SPECTRA_INTERNAL_TOKEN.
    """
    try:
        detectors = await AnalysisService.execute_detect_stage(db, job_id)
        job = AnalysisService.get_job(db, job_id)
        return InternalStageResponse(
            job_id=job.id,
            media_type=job.media_type,
            status=job.status,
            stage="detect",
            data={"detectors": detectors}
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{job_id}/finalize", response_model=InternalStageResponse)
async def stage_finalize(job_id: str, db: Session = Depends(get_db)):
    """
    Stage 3: Assemble single stable report JSON object and transition job to completed.
    Idempotent. Protected by SPECTRA_INTERNAL_TOKEN.
    """
    try:
        report = await AnalysisService.execute_finalize_stage(db, job_id)
        job = AnalysisService.get_job(db, job_id)
        return InternalStageResponse(
            job_id=job.id,
            media_type=job.media_type,
            status=job.status,
            stage="finalize",
            data={"report": report}
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{job_id}/failed", response_model=InternalStageResponse)
def stage_failed(job_id: str, payload: InternalFailedRequest, db: Session = Depends(get_db)):
    """
    Record failure from n8n or internal stages.
    Protected by SPECTRA_INTERNAL_TOKEN.
    """
    try:
        res = AnalysisService.execute_failed_stage(
            db,
            job_id=job_id,
            error_message=payload.error or "Pipeline failure reported by n8n.",
            stage_name=payload.stage or "pipeline"
        )
        job = AnalysisService.get_job(db, job_id)
        return InternalStageResponse(
            job_id=job.id,
            media_type=job.media_type,
            status=job.status,
            stage="failed",
            message=payload.error
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
