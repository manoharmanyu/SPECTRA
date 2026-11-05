import os
import time
import uuid
import shutil
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import (
    APIRouter,
    UploadFile,
    File,
    Form,
    Query,
    Depends,
    HTTPException,
    BackgroundTasks,
    Request,
    status
)
from sqlalchemy.orm import Session
import PIL
import numpy as np

from app.config import settings
from app.database import get_db, SessionLocal
from app.models.analysis import AnalysisJob
from app.storage import get_storage
from app.media.detector import detect_media_signature
from app.media.inspector import inspect_with_exiftool, resolve_binary
from app.media.pipelines.image import ImageDetectionService
from app.media.pipelines.audio import AudioDetectionService
from app.media.pipelines.video import VideoDetectionService
from app.media.fusion import EvidenceFusionEngine
from app.services.analysis_service import AnalysisService
from app.api.deps import get_client_ip, get_current_user_context, enforce_job_ownership
from app.schemas.media_detection import (
    MediaDetectionResponse,
    DetectorHealthResponse,
    DetectorHealthItem
)

# Decompression bomb mitigation
PIL.Image.MAX_IMAGE_PIXELS = 50_000_000

router = APIRouter(prefix="/api/v1/media", tags=["Media Detection Engine"])


async def execute_media_pipeline_worker(
    analysis_id: str,
    local_path: str,
    original_filename: str,
    media_type: str,
    detected_mime: str,
    size_bytes: int,
    sha256_hash: str
):
    """
    Independent background worker for async media analysis.
    Uses its own isolated SessionLocal to guarantee safe DB session lifecycle.
    """
    db = SessionLocal()
    try:
        await execute_media_pipeline(
            analysis_id=analysis_id,
            local_path=local_path,
            original_filename=original_filename,
            media_type=media_type,
            detected_mime=detected_mime,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            db=db
        )
    finally:
        db.close()


async def execute_media_pipeline(
    analysis_id: str,
    local_path: str,
    original_filename: str,
    media_type: str,
    detected_mime: str,
    size_bytes: int,
    sha256_hash: str,
    db: Session
) -> MediaDetectionResponse:
    """
    Executes the appropriate specialized forensic pipeline and fuses all evidence.
    """
    start_time = time.time()

    if media_type == "image":
        pipeline_output = await ImageDetectionService.analyze_image(local_path, original_filename)
        raw_metadata = await inspect_with_exiftool(local_path)
    elif media_type == "audio":
        pipeline_output = await AudioDetectionService.analyze_audio(local_path, original_filename)
        raw_metadata = await inspect_with_exiftool(local_path)
    elif media_type == "video":
        pipeline_output = await VideoDetectionService.analyze_video(local_path, original_filename)
        raw_metadata = await inspect_with_exiftool(local_path)
    else:
        raise ValueError(f"Unsupported media type: {media_type}")

    elapsed_ms = round((time.time() - start_time) * 1000.0, 2)

    # Fuse evidence through transparent decision layer
    response = EvidenceFusionEngine.fuse_evidence(
        analysis_id=analysis_id,
        media_type=media_type,
        sha256=sha256_hash,
        file_size_bytes=size_bytes,
        pipeline_output=pipeline_output,
        raw_metadata=raw_metadata,
        processing_time_ms=elapsed_ms
    )

    # Persist or update DB record
    job = db.query(AnalysisJob).filter(AnalysisJob.id == str(analysis_id)).first()
    if job:
        job.status = "completed"
        job.assessment_label = response.classification.lower()
        job.assessment_score = response.confidence.score
        job.final_report = response.model_dump()
        job.completed_at = datetime.now(timezone.utc)
        db.commit()

    return response


@router.post(
    "/analyze",
    response_model=MediaDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze media for AI generation, manipulation, or conventional capture"
)
async def analyze_media(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Multipart image, audio, or video file"),
    async_mode: bool = Query(False, description="Whether to execute asynchronously and return 202 status"),
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Unified AI-Generated Media Detection & Forensics Endpoint.
    
    Accepts:
      - Images: JPEG, PNG, WebP, TIFF (including BigTIFF), BMP, GIF, PSD
      - Audio: WAV, MP3, FLAC, M4A, OGG, AAC
      - Video: MP4, MOV, MKV, WebM, AVI
      
    Estimates whether media is:
      1. LIKELY_AI_GENERATED
      2. LIKELY_CAMERA_CAPTURED (Conventional sensor / microphone recording)
      3. POSSIBLY_EDITED_OR_MANIPULATED
      4. INCONCLUSIVE (Missing evidence, conflicting signals, or unsupported conditions)
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided in multipart request."
        )

    analysis_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1].lower()
    storage_key = f"uploads/{analysis_id[:8]}/{analysis_id}{ext}"
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Storage streaming error: {str(e)}")

    local_path = storage.get_local_path(storage_key)

    # Validate actual file signature/magic bytes
    try:
        media_type, detected_mime = detect_media_signature(local_path, file.filename)
    except ValueError as e:
        await storage.delete(storage_key)
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(e))

    # Decompression bomb and extreme dimension mitigation
    if media_type == "image":
        try:
            with PIL.Image.open(local_path) as test_img:
                w, h = test_img.size
                if w > 8192 or h > 8192:
                    await storage.delete(storage_key)
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Image dimensions ({w}x{h}) exceed maximum allowed dimension limit of 8192x8192."
                    )
        except HTTPException:
            raise
        except Exception:
            pass

    owner_id = user_context.get("id") if user_context.get("id") != "anonymous_guest" else None

    # Create AnalysisJob DB record
    job = AnalysisJob(
        id=analysis_id,
        user_id=owner_id,
        source_origin="media_analyze_api",
        media_type=media_type,
        detected_mime_type=detected_mime,
        original_filename=file.filename,
        storage_key=storage_key,
        size_bytes=size_bytes,
        sha256_hash=sha256_hash,
        status="processing" if async_mode else "completed",
        retry_count=0,
        max_retries=3,
        created_at=datetime.now(timezone.utc)
    )
    db.add(job)
    db.commit()

    # Log initial tamper-evident audit event (Chain of Custody sequence 1)
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
            "storage_key": storage_key
        },
        ip_address=get_client_ip(request),
        actor_id=owner_id or "system",
        actor_role=user_context.get("role", "investigator")
    )

    if async_mode:
        # Launch durable background processing with independent SessionLocal worker
        background_tasks.add_task(
            execute_media_pipeline_worker,
            analysis_id,
            local_path,
            file.filename,
            media_type,
            detected_mime,
            size_bytes,
            sha256_hash
        )
        return MediaDetectionResponse(
            project="SPECTRA",
            analysis_id=analysis_id,
            job_id=analysis_id,
            media_type=media_type,
            sha256=sha256_hash,
            file_size_bytes=size_bytes,
            classification="INCONCLUSIVE",
            confidence={"score": None, "interpretation": "Processing asynchronously"},
            ai_generation_assessment={"label": "UNCERTAIN"},
            capture_assessment={"label": "UNVERIFIED"},
            metadata_assessment={"metadata_present": False},
            processing_status="processing"
        )

    # Synchronous processing (default)
    return await execute_media_pipeline(
        analysis_id,
        local_path,
        file.filename,
        media_type,
        detected_mime,
        size_bytes,
        sha256_hash,
        db
    )


@router.get(
    "/analyze/{analysis_id}",
    response_model=MediaDetectionResponse,
    summary="Retrieve the status and detailed report of an analysis job"
)
async def get_analysis_status(
    analysis_id: str,
    user_context: Dict[str, Any] = Depends(get_current_user_context),
    db: Session = Depends(get_db)
):
    """
    Polls the status or retrieves the completed forensic report by analysis_id.
    Enforces object-level authorization.
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == str(analysis_id)).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID '{analysis_id}' not found."
        )

    # Object-level authorization
    enforce_job_ownership(job.user_id, user_context)

    if job.status == "completed" and job.final_report:
        return MediaDetectionResponse(**job.final_report)

    return MediaDetectionResponse(
        project="SPECTRA",
        analysis_id=job.id,
        job_id=job.id,
        media_type=job.media_type,
        sha256=job.sha256_hash,
        file_size_bytes=job.size_bytes,
        classification="INCONCLUSIVE",
        confidence={"score": None, "interpretation": f"Job status: {job.status}"},
        ai_generation_assessment={"label": "UNCERTAIN"},
        capture_assessment={"label": "UNVERIFIED"},
        metadata_assessment={"metadata_present": False},
        processing_status=job.status
    )


@router.get(
    "/health",
    response_model=DetectorHealthResponse,
    summary="Check detector pipeline and dependency availability"
)
async def detector_health():
    """
    Reports the operational health of all media detection pipelines and underlying forensic tools.
    """
    detectors = []

    # 1. Image Pipeline & Pillow
    detectors.append(DetectorHealthItem(
        name="ImageDetectionService",
        category="image",
        status="available",
        version=f"Pillow-{PIL.__version__}",
        details="Error Level Analysis, PRNU spatial residuals, and bounded patch scanning active."
    ))

    # 2. Audio Pipeline & FFmpeg
    ffmpeg_bin = VideoDetectionService.get_ffmpeg_binary()
    detectors.append(DetectorHealthItem(
        name="AudioDetectionService",
        category="audio",
        status="available" if ffmpeg_bin else "degraded",
        version="FFmpeg-v7.1" if ffmpeg_bin else "wave-stdlib-only",
        details="Acoustic spectral roll-off, neural vocoder cutoff detection, and ZCR cadence active."
    ))

    # 3. Video Pipeline
    detectors.append(DetectorHealthItem(
        name="VideoDetectionService",
        category="video",
        status="available" if ffmpeg_bin else "degraded",
        version="FFmpeg-v7.1" if ffmpeg_bin else "unavailable",
        details="Bounded frame sampling (4-16 frames), inter-frame motion residuals, and independent audio analysis."
    ))

    # 4. Provenance & ExifTool
    exiftool_bin = resolve_binary("exiftool")
    detectors.append(DetectorHealthItem(
        name="ProvenanceAndMakerNoteService",
        category="provenance",
        status="available" if exiftool_bin else "degraded",
        version="ExifTool-13.x" if exiftool_bin else "basic-exif",
        details="18-manufacturer MakerNote decoders, C2PA JUMBF inspector, and generative tag parser."
    ))

    all_healthy = all(d.status == "available" for d in detectors)

    return DetectorHealthResponse(
        status="healthy" if all_healthy else "degraded",
        detectors=detectors,
        supported_media_types=["image", "audio", "video"]
    )
