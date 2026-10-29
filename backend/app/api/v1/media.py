import os
import time
import uuid
import shutil
from datetime import datetime, timezone
from typing import Optional
from fastapi import (
    APIRouter,
    UploadFile,
    File,
    Form,
    Query,
    Depends,
    HTTPException,
    BackgroundTasks,
    status
)
from sqlalchemy.orm import Session
import PIL
import numpy as np

from app.config import settings
from app.database import get_db
from app.models.analysis import AnalysisJob
from app.storage import get_storage
from app.media.detector import detect_media_signature
from app.media.inspector import inspect_with_exiftool
from app.media.pipelines.image import ImageDetectionService
from app.media.pipelines.audio import AudioDetectionService
from app.media.pipelines.video import VideoDetectionService
from app.media.fusion import EvidenceFusionEngine
from app.schemas.media_detection import (
    MediaDetectionResponse,
    DetectorHealthResponse,
    DetectorHealthItem
)

router = APIRouter(prefix="/api/v1/media", tags=["Media Detection Engine"])


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
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Multipart image, audio, or video file"),
    async_mode: bool = Query(False, description="Whether to execute asynchronously and return 202 status"),
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

    # Create AnalysisJob DB record
    job = AnalysisJob(
        id=analysis_id,
        source_origin="media_analyze_api",
        media_type=media_type,
        detected_mime_type=detected_mime,
        original_filename=file.filename,
        storage_key=storage_key,
        size_bytes=size_bytes,
        sha256_hash=sha256_hash,
        status="processing" if async_mode else "completed",
        created_at=datetime.now(timezone.utc)
    )
    db.add(job)
    db.commit()

    if async_mode:
        # Launch background processing
        background_tasks.add_task(
            execute_media_pipeline,
            analysis_id,
            local_path,
            file.filename,
            media_type,
            detected_mime,
            size_bytes,
            sha256_hash,
            db
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
async def get_analysis_status(analysis_id: str, db: Session = Depends(get_db)):
    """
    Polls the status or retrieves the completed forensic report by analysis_id.
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == str(analysis_id)).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID '{analysis_id}' not found."
        )

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
    exiftool_bin = shutil.which("exiftool") or (
        "/Users/manyugaddam/.local/bin/exiftool" if os.path.exists("/Users/manyugaddam/.local/bin/exiftool") else None
    )
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
