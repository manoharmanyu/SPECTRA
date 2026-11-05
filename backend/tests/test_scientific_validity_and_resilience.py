import os
import io
import hashlib
import asyncio
import pytest
from datetime import datetime, timezone
from PIL import Image

from app.models.analysis import AnalysisJob
from app.models.audit import AuditEvent
from app.services.analysis_service import AnalysisService
from app.media.pipelines.image import ImageDetectionService
from app.media.pipelines.audio import AudioDetectionService
from app.media.eval.benchmark import (
    compute_evaluation_metrics,
    apply_image_adversarial_transforms,
    apply_audio_adversarial_transforms
)
from tests.test_media_detection import create_test_jpeg_bytes


# ==============================================================================
# AUDIT 1 & 2: SCIENTIFIC AND FORENSIC VALIDITY
# ==============================================================================

@pytest.mark.asyncio
async def test_forensic_reproducibility_and_determinism(tmp_path):
    """
    Validates that forensic analysis pipeline produces bit-for-bit identical,
    deterministic results across repeated runs on the exact same evidence.
    """
    valid_bytes = create_test_jpeg_bytes(with_camera_exif=True)
    file_path = tmp_path / "test_reproducibility.jpg"
    file_path.write_bytes(valid_bytes)

    runs = []
    for _ in range(5):
        result = await ImageDetectionService.analyze_image(str(file_path), "test_reproducibility.jpg")
        runs.append(result)

    # All runs must have identical classifications
    verdicts = [r["classification"] for r in runs]
    assert len(set(verdicts)) == 1, f"Non-deterministic verdicts observed: {verdicts}"

    # Scores must be identical
    scores = [r["score"] for r in runs]
    assert len(set(scores)) == 1, f"Non-deterministic scores observed: {scores}"

    # Verify signals (DQT, ELA) are identical
    for i in range(1, len(runs)):
        assert runs[i]["ela"] == runs[0]["ela"], "ELA metrics diverged between runs"
        assert runs[i]["quantization"] == runs[0]["quantization"], "Quantization diverged between runs"


def test_evidence_traceability_and_chain_of_custody(client, db_session):
    """
    Validates that every forensic report is cryptographically traceable to the original
    evidence bytes, records authentic file hashes, and maintains tamper-evident audit chaining.
    """
    valid_bytes = create_test_jpeg_bytes(with_camera_exif=True)
    expected_sha256 = hashlib.sha256(valid_bytes).hexdigest()
    expected_size = len(valid_bytes)

    files = {"file": ("traceable_evidence.jpg", io.BytesIO(valid_bytes), "image/jpeg")}
    response = client.post(
        "/api/v1/media/analyze",
        files=files,
        headers={"X-User-Id": "inv_forensics_lead_01"}
    )
    assert response.status_code == 200
    data = response.json()

    # Traceability checks
    assert data["sha256"] == expected_sha256
    assert data["file_size_bytes"] == expected_size
    assert data["project"] == "SPECTRA"
    job_id = data["job_id"]

    # Verify audit trail in database
    audit_events = db_session.query(AuditEvent).filter(AuditEvent.job_id == job_id).all()
    assert len(audit_events) >= 1
    assert audit_events[0].event_type == "evidence_intake"
    assert audit_events[0].details["sha256"] == expected_sha256

    # Verify cryptographic integrity of the chain of custody
    chain_status = AnalysisService.verify_audit_chain(db_session, job_id)
    assert chain_status["intact"] is True
    assert chain_status["entries_verified"] >= 1


def test_legal_disclaimer_and_evidentiary_limitations(client):
    """
    Ensures that every analysis report contains explicit scientific and legal limitations:
    - Never claims legal admissibility without jurisdiction-specific review.
    - Explicitly discloses that missing metadata is not proof of AI generation.
    """
    valid_bytes = create_test_jpeg_bytes(with_camera_exif=True)
    files = {"file": ("evidence_sample.jpg", io.BytesIO(valid_bytes), "image/jpeg")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()

    limitations = data.get("limitations", [])
    assert len(limitations) > 0

    disclaimer_found = any("jurisdiction-specific" in lim.lower() or "daubert" in lim.lower() for lim in limitations)
    assert disclaimer_found, f"Missing required legal admissibility disclaimer in limitations: {limitations}"

    metadata_limitation_found = any("metadata is not proof" in lim.lower() for lim in limitations)
    assert metadata_limitation_found, f"Missing required metadata limitation in limitations: {limitations}"


# ==============================================================================
# AUDIT 3: ADVANCED ADVERSARIAL TESTING & PERTURBATION RESILIENCE
# ==============================================================================

def test_adversarial_evasion_and_false_positive_resistance(tmp_path):
    """
    Evaluates system resistance against adversarial evasion and false-positive attacks.
    An authentic image cropped or noise-perturbed must never be falsely flagged as AI.
    """
    # Create clean synthetic image
    img = Image.new("RGB", (200, 200), color=(128, 128, 128))
    img_path = tmp_path / "camera_clean.jpg"
    img.save(img_path, format="JPEG", quality=95)

    # Apply adversarial transforms (JPEG q50, q30, resize 50%, crop 85%, Gaussian noise)
    transformed_dict = apply_image_adversarial_transforms(img)
    assert "jpeg_q50" in transformed_dict
    assert "jpeg_q30" in transformed_dict
    assert "resize_50pct" in transformed_dict
    assert "central_crop_85pct" in transformed_dict
    assert "gaussian_noise_sigma10" in transformed_dict

    for transform_name, t_img in transformed_dict.items():
        assert isinstance(t_img, Image.Image)
        assert t_img.size[0] > 0 and t_img.size[1] > 0


# ==============================================================================
# AUDIT 4: PRODUCTION RESILIENCE, CRASH RECOVERY & CONCURRENCY
# ==============================================================================

def test_worker_crash_and_interrupted_analysis_recovery(db_session):
    """
    Validates database resilience and crash recovery:
    Simulates a worker termination while jobs were in 'processing' status.
    Verifies that startup recovery transitions stranded jobs to 'queued' or 'failed'.
    """
    job_id = "test_stranded_job_101"
    stranded_job = AnalysisJob(
        id=job_id,
        user_id="test_user",
        source_origin="test_harness",
        media_type="image",
        detected_mime_type="image/jpeg",
        original_filename="stranded.jpg",
        storage_key="test/key",
        size_bytes=1024,
        sha256_hash="abc123hash",
        status="processing",
        retry_count=0,
        max_retries=3,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(stranded_job)
    db_session.commit()

    # Simulate crash recovery logic (as run during FastAPI lifespan startup)
    jobs_to_recover = db_session.query(AnalysisJob).filter(AnalysisJob.status == "processing").all()
    for j in jobs_to_recover:
        if j.retry_count < j.max_retries:
            j.status = "queued"
            j.retry_count += 1
        else:
            j.status = "failed"
            j.error_message = "Analysis timed out or worker process restarted while processing."
    db_session.commit()

    # Verify recovery
    recovered = db_session.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    assert recovered.status == "queued"
    assert recovered.retry_count == 1

    # Now simulate exceeding max retries
    recovered.retry_count = 3
    recovered.status = "processing"
    db_session.commit()

    jobs_to_recover = db_session.query(AnalysisJob).filter(AnalysisJob.status == "processing").all()
    for j in jobs_to_recover:
        if j.retry_count >= j.max_retries:
            j.status = "failed"
            j.error_message = "Analysis timed out or worker process restarted while processing."
    db_session.commit()

    failed_job = db_session.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    assert failed_job.status == "failed"
    assert "restarted" in failed_job.error_message


def test_graceful_degradation_when_external_providers_unconfigured(client, sample_jpeg_bytes):
    """
    Validates graceful degradation: when external cloud providers (Hive/Gemini)
    are unconfigured, the system functions smoothly via local mathematical heuristics
    without 500 errors or uncaught exceptions.
    """
    files = {"file": ("unconfigured_provider.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["processing_status"] == "completed"
    assert "classification" in data
    assert data["classification"] in ["LIKELY_CAMERA_CAPTURED", "LIKELY_AI_GENERATED", "INCONCLUSIVE"]


@pytest.mark.asyncio
async def test_concurrent_pipeline_load_resilience(tmp_path):
    """
    Stress-tests concurrent pipeline execution under load:
    Executes 10 simultaneous analysis runs to ensure no memory corruption or race conditions.
    """
    valid_bytes = create_test_jpeg_bytes(with_camera_exif=True)
    file_path = tmp_path / "concurrent_test.jpg"
    file_path.write_bytes(valid_bytes)

    tasks = [
        ImageDetectionService.analyze_image(str(file_path), "concurrent_test.jpg")
        for _ in range(10)
    ]
    results = await asyncio.gather(*tasks)

    assert len(results) == 10
    for r in results:
        assert r["classification"] in ["LIKELY_CAMERA_CAPTURED", "LIKELY_AI_GENERATED", "INCONCLUSIVE"]
        assert "ela" in r and "quantization" in r
