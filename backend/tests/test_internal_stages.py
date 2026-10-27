import io
import pytest
from app.config import settings

VALID_TOKEN_HEADER = {"Authorization": f"Bearer {settings.SPECTRA_INTERNAL_TOKEN}"}
INVALID_TOKEN_HEADER = {"Authorization": "Bearer bad_secret_token_12345"}


def test_internal_routes_token_protection(client, sample_jpeg_bytes):
    # Upload a job first
    files = {"file": ("test.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    upload_res = client.post("/api/v1/analyses", files=files)
    job_id = upload_res.json()["job_id"]

    url = f"/internal/analyses/{job_id}/metadata"

    # Missing token -> 401
    res_no_auth = client.post(url)
    assert res_no_auth.status_code == 401

    # Invalid token -> 403
    res_bad_auth = client.post(url, headers=INVALID_TOKEN_HEADER)
    assert res_bad_auth.status_code == 403

    # Valid token -> 200
    res_valid = client.post(url, headers=VALID_TOKEN_HEADER)
    assert res_valid.status_code == 200
    assert res_valid.json()["stage"] == "metadata"


def test_internal_stages_lifecycle_and_idempotency(client, sample_jpeg_bytes):
    # 1. Upload job
    files = {"file": ("inspection_photo.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    upload_res = client.post("/api/v1/analyses", files=files)
    job_id = upload_res.json()["job_id"]

    # 2. Stage 1: Metadata
    meta_res1 = client.post(f"/internal/analyses/{job_id}/metadata", headers=VALID_TOKEN_HEADER)
    assert meta_res1.status_code == 200
    meta_data1 = meta_res1.json()
    assert meta_data1["stage"] == "metadata"

    # Idempotent re-run
    meta_res2 = client.post(f"/internal/analyses/{job_id}/metadata", headers=VALID_TOKEN_HEADER)
    assert meta_res2.status_code == 200
    assert meta_res2.json()["data"] == meta_data1["data"]

    # 3. Stage 2: Detect
    detect_res1 = client.post(f"/internal/analyses/{job_id}/detect", headers=VALID_TOKEN_HEADER)
    assert detect_res1.status_code == 200
    detect_data1 = detect_res1.json()
    assert detect_data1["stage"] == "detect"

    # Idempotent re-run
    detect_res2 = client.post(f"/internal/analyses/{job_id}/detect", headers=VALID_TOKEN_HEADER)
    assert detect_res2.status_code == 200
    assert detect_res2.json()["data"] == detect_data1["data"]

    # 4. Stage 3: Finalize
    final_res1 = client.post(f"/internal/analyses/{job_id}/finalize", headers=VALID_TOKEN_HEADER)
    assert final_res1.status_code == 200
    report = final_res1.json()["data"]["report"]
    assert report["status"] == "completed"
    assert report["assessment"]["label"] in ("likely_ai_generated", "likely_not_ai_detected", "inconclusive", "not_assessed")
    assert "limitations" in report
    assert len(report["limitations"]) > 0

    # Idempotent re-run
    final_res2 = client.post(f"/internal/analyses/{job_id}/finalize", headers=VALID_TOKEN_HEADER)
    assert final_res2.status_code == 200
    assert final_res2.json()["data"]["report"]["job_id"] == job_id


def test_internal_failed_stage(client, sample_jpeg_bytes):
    files = {"file": ("fail_test.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    upload_res = client.post("/api/v1/analyses", files=files)
    job_id = upload_res.json()["job_id"]

    res = client.post(
        f"/internal/analyses/{job_id}/failed",
        headers=VALID_TOKEN_HEADER,
        json={"error": "Decoder memory threshold exceeded in n8n worker", "stage": "decode"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "failed"

    # Verify status report reflects failure
    status_res = client.get(f"/api/v1/analyses/{job_id}")
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "failed"
    assert "Decoder memory" in status_res.json()["error_message"]
