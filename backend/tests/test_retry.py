import io
import pytest
from app.config import settings

VALID_TOKEN_HEADER = {"Authorization": f"Bearer {settings.SPECTRA_INTERNAL_TOKEN}"}


def test_retry_failed_job(client, sample_jpeg_bytes):
    # 1. Upload job
    files = {"file": ("retry_target.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    upload_res = client.post("/api/v1/analyses", files=files)
    job_id = upload_res.json()["job_id"]

    # 2. Mark as failed
    fail_res = client.post(
        f"/internal/analyses/{job_id}/failed",
        headers=VALID_TOKEN_HEADER,
        json={"error": "Simulated network timeout during webhook dispatch"}
    )
    assert fail_res.status_code == 200

    # 3. Retry job
    retry_res = client.post(f"/api/v1/analyses/{job_id}/retry")
    assert retry_res.status_code == 200
    assert retry_res.json()["status"] == "queued"

    # 4. Status reflects queued and cleared error
    status_res = client.get(f"/api/v1/analyses/{job_id}")
    assert status_res.status_code == 200
    assert status_res.json()["status"] in ("queued", "processing", "completed")
