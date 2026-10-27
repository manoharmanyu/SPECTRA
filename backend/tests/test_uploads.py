import io
import pytest


def test_upload_valid_image(client, sample_jpeg_bytes):
    session_res = client.post("/api/v1/device-sessions", json={"device_name": "Field Mobile"})
    session_id = session_res.json()["capture_session_id"]

    files = {"file": ("camera_photo.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    data = {
        "capture_session_id": session_id,
        "source_origin": "phone_simulator",
        "source_device_id": "dev_phone_123"
    }

    res = client.post("/api/v1/analyses", files=files, data=data)
    assert res.status_code == 202
    resp_data = res.json()
    assert "job_id" in resp_data
    assert resp_data["status"] == "queued"
    assert resp_data["media_type"] == "image"
    assert resp_data["status_url"].endswith(resp_data["job_id"])
    assert resp_data["report_url"].endswith("/report")

    # Verify session association
    list_res = client.get(f"/api/v1/device-sessions/{session_id}/analyses")
    assert list_res.status_code == 200
    analyses = list_res.json()
    assert len(analyses) == 1
    assert analyses[0]["job_id"] == resp_data["job_id"]
    assert analyses[0]["original_filename"] == "camera_photo.jpg"


def test_upload_valid_audio(client, sample_wav_bytes):
    files = {"file": ("audio_memo.wav", io.BytesIO(sample_wav_bytes), "audio/wav")}
    res = client.post("/api/v1/analyses", files=files)
    assert res.status_code == 202
    data = res.json()
    assert data["media_type"] == "audio"


def test_upload_valid_video(client, sample_mp4_bytes):
    files = {"file": ("security_stream.mp4", io.BytesIO(sample_mp4_bytes), "video/mp4")}
    res = client.post("/api/v1/analyses", files=files)
    assert res.status_code == 202
    data = res.json()
    assert data["media_type"] == "video"


def test_upload_empty_file_rejected(client):
    files = {"file": ("empty.jpg", io.BytesIO(b""), "image/jpeg")}
    res = client.post("/api/v1/analyses", files=files)
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


def test_upload_spoofed_mime_rejected(client):
    # Plain text file disguised as a JPEG
    fake_jpeg = b"This is clearly a text file with no JPEG magic bytes."
    files = {"file": ("spoofed.jpg", io.BytesIO(fake_jpeg), "image/jpeg")}
    res = client.post("/api/v1/analyses", files=files)
    assert res.status_code == 415
    assert "unsupported" in res.json()["detail"].lower() or "spoofed" in res.json()["detail"].lower()


def test_upload_status_and_report_polling(client, sample_jpeg_bytes):
    files = {"file": ("photo.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    res = client.post("/api/v1/analyses", files=files)
    job_id = res.json()["job_id"]

    # Poll status
    status_res = client.get(f"/api/v1/analyses/{job_id}")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["job_id"] == job_id
    assert status_data["status"] in ("queued", "processing", "completed")
    assert status_data["sha256"] is not None


def test_upload_oversized_file_rejected(client, monkeypatch):
    from app.config import settings
    # Temporarily set max upload limit to 100 bytes
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_BYTES", 100)

    oversized_data = b"\xff\xd8\xff\xe0" + (b"\x00" * 300)
    files = {"file": ("oversized.jpg", io.BytesIO(oversized_data), "image/jpeg")}
    res = client.post("/api/v1/analyses", files=files)
    assert res.status_code == 400
    assert "exceeds" in res.json()["detail"].lower()


def test_report_preserves_missing_metadata(client, sample_jpeg_bytes):
    # Upload JPEG without GPS or author tags
    files = {"file": ("minimal.jpg", io.BytesIO(sample_jpeg_bytes), "image/jpeg")}
    res = client.post("/api/v1/analyses", files=files)
    job_id = res.json()["job_id"]

    # Finalize via internal route
    from app.config import settings
    client.post(
        f"/internal/analyses/{job_id}/finalize",
        headers={"Authorization": f"Bearer {settings.SPECTRA_INTERNAL_TOKEN}"}
    )

    report_res = client.get(f"/api/v1/analyses/{job_id}/report")
    assert report_res.status_code == 200
    report = report_res.json()
    assert report["job_id"] == job_id
    # Metadata facts preserved; GPS is explicit false, not fabricated
    assert report["metadata"]["gps"]["has_gps"] is False
    assert report["metadata"]["gps"]["latitude"] is None
