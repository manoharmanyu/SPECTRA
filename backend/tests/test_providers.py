import io
import pytest
from app.providers.hive import HiveProvider
from app.config import settings

VALID_TOKEN_HEADER = {"Authorization": f"Bearer {settings.SPECTRA_INTERNAL_TOKEN}"}


@pytest.mark.asyncio
async def test_hive_provider_unconfigured():
    # Ensure HIVE_API_KEY is None
    settings.HIVE_API_KEY = None
    provider = HiveProvider()
    result = await provider.detect("dummy_path.jpg", "image", {})
    assert result.status == "not_assessed"
    assert result.score is None
    assert "not configured" in result.reason.lower()


@pytest.mark.asyncio
async def test_hive_provider_timeout_handling(tmp_path, monkeypatch):
    import httpx
    settings.HIVE_API_KEY = "test_hive_key_12345"

    dummy_file = tmp_path / "test_timeout.jpg"
    dummy_file.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 32 + b"\xff\xd9")

    async def mock_post(*args, **kwargs):
        raise httpx.TimeoutException("Timed out connecting to Hive")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    provider = HiveProvider()
    result = await provider.detect(str(dummy_file), "image", {})
    assert result.status == "failed"
    assert "timed out" in result.reason.lower()


def test_ai_synthetic_metadata_detection(client, sample_ai_jpeg_bytes):
    # Upload JPEG with Stable Diffusion / ComfyUI parameters
    files = {"file": ("ai_render.jpg", io.BytesIO(sample_ai_jpeg_bytes), "image/jpeg")}
    upload_res = client.post("/api/v1/analyses", files=files)
    job_id = upload_res.json()["job_id"]

    # Finalize
    final_res = client.post(f"/internal/analyses/{job_id}/finalize", headers=VALID_TOKEN_HEADER)
    assert final_res.status_code == 200
    report = final_res.json()["data"]["report"]

    assert report["assessment"]["label"] == "likely_ai_generated"
    assert "synthetic" in report["assessment"]["explanation"].lower() or "prompt" in report["assessment"]["explanation"].lower()
