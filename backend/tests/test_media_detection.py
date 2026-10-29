import io
import wave
import pytest
from PIL import Image, PngImagePlugin
import numpy as np


def create_test_jpeg_bytes(with_camera_exif: bool = True) -> bytes:
    """Create in-memory JPEG with or without camera EXIF."""
    img = Image.new("RGB", (128, 128), color=(73, 109, 137))
    buf = io.BytesIO()
    if with_camera_exif:
        exif = img.getexif()
        exif[0x010F] = "Apple"  # Make
        exif[0x0110] = "iPhone 15 Pro"  # Model
        exif[0x0131] = "17.4.1"  # Software
        img.save(buf, format="JPEG", exif=exif)
    else:
        img.save(buf, format="JPEG")
    return buf.getvalue()


def create_ai_png_bytes() -> bytes:
    """Create in-memory PNG with Stable Diffusion / ComfyUI metadata markers."""
    img = Image.new("RGB", (128, 128), color=(20, 20, 20))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("parameters", "cyberpunk street, neon rain, masterpiece, 8k\nSteps: 25, Sampler: DPM++ 2M Karras, CFG scale: 7, Seed: 14298129")
    meta.add_text("prompt", '{"3": {"class_type": "KSampler", "inputs": {"seed": 14298129, "steps": 25}}}')
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=meta)
    return buf.getvalue()


def create_test_wav_bytes(duration_sec: float = 2.0, sample_rate: int = 16000, is_silence: bool = False) -> bytes:
    """Create valid PCM WAV in-memory."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        n_samples = int(duration_sec * sample_rate)
        if is_silence:
            samples = np.zeros(n_samples, dtype=np.int16)
        else:
            # Synthetic human-like voice fundamental + harmonics (120Hz pitch + room noise)
            t = np.linspace(0, duration_sec, n_samples, endpoint=False)
            signal = (
                0.4 * np.sin(2 * np.pi * 120 * t) +
                0.25 * np.sin(2 * np.pi * 240 * t) +
                0.15 * np.sin(2 * np.pi * 360 * t) +
                0.05 * np.random.normal(0, 0.05, n_samples)
            )
            samples = (signal * 32767).astype(np.int16)
        wf.writeframes(samples.tobytes())
    return buf.getvalue()


def test_media_detection_health(client):
    """Test GET /api/v1/media/health reports available pipelines."""
    response = client.get("/api/v1/media/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "detectors" in data
    assert any(d["name"] == "ImageDetectionService" for d in data["detectors"])
    assert any(d["name"] == "AudioDetectionService" for d in data["detectors"])
    assert any(d["name"] == "VideoDetectionService" for d in data["detectors"])
    assert any(d["name"] == "ProvenanceAndMakerNoteService" for d in data["detectors"])


def test_analyze_camera_captured_image(client):
    """Test camera image with EXIF registers classified as LIKELY_CAMERA_CAPTURED."""
    jpeg_data = create_test_jpeg_bytes(with_camera_exif=True)
    files = {"file": ("camera_photo.jpg", jpeg_data, "image/jpeg")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["media_type"] == "image"
    assert data["classification"] in ["LIKELY_CAMERA_CAPTURED", "POSSIBLY_CAMERA_CAPTURED"]
    assert data["capture_assessment"]["device_evidence_found"] is True
    assert data["capture_assessment"]["sensor_make"] == "Apple"
    assert data["capture_assessment"]["sensor_model"] == "iPhone 15 Pro"
    assert len(data["evidence"]) > 0
    assert len(data["limitations"]) > 0


def test_analyze_ai_generated_image(client):
    """Test image with generative AI markers classified as LIKELY_AI_GENERATED."""
    ai_data = create_ai_png_bytes()
    files = {"file": ("synthetic_art.png", ai_data, "image/png")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["media_type"] == "image"
    assert data["classification"] == "LIKELY_AI_GENERATED"
    assert data["ai_generation_assessment"]["label"] == "SYNTHETIC"
    assert data["confidence"]["score"] >= 0.85
    assert any(e["source"] == "metadata_extraction" and "AI" in e["finding"] for e in data["evidence"])


def test_analyze_stripped_metadata_inconclusive(client):
    """Test image with stripped EXIF and ambiguous residuals is classified as INCONCLUSIVE."""
    plain_jpeg = create_test_jpeg_bytes(with_camera_exif=False)
    files = {"file": ("stripped_photo.jpg", plain_jpeg, "image/jpeg")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["media_type"] == "image"
    # Stripped metadata alone must NEVER be claimed as proof of AI generation
    assert data["classification"] in ["INCONCLUSIVE", "LIKELY_CAMERA_CAPTURED", "LIKELY_AI_GENERATED"]
    assert any("Missing EXIF does not indicate AI generation" in lim or "Metadata is not proof of origin" in lim for lim in data["limitations"])


def test_analyze_valid_audio(client):
    """Test audio recording with natural acoustic features classified properly."""
    wav_data = create_test_wav_bytes(duration_sec=2.0, is_silence=False)
    files = {"file": ("voice_note.wav", wav_data, "audio/wav")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["media_type"] == "audio"
    assert data["classification"] in ["LIKELY_CAMERA_CAPTURED", "POSSIBLY_EDITED_OR_MANIPULATED"]
    assert len(data["evidence"]) > 0


def test_analyze_short_audio_inconclusive(client):
    """Test audio under 1.0s is marked INCONCLUSIVE with duration limitation."""
    short_wav = create_test_wav_bytes(duration_sec=0.4, is_silence=False)
    files = {"file": ("short_chirp.wav", short_wav, "audio/wav")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["media_type"] == "audio"
    assert data["classification"] == "INCONCLUSIVE"
    assert any("too short" in lim for lim in data["limitations"])


def test_analyze_async_mode(client):
    """Test async_mode=True returns processing status and analysis_id."""
    jpeg_data = create_test_jpeg_bytes(with_camera_exif=True)
    files = {"file": ("async_photo.jpg", jpeg_data, "image/jpeg")}
    response = client.post("/api/v1/media/analyze?async_mode=true", files=files)
    assert response.status_code == 200
    data = response.json()
    assert "analysis_id" in data
    assert data["processing_status"] in ["processing", "completed"]

    # Poll status endpoint
    poll_res = client.get(f"/api/v1/media/analyze/{data['analysis_id']}")
    assert poll_res.status_code == 200
    poll_data = poll_res.json()
    assert poll_data["analysis_id"] == data["analysis_id"]


def test_analyze_spoofed_file_rejected(client):
    """Test text file spoofed with .jpg extension is rejected with 415."""
    fake_jpeg = b"This is plain text pretending to be a picture."
    files = {"file": ("malicious.jpg", fake_jpeg, "image/jpeg")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 415


def test_analyze_empty_file_rejected(client):
    """Test empty file is rejected with 400."""
    files = {"file": ("empty.png", b"", "image/png")}
    response = client.post("/api/v1/media/analyze", files=files)
    assert response.status_code == 400
