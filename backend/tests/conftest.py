import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.config import settings
from app.database import Base, get_db

TEST_DATABASE_URL = "sqlite:///./test_spectra.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_spectra.db"):
        try:
            os.remove("./test_spectra.db")
        except OSError:
            pass


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_jpeg_bytes():
    # Valid JPEG magic bytes + minimal frame
    header = bytes([
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
        0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00
    ])
    exif = b"Make\x00Apple\x00Model\x00iPhone 15 Pro\x00"
    payload = b"\x00" * 256
    eoi = bytes([0xff, 0xd9])
    return header + exif + payload + eoi


@pytest.fixture
def sample_ai_jpeg_bytes():
    header = bytes([
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
        0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00
    ])
    prompt = b"parameters: cinematic portrait, realistic lighting, steps: 30, sampler: DPM++ 2M, seed: 123456"
    payload = b"\x00" * 256
    eoi = bytes([0xff, 0xd9])
    return header + prompt + payload + eoi


@pytest.fixture
def sample_wav_bytes():
    # Valid 44.1kHz Stereo 16-bit WAV header
    riff = bytes([
        0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
        0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
        0x44, 0xac, 0x00, 0x00, 0x10, 0xb1, 0x02, 0x00, 0x04, 0x00, 0x10, 0x00,
        0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00
    ])
    return riff + (b"\x12" * 512)


@pytest.fixture
def sample_mp4_bytes():
    # Valid ftyp mp42 ISO container
    ftyp = bytes([
        0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70,
        0x6d, 0x70, 0x34, 0x32, 0x00, 0x00, 0x00, 0x00,
        0x69, 0x73, 0x6f, 0x6d, 0x6d, 0x70, 0x34, 0x32
    ])
    moov = bytes([0x00, 0x00, 0x00, 0x08, 0x6d, 0x6f, 0x6f, 0x76])
    return ftyp + moov + (b"\x00" * 256)
