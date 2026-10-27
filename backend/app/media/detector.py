import os
from typing import Tuple

# Allowed Magic Bytes signatures
MAGIC_SIGNATURES = [
    # Images
    (b"\xff\xd8\xff", "image/jpeg", "image", [".jpg", ".jpeg"]),
    (b"\x89PNG\r\n\x1a\n", "image/png", "image", [".png"]),
    (b"RIFF", "image/webp", "image", [".webp"]),  # Verified with WEBP chunk
    (b"GIF87a", "image/gif", "image", [".gif"]),
    (b"GIF89a", "image/gif", "image", [".gif"]),
    (b"II*\x00", "image/tiff", "image", [".tif", ".tiff"]),
    (b"MM\x00*", "image/tiff", "image", [".tif", ".tiff"]),
    (b"BM", "image/bmp", "image", [".bmp"]),
    # Audio
    (b"RIFF", "audio/wav", "audio", [".wav"]),  # Verified with WAVE chunk
    (b"ID3", "audio/mpeg", "audio", [".mp3"]),
    (b"\xff\xfb", "audio/mpeg", "audio", [".mp3"]),
    (b"\xff\xf3", "audio/mpeg", "audio", [".mp3"]),
    (b"\xff\xf2", "audio/mpeg", "audio", [".mp3"]),
    (b"fLaC", "audio/flac", "audio", [".flac"]),
    (b"OggS", "audio/ogg", "audio", [".ogg", ".oga"]),
    # Video / Containers (ftyp at offset 4)
    (b"ftyp", "video/mp4", "video", [".mp4", ".m4v", ".mov"]),
    (b"\x1a\x45\xdf\xa3", "video/webm", "video", [".webm", ".mkv"]),
]


def detect_media_signature(file_path: str, original_filename: str) -> Tuple[str, str]:
    """
    Validate actual file signatures/magic bytes, allowed types, and supported extensions.
    Returns: (media_type, detected_mime_type) where media_type in ('image', 'audio', 'video').
    Raises: ValueError for invalid, spoofed, or unsupported media types.
    """
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        raise ValueError("Uploaded file is missing or empty (0 bytes).")

    ext = os.path.splitext(original_filename)[1].lower()

    with open(file_path, "rb") as f:
        header = f.read(64)

    if len(header) < 4:
        raise ValueError("File header is too short to be a valid media container.")

    # 1. JPEG
    if header.startswith(b"\xff\xd8\xff"):
        if ext not in [".jpg", ".jpeg"]:
            raise ValueError(f"Spoofed file detected: JPEG signature does not match extension '{ext}'.")
        return "image", "image/jpeg"

    # 2. PNG
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        if ext != ".png":
            raise ValueError(f"Spoofed file detected: PNG signature does not match extension '{ext}'.")
        return "image", "image/png"

    # 3. RIFF containers (WebP or WAV)
    if header.startswith(b"RIFF") and len(header) >= 12:
        riff_type = header[8:12]
        if riff_type == b"WEBP":
            if ext != ".webp":
                raise ValueError(f"Spoofed file detected: WebP signature does not match extension '{ext}'.")
            return "image", "image/webp"
        if riff_type == b"WAVE":
            if ext != ".wav":
                raise ValueError(f"Spoofed file detected: WAV audio signature does not match extension '{ext}'.")
            return "audio", "audio/wav"

    # 4. GIF
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        if ext != ".gif":
            raise ValueError(f"Spoofed file detected: GIF signature does not match extension '{ext}'.")
        return "image", "image/gif"

    # 5. TIFF
    if header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        if ext not in [".tif", ".tiff"]:
            raise ValueError(f"Spoofed file detected: TIFF signature does not match extension '{ext}'.")
        return "image", "image/tiff"

    # 6. MP3
    if header.startswith(b"ID3") or (len(header) >= 2 and header[0] == 0xff and (header[1] & 0xe0) == 0xe0):
        if ext not in [".mp3", ".audio"]:
            raise ValueError(f"Spoofed file detected: MP3 audio signature does not match extension '{ext}'.")
        return "audio", "audio/mpeg"

    # 7. FLAC
    if header.startswith(b"fLaC"):
        if ext != ".flac":
            raise ValueError(f"Spoofed file detected: FLAC audio signature does not match extension '{ext}'.")
        return "audio", "audio/flac"

    # 8. OGG
    if header.startswith(b"OggS"):
        if ext in [".ogg", ".oga"]:
            return "audio", "audio/ogg"
        if ext in [".ogv"]:
            return "video", "video/ogg"
        return "audio", "audio/ogg"

    # 9. Matroska / WebM
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        if ext in [".webm", ".mkv"]:
            return "video", "video/webm"
        raise ValueError(f"Spoofed file detected: Matroska/WebM signature does not match extension '{ext}'.")

    # 10. ISO/IEC 14496 Containers (MP4, MOV, M4A, M4V)
    if len(header) >= 12 and header[4:8] == b"ftyp":
        major_brand = header[8:12].decode("ascii", errors="ignore").strip().lower()
        if major_brand in ["m4a", "m4b"]:
            return "audio", "audio/mp4"
        if ext in [".mp4", ".m4v", ".mov"]:
            return "video", "video/mp4"
        if ext in [".m4a"]:
            return "audio", "audio/mp4"
        # If extension is valid mp4/mov
        return "video", "video/mp4"

    raise ValueError(f"Unsupported or unverified media format. Signature did not match supported image, audio, or video formats.")
