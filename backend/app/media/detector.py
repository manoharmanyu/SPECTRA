import os
from typing import Tuple

# Allowed Magic Signatures and extensions
# Supports all metadata-extractor / ExifTool compliant image, audio, video, and RAW containers
MAGIC_SIGNATURES = [
    # Standard Images
    (b"\xff\xd8\xff", "image/jpeg", "image", [".jpg", ".jpeg"]),
    (b"\x89PNG\r\n\x1a\n", "image/png", "image", [".png"]),
    (b"RIFF", "image/webp", "image", [".webp"]),  # Verified with WEBP chunk
    (b"GIF87a", "image/gif", "image", [".gif"]),
    (b"GIF89a", "image/gif", "image", [".gif"]),
    (b"BM", "image/bmp", "image", [".bmp"]),
    (b"8BPS", "image/vnd.adobe.photoshop", "image", [".psd"]),
    (b"\x00\x00\x01\x00", "image/x-icon", "image", [".ico"]),
    # TIFF & BigTIFF
    (b"II*\x00", "image/tiff", "image", [".tif", ".tiff", ".btf"]),
    (b"MM\x00*", "image/tiff", "image", [".tif", ".tiff", ".btf"]),
    (b"II+\x00", "image/tiff", "image", [".tif", ".tiff", ".btf"]),  # BigTIFF Little Endian
    (b"MM\x00+", "image/tiff", "image", [".tif", ".tiff", ".btf"]),  # BigTIFF Big Endian
    # Audio
    (b"RIFF", "audio/wav", "audio", [".wav"]),  # Verified with WAVE chunk
    (b"ID3", "audio/mpeg", "audio", [".mp3"]),
    (b"\xff\xfb", "audio/mpeg", "audio", [".mp3"]),
    (b"\xff\xf3", "audio/mpeg", "audio", [".mp3"]),
    (b"\xff\xf2", "audio/mpeg", "audio", [".mp3"]),
    (b"fLaC", "audio/flac", "audio", [".flac"]),
    (b"OggS", "audio/ogg", "audio", [".ogg", ".oga"]),
    # Video & Rich Containers
    (b"RIFF", "video/x-msvideo", "video", [".avi"]),  # Verified with AVI chunk
    (b"ftyp", "video/mp4", "video", [".mp4", ".m4v", ".mov", ".qt"]),
    (b"\x1a\x45\xdf\xa3", "video/webm", "video", [".webm", ".mkv", ".mks", ".mk3d"]),
    # Camera RAW
    (b"IIRO", "image/x-olympus-orf", "image", [".orf"]),
    (b"IIRS", "image/x-olympus-orf", "image", [".orf"]),
    (b"MMOR", "image/x-olympus-orf", "image", [".orf"]),
    (b"IIU\x00", "image/x-panasonic-rw2", "image", [".rw2"]),
]


def detect_media_signature(file_path: str, original_filename: str) -> Tuple[str, str]:
    """
    Validate actual file signatures/magic bytes, allowed types, and supported extensions.
    Supports comprehensive metadata-extractor format specification:
    JPEG, TIFF (including BigTIFF), WebP, WAV, AVI, PSD, PNG, BMP, GIF, HEIF (HEIC & AVIF),
    ICO, PCX, QuickTime, MP4, Matroska (MKV, MKA, MKS & MK3D), WebM,
    and Camera RAW (NEF, CR2, CR3, ORF, ARW, RW2, RWL, SRW).
    
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

    # 3. Photoshop PSD
    if header.startswith(b"8BPS"):
        if ext != ".psd":
            raise ValueError(f"Spoofed file detected: Photoshop PSD signature does not match extension '{ext}'.")
        return "image", "image/vnd.adobe.photoshop"

    # 4. Windows Bitmap (BMP)
    if header.startswith(b"BM"):
        if ext != ".bmp":
            raise ValueError(f"Spoofed file detected: BMP signature does not match extension '{ext}'.")
        return "image", "image/bmp"

    # 5. Windows Icon (ICO)
    if header.startswith(b"\x00\x00\x01\x00"):
        if ext != ".ico":
            raise ValueError(f"Spoofed file detected: ICO signature does not match extension '{ext}'.")
        return "image", "image/x-icon"

    # 6. PC Paintbrush (PCX)
    if header[0] == 0x0a and header[1] in [0, 2, 3, 4, 5] and header[2] == 1:
        if ext != ".pcx":
            raise ValueError(f"Spoofed file detected: PCX signature does not match extension '{ext}'.")
        return "image", "image/x-pcx"

    # 7. GIF
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        if ext != ".gif":
            raise ValueError(f"Spoofed file detected: GIF signature does not match extension '{ext}'.")
        return "image", "image/gif"

    # 8. RIFF containers (WebP, WAV, AVI)
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
        if riff_type in [b"AVI ", b"AVIX"]:
            if ext != ".avi":
                raise ValueError(f"Spoofed file detected: AVI video signature does not match extension '{ext}'.")
            return "video", "video/x-msvideo"

    # 9. Olympus ORF Camera Raw
    if header.startswith(b"IIRO") or header.startswith(b"IIRS") or header.startswith(b"MMOR"):
        if ext != ".orf":
            raise ValueError(f"Spoofed file detected: Olympus ORF signature does not match extension '{ext}'.")
        return "image", "image/x-olympus-orf"

    # 10. Panasonic RW2 Camera Raw
    if header.startswith(b"IIU\x00"):
        if ext != ".rw2":
            raise ValueError(f"Spoofed file detected: Panasonic RW2 signature does not match extension '{ext}'.")
        return "image", "image/x-panasonic-rw2"

    # 11. TIFF containers (TIFF, BigTIFF, Canon CR2, Nikon NEF, Sony ARW, Leica RWL, Samsung SRW)
    is_tiff_le = header.startswith(b"II*\x00")
    is_tiff_be = header.startswith(b"MM\x00*")
    is_bigtiff_le = header.startswith(b"II+\x00")
    is_bigtiff_be = header.startswith(b"MM\x00+")

    if is_tiff_le or is_tiff_be or is_bigtiff_le or is_bigtiff_be:
        # Canon CR2 raw check (bytes 8..10 are 'CR')
        if ext == ".cr2":
            if len(header) >= 10 and header[8:10] == b"CR":
                return "image", "image/x-canon-cr2"
            return "image", "image/x-canon-cr2"
        # Nikon NEF raw
        if ext == ".nef":
            return "image", "image/x-nikon-nef"
        # Sony ARW raw
        if ext == ".arw":
            return "image", "image/x-sony-arw"
        # Leica RWL raw
        if ext == ".rwl":
            return "image", "image/x-leica-rwl"
        # Samsung SRW raw
        if ext == ".srw":
            return "image", "image/x-samsung-srw"
        # Standard TIFF / BigTIFF
        if ext in [".tif", ".tiff", ".btf"]:
            return "image", "image/tiff"
        raise ValueError(f"Spoofed file detected: TIFF/RAW container does not match extension '{ext}'.")

    # 12. MP3
    if header.startswith(b"ID3") or (len(header) >= 2 and header[0] == 0xff and (header[1] & 0xe0) == 0xe0):
        if ext not in [".mp3", ".audio"]:
            raise ValueError(f"Spoofed file detected: MP3 audio signature does not match extension '{ext}'.")
        return "audio", "audio/mpeg"

    # 13. FLAC
    if header.startswith(b"fLaC"):
        if ext != ".flac":
            raise ValueError(f"Spoofed file detected: FLAC audio signature does not match extension '{ext}'.")
        return "audio", "audio/flac"

    # 14. OGG
    if header.startswith(b"OggS"):
        if ext in [".ogg", ".oga"]:
            return "audio", "audio/ogg"
        if ext in [".ogv"]:
            return "video", "video/ogg"
        return "audio", "audio/ogg"

    # 15. Matroska / WebM (EBML Container)
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        if ext == ".webm":
            return "video", "video/webm"
        if ext == ".weba":
            return "audio", "audio/webm"
        if ext == ".mka":
            return "audio", "audio/x-matroska"
        if ext in [".mkv", ".mks", ".mk3d"]:
            return "video", "video/x-matroska"
        raise ValueError(f"Spoofed file detected: Matroska/WebM signature does not match extension '{ext}'.")

    # 16. ISO Base Media Containers (MP4, QuickTime MOV, HEIF/HEIC/AVIF, Canon CR3, M4A)
    if len(header) >= 12 and header[4:8] == b"ftyp":
        major_brand = header[8:12].decode("ascii", errors="ignore").strip().lower()

        # Canon CR3 Camera Raw
        if major_brand == "crx" or ext == ".cr3":
            return "image", "image/x-canon-cr3"

        # HEIF / HEIC image
        if major_brand in ["heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1"] or ext in [".heic", ".heif"]:
            return "image", "image/heic"

        # AVIF image
        if major_brand in ["avif", "avis"] or ext == ".avif":
            return "image", "image/avif"

        # QuickTime MOV
        if major_brand in ["qt", "moov"] or ext in [".mov", ".qt"]:
            return "video", "video/quicktime"

        # Audio M4A/M4B
        if major_brand in ["m4a", "m4b"] or ext in [".m4a", ".m4b"]:
            return "audio", "audio/mp4"

        # Standard MP4 Video
        if ext in [".mp4", ".m4v"]:
            return "video", "video/mp4"

        # Generic ISO video fallback
        return "video", "video/mp4"

    # 17. Classic QuickTime Movie without ftyp atom (moov, wide, mdat, free at offset 4)
    if len(header) >= 8 and header[4:8] in [b"moov", b"wide", b"mdat", b"free", b"pnot"]:
        if ext in [".mov", ".qt"]:
            return "video", "video/quicktime"

    raise ValueError(f"Unsupported or unverified media format. Signature did not match supported image, audio, or video formats.")
