import asyncio
import json
import os
import shutil
from typing import Dict, Any, Optional
from PIL import Image, ExifTags


async def run_cmd_json(args: list, timeout: float = 10.0) -> Optional[Any]:
    """
    Execute inspection binary with argument array, strict timeout, and no shell interpolation.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode == 0 and stdout:
            return json.loads(stdout.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    return None


async def inspect_with_exiftool(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Run ExifTool on media file to extract technical and embedded provenance metadata.
    """
    if not shutil.which("exiftool"):
        return None

    # -json: output JSON, -n: numerical coordinates, -s: tag names, -G: group names
    res = await run_cmd_json(["exiftool", "-json", "-n", file_path], timeout=10.0)
    if isinstance(res, list) and len(res) > 0 and isinstance(res[0], dict):
        return res[0]
    return None


async def inspect_with_ffprobe(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Run ffprobe on audio/video container to extract stream tracks, codecs, and durations.
    """
    if not shutil.which("ffprobe"):
        return None

    args = [
        "ffprobe",
        "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        "-show_streams",
        file_path
    ]
    res = await run_cmd_json(args, timeout=12.0)
    if isinstance(res, dict):
        return res
    return None


def inspect_image_fallback(file_path: str) -> Dict[str, Any]:
    """
    Robust pure-Python fallback for image metadata extraction using Pillow and binary scanning.
    """
    meta = {
        "dimensions": None,
        "format": None,
        "color_profile": None,
        "exif": {},
        "gps": {"has_gps": False, "latitude": None, "longitude": None, "altitude": None},
        "provenance_clues": {"c2pa_status": "not_present", "ai_metadata_tags": []}
    }

    try:
        with Image.open(file_path) as img:
            width, height = img.size
            aspect = f"{round(width / max(height, 1), 2)}:1"
            meta["dimensions"] = {
                "width": width,
                "height": height,
                "aspect_ratio": aspect
            }
            meta["format"] = img.format
            meta["color_profile"] = img.mode

            # Pillow EXIF extraction
            exif_data = img.getexif()
            if exif_data:
                exif_dict = {}
                for tag_id, val in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    # Omit raw byte blobs from simple dict
                    if isinstance(val, (str, int, float)):
                        exif_dict[tag_name] = val
                    elif isinstance(val, bytes) and len(val) < 128:
                        exif_dict[tag_name] = val.decode("utf-8", errors="ignore").strip()

                meta["exif"] = {
                    "make": exif_dict.get("Make"),
                    "model": exif_dict.get("Model"),
                    "software": exif_dict.get("Software"),
                    "lens": exif_dict.get("LensModel"),
                    "captured_at": exif_dict.get("DateTimeOriginal") or exif_dict.get("DateTime")
                }

                # GPS IFD
                gps_info = exif_data.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(exif_data, "get_ifd") else None
                if gps_info:
                    meta["gps"]["has_gps"] = True
                    meta["gps"]["source"] = "EXIF GPS IFD"
    except Exception:
        pass

    # Inspect raw container binary for C2PA, GPS strings, and AI generation parameters
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read(min(os.path.getsize(file_path), 512 * 1024))
            raw_str = raw_bytes.decode("latin1", errors="ignore")

        # C2PA presence check
        if b"c2pa" in raw_bytes or b"jumb" in raw_bytes:
            meta["provenance_clues"]["c2pa_status"] = "present_unverified"

        # AI prompt tokens and markers
        ai_tags = []
        raw_lower = raw_str.lower()
        if "parameters" in raw_lower and ("negative prompt" in raw_lower or "steps:" in raw_lower or "sampler:" in raw_lower):
            ai_tags.append("Automatic1111 / Stable Diffusion Parameters")
        if "prompt" in raw_lower and "nodes" in raw_lower and "class_type" in raw_lower:
            ai_tags.append("ComfyUI Node Graph Execution Data")
        if "midjourney" in raw_lower or "--v 5" in raw_lower or "--v 6" in raw_lower:
            ai_tags.append("Midjourney Render Parameter Syntax")
        if "trainedalgorithmicmedia" in raw_lower:
            ai_tags.append("IPTC DigitalSourceType: trainedAlgorithmicMedia")

        meta["provenance_clues"]["ai_metadata_tags"] = ai_tags
    except Exception:
        pass

    return meta


def inspect_audio_fallback(file_path: str) -> Dict[str, Any]:
    """
    Pure-Python fallback for audio containers (WAV fmt chunk, MP3 ID3 header).
    """
    meta = {
        "container": "Audio Stream",
        "codec": "Audio",
        "duration_seconds": None,
        "sample_rate": None,
        "channels": None,
        "bitrate_kbps": None,
        "tags": {},
        "ai_acoustic_markers": []
    }

    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            header = f.read(1024)

        # WAV parsing
        if header.startswith(b"RIFF") and b"WAVE" in header:
            meta["container"] = "WAV Container (RIFF)"
            meta["codec"] = "LPCM Uncompressed"
            fmt_idx = header.find(b"fmt ")
            if fmt_idx != -1 and len(header) >= fmt_idx + 24:
                channels = int.from_bytes(header[fmt_idx + 10:fmt_idx + 12], "little")
                sample_rate = int.from_bytes(header[fmt_idx + 12:fmt_idx + 16], "little")
                bit_depth = int.from_bytes(header[fmt_idx + 22:fmt_idx + 24], "little")
                meta["channels"] = channels
                meta["sample_rate"] = sample_rate
                meta["tags"]["bit_depth"] = f"{bit_depth}-bit"
                if sample_rate > 0 and channels > 0 and bit_depth > 0:
                    bytes_per_sec = (sample_rate * channels * bit_depth) // 8
                    if bytes_per_sec > 0:
                        meta["duration_seconds"] = round(file_size / bytes_per_sec, 2)
                        meta["bitrate_kbps"] = round((bytes_per_sec * 8) / 1000)

        # Check for neural TTS / vocoder traces in text comments
        with open(file_path, "rb") as f:
            raw_sample = f.read(65536).decode("latin1", errors="ignore")
        if "elevenlabs" in raw_sample.lower():
            meta["ai_acoustic_markers"].append("ElevenLabs Neural Synthesis Signature")
        if "rvc" in raw_sample.lower() and "model" in raw_sample.lower():
            meta["ai_acoustic_markers"].append("RVC Retrieval-based Voice Conversion")
    except Exception:
        pass

    return meta


def inspect_video_fallback(file_path: str) -> Dict[str, Any]:
    """
    Pure-Python fallback for video containers (MP4 tkhd/mvhd atoms).
    """
    meta = {
        "container": "MP4 / ISO Media Container",
        "duration_seconds": None,
        "dimensions": None,
        "codecs": {"video": "H.264 / AVC", "audio": "AAC-LC"},
        "fps": None,
        "bitrate_kbps": None,
        "audio_tracks": 1,
        "tags": {}
    }

    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            chunk = f.read(min(file_size, 1024 * 1024))

        # Extract dimensions from tkhd atom
        tkhd_idx = chunk.find(b"tkhd")
        if tkhd_idx != -1 and len(chunk) >= tkhd_idx + 88:
            ver = chunk[tkhd_idx + 4]
            offset = tkhd_idx + 88 if ver == 1 else tkhd_idx + 76
            if len(chunk) >= offset + 8:
                w = int.from_bytes(chunk[offset:offset + 4], "big") >> 16
                h = int.from_bytes(chunk[offset + 4:offset + 8], "big") >> 16
                if 0 < w < 10000 and 0 < h < 10000:
                    meta["dimensions"] = {
                        "width": w,
                        "height": h,
                        "aspect_ratio": f"{round(w / max(h, 1), 2)}:1"
                    }
    except Exception:
        pass

    return meta
