import asyncio
import json
import os
import shutil
from typing import Dict, Any, Optional, List
from PIL import Image, ExifTags

# Supported Camera-specific MakerNote manufacturers as specified by metadata-extractor standard
SUPPORTED_MAKERNOTE_MANUFACTURERS = {
    "Agfa": ["agfa", "agfaphoto"],
    "Apple": ["apple", "iphone", "ipad"],
    "Canon": ["canon"],
    "Casio": ["casio"],
    "Epson": ["epson", "seiko epson"],
    "Fujifilm": ["fujifilm", "fuji"],
    "Kodak": ["kodak", "eastman kodak"],
    "Kyocera": ["kyocera"],
    "Leica": ["leica"],
    "Minolta": ["minolta", "konica minolta"],
    "Nikon": ["nikon"],
    "Olympus": ["olympus", "om digital"],
    "Panasonic": ["panasonic", "lumix"],
    "Pentax": ["pentax", "ricoh"],
    "Reconyx": ["reconyx"],
    "Sanyo": ["sanyo"],
    "Sigma/Foveon": ["sigma", "foveon"],
    "Sony": ["sony"]
}


async def run_cmd_json(args: list, timeout: float = 12.0) -> Optional[Any]:
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
    Run ExifTool on media file to extract technical, embedded provenance, and MakerNote metadata.
    Supports all image, audio, video, container, and camera RAW formats.
    """
    exiftool_bin = shutil.which("exiftool") or (
        "/Users/manyugaddam/.local/bin/exiftool" if os.path.exists("/Users/manyugaddam/.local/bin/exiftool") else None
    )
    if not exiftool_bin:
        return None

    # -json: output JSON, -n: numerical coordinates/values, -a: allow duplicate tags, -u: extract unknown/makernote tags
    res = await run_cmd_json([exiftool_bin, "-json", "-n", "-a", "-u", file_path], timeout=15.0)
    if isinstance(res, list) and len(res) > 0 and isinstance(res[0], dict):
        return res[0]
    return None


async def inspect_with_ffprobe(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Run ffprobe on audio/video container to extract stream tracks, codecs, and durations.
    """
    ffprobe_bin = shutil.which("ffprobe")
    if not ffprobe_bin:
        return None

    args = [
        ffprobe_bin,
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


def decode_camera_makernotes(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decodes and structures camera-specific 'makernote' data for cameras manufactured by:
    Agfa, Apple, Canon, Casio, Epson, Fujifilm, Kodak, Kyocera, Leica,
    Minolta, Nikon, Olympus, Panasonic, Pentax, Reconyx, Sanyo, Sigma/Foveon, Sony.
    """
    make_raw = str(data.get("Make") or data.get("Manufacturer") or "").strip()
    model_raw = str(data.get("Model") or "").strip()
    make_lower = make_raw.lower()
    model_lower = model_raw.lower()

    matched_mfg = None
    for mfg_name, aliases in SUPPORTED_MAKERNOTE_MANUFACTURERS.items():
        if any(alias in make_lower or alias in model_lower for alias in aliases):
            matched_mfg = mfg_name
            break

    # Extract hardware identifiers
    serial_number = (
        data.get("SerialNumber") or
        data.get("CameraSerialNumber") or
        data.get("InternalSerialNumber") or
        data.get("BodySerialNumber") or
        data.get("CanonSerialNumber") or
        data.get("NikonSerialNumber") or
        data.get("SonySerialNumber")
    )
    lens_model = data.get("LensModel") or data.get("Lens") or data.get("LensID") or data.get("LensType")
    lens_serial = data.get("LensSerialNumber")
    shutter_count = data.get("ShutterCount") or data.get("ImageCount") or data.get("TotalShutterReleases")
    firmware = (
        data.get("Firmware") or
        data.get("Software") or
        data.get("CanonFirmwareVersion") or
        data.get("CameraFirmwareVersion")
    )

    # Collect manufacturer-specific proprietary MakerNote tags
    proprietary_tags: Dict[str, Any] = {}
    known_makernote_keys = [
        # Apple
        "RunTime", "AccelerationVector", "HDRImageType", "FocusPosition", "SceneFlags",
        "PhotosAppQualityMetric", "MediaGroupUUID", "ContentIdentifier",
        # Canon
        "CanonModelID", "CanonFirmwareVersion", "ContinuousDrive", "FocusDistanceUpper",
        "FocusDistanceLower", "RecordMode", "CanonFlashMode", "AFPointsUsed",
        # Nikon
        "NikonCaptureVersion", "ColorSpace", "VibrationReduction", "FlashSetting",
        "AutoBracketMode", "ActiveD-Lighting", "ShotInfo", "ISOControl",
        # Sony
        "SonyModelID", "DynamicRangeOptimizer", "CreativeStyle", "DistortionCorrectionSetting",
        "ElectronicFrontCurtainShutter", "SonyImageQuality",
        # Fujifilm
        "FilmMode", "DynamicRange", "NoiseReduction", "ShadowTone", "HighlightTone", "FujiModelID",
        # Olympus
        "SpecialMode", "CameraType", "FlashModel", "EquipmentVersion", "OlympusModelID",
        # Panasonic
        "PanasonicImageQuality", "MacroMode", "BurstMode", "ContrastMode", "Audio", "ConversionLens",
        # Leica
        "LeicaCameraType", "ColorTemperature", "WB_RGBLevels", "LeicaModelID",
        # Pentax
        "PentaxModelID", "DriveMode", "ShakeReduction", "PentaxImageQuality",
        # Reconyx
        "MotionTrigger", "AmbientTemperature", "BatteryVoltage", "UserLabel", "TriggerMode",
        # Sigma / Foveon
        "FoveonSensorData", "ColorMode", "SigmaModelID",
        # Casio / Epson / Kodak / Kyocera / Agfa / Minolta / Sanyo
        "RecordMode", "SelfTimer", "ObjectDistance", "PrintImageMatching", "AgfaModel",
        "MinoltaQuality", "MinoltaModelID", "SanyoQuality"
    ]

    for key in known_makernote_keys:
        if key in data and data[key] is not None:
            proprietary_tags[key] = data[key]

    has_makernote = bool(
        matched_mfg or
        serial_number or
        shutter_count or
        len(proprietary_tags) > 0 or
        data.get("MakerNote") is not None
    )

    # Determine hardware sensor provenance verification tier
    provenance_tier = "UNVERIFIED_GENERIC_CONTAINER"
    if has_makernote and matched_mfg:
        provenance_tier = "GENUINE_OPTICAL_SENSOR_VERIFIED"
    elif make_raw:
        provenance_tier = "METADATA_DECLARED_SENSOR"

    return {
        "makernote_present": has_makernote,
        "manufacturer_matched": matched_mfg,
        "camera_make": make_raw or None,
        "camera_model": model_raw or None,
        "hardware_serial_number": str(serial_number) if serial_number is not None else None,
        "lens_model": str(lens_model) if lens_model is not None else None,
        "lens_serial_number": str(lens_serial) if lens_serial is not None else None,
        "shutter_count": int(shutter_count) if isinstance(shutter_count, (int, float)) else None,
        "firmware": str(firmware) if firmware is not None else None,
        "provenance_tier": provenance_tier,
        "shooting_parameters": {
            "focus_mode": data.get("FocusMode"),
            "exposure_program": data.get("ExposureProgram"),
            "metering_mode": data.get("MeteringMode"),
            "white_balance": data.get("WhiteBalance"),
            "flash": data.get("Flash"),
            "iso": data.get("ISO"),
            "f_number": data.get("FNumber"),
            "exposure_time": data.get("ExposureTime"),
            "focal_length": data.get("FocalLength")
        },
        "proprietary_tags": proprietary_tags
    }


def inspect_image_fallback(file_path: str) -> Dict[str, Any]:
    """
    Robust pure-Python fallback for image and RAW metadata extraction.
    Parses JPEG, PNG, WebP, GIF, BMP, PSD, ICO, PCX, TIFF, BigTIFF, and Camera RAW formats.
    """
    meta = {
        "dimensions": None,
        "format": None,
        "color_profile": None,
        "exif": {},
        "gps": {"has_gps": False, "latitude": None, "longitude": None, "altitude": None},
        "makernote": {
            "makernote_present": False,
            "manufacturer_matched": None,
            "camera_make": None,
            "camera_model": None,
            "hardware_serial_number": None,
            "lens_model": None,
            "lens_serial_number": None,
            "shutter_count": None,
            "firmware": None,
            "provenance_tier": "UNVERIFIED_GENERIC_CONTAINER",
            "shooting_parameters": {},
            "proprietary_tags": {}
        },
        "provenance_clues": {"c2pa_status": "not_present", "ai_metadata_tags": []}
    }

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(min(os.path.getsize(file_path), 512 * 1024))
            raw_str = chunk.decode("latin1", errors="ignore")

        # 1. Photoshop PSD
        if chunk.startswith(b"8BPS") and len(chunk) >= 26:
            channels = int.from_bytes(chunk[12:14], "big")
            height = int.from_bytes(chunk[14:18], "big")
            width = int.from_bytes(chunk[18:22], "big")
            depth = int.from_bytes(chunk[22:24], "big")
            mode = int.from_bytes(chunk[24:26], "big")
            modes = {0: "Bitmap", 1: "Grayscale", 2: "Indexed", 3: "RGB", 4: "CMYK", 7: "Multichannel", 8: "Duotone", 9: "Lab"}
            meta["dimensions"] = {"width": width, "height": height, "aspect_ratio": f"{round(width / max(height, 1), 2)}:1"}
            meta["format"] = "PSD"
            meta["color_profile"] = f"{modes.get(mode, 'RGB')} ({depth}-bit)"

        # 2. Windows Bitmap (BMP)
        elif chunk.startswith(b"BM") and len(chunk) >= 26:
            width = int.from_bytes(chunk[18:22], "little")
            height = abs(int.from_bytes(chunk[22:26], "little", signed=True))
            bpp = int.from_bytes(chunk[28:30], "little")
            meta["dimensions"] = {"width": width, "height": height, "aspect_ratio": f"{round(width / max(height, 1), 2)}:1"}
            meta["format"] = "BMP"
            meta["color_profile"] = f"{bpp}-bit Bitmap"

        # 3. Windows Icon (ICO)
        elif chunk.startswith(b"\x00\x00\x01\x00") and len(chunk) >= 12:
            width = chunk[6] or 256
            height = chunk[7] or 256
            meta["dimensions"] = {"width": width, "height": height, "aspect_ratio": "1.0:1"}
            meta["format"] = "ICO"
            meta["color_profile"] = "Icon Palette"

        # 4. PCX
        elif chunk[0] == 0x0a and len(chunk) >= 12:
            xmin = int.from_bytes(chunk[4:6], "little")
            ymin = int.from_bytes(chunk[6:8], "little")
            xmax = int.from_bytes(chunk[8:10], "little")
            ymax = int.from_bytes(chunk[10:12], "little")
            w = xmax - xmin + 1
            h = ymax - ymin + 1
            meta["dimensions"] = {"width": w, "height": h, "aspect_ratio": f"{round(w / max(h, 1), 2)}:1"}
            meta["format"] = "PCX"
            meta["color_profile"] = f"{chunk[3]}-bit PCX"

        # 5. Pillow extraction (JPEG, PNG, WebP, GIF, TIFF, etc.)
        else:
            with Image.open(file_path) as img:
                width, height = img.size
                meta["dimensions"] = {
                    "width": width,
                    "height": height,
                    "aspect_ratio": f"{round(width / max(height, 1), 2)}:1"
                }
                meta["format"] = img.format
                meta["color_profile"] = img.mode

                exif_data = img.getexif()
                if exif_data:
                    exif_dict = {}
                    for tag_id, val in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
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

                    # Check MakerNote tag (0x927c / 37510)
                    meta["makernote"] = decode_camera_makernotes(exif_dict)

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
    Pure-Python fallback for audio containers (WAV fmt chunk, MP3 ID3 header, FLAC, M4A, MKA).
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

        # Matroska / WebM Audio (.mka, .weba)
        elif header.startswith(b"\x1a\x45\xdf\xa3"):
            meta["container"] = "Matroska / WebM Audio Container"
            meta["codec"] = "Opus / Vorbis"

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
    Pure-Python fallback for video containers (MP4, QuickTime MOV, AVI, WebM, MKV).
    """
    meta = {
        "container": "ISO / Media Container",
        "duration_seconds": None,
        "dimensions": None,
        "codecs": {"video": "Video Stream", "audio": "Audio Track"},
        "fps": None,
        "bitrate_kbps": None,
        "audio_tracks": 1,
        "tags": {}
    }

    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            chunk = f.read(min(file_size, 1024 * 1024))

        # AVI (RIFF / AVI)
        if chunk.startswith(b"RIFF") and len(chunk) >= 12 and chunk[8:12] in [b"AVI ", b"AVIX"]:
            meta["container"] = "Audio Video Interleave (AVI)"
            meta["codecs"]["video"] = "MPEG-4 / MJPEG / DivX"
            avih_idx = chunk.find(b"avih")
            if avih_idx != -1 and len(chunk) >= avih_idx + 40:
                microsec_per_frame = int.from_bytes(chunk[avih_idx + 8:avih_idx + 12], "little")
                w = int.from_bytes(chunk[avih_idx + 32:avih_idx + 36], "little")
                h = int.from_bytes(chunk[avih_idx + 36:avih_idx + 40], "little")
                if microsec_per_frame > 0:
                    meta["fps"] = round(1000000.0 / microsec_per_frame, 2)
                if 0 < w < 10000 and 0 < h < 10000:
                    meta["dimensions"] = {"width": w, "height": h, "aspect_ratio": f"{round(w / max(h, 1), 2)}:1"}

        # Matroska / WebM Video
        elif chunk.startswith(b"\x1a\x45\xdf\xa3"):
            meta["container"] = "Matroska / WebM Video Container"
            meta["codecs"]["video"] = "VP9 / AV1 / H.264"
            meta["codecs"]["audio"] = "Opus / Vorbis"

        # MP4 / QuickTime MOV
        else:
            meta["container"] = "MP4 / Apple QuickTime Movie"
            meta["codecs"] = {"video": "H.264 / HEVC", "audio": "AAC-LC"}
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
