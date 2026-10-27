from typing import Dict, Any
from app.media.detector import detect_media_signature
from app.media.inspector import (
    inspect_with_exiftool,
    inspect_with_ffprobe,
    inspect_image_fallback,
    inspect_audio_fallback,
    inspect_video_fallback
)


async def extract_media_metadata(file_path: str, media_type: str, mime_type: str) -> Dict[str, Any]:
    """
    Extract technical metadata, stream metrics, and provenance clues using
    ExifTool / ffprobe with graceful native Python fallbacks.
    """
    if media_type == "image":
        exiftool_data = await inspect_with_exiftool(file_path)
        fallback = inspect_image_fallback(file_path)

        if exiftool_data:
            width = exiftool_data.get("ImageWidth") or fallback.get("dimensions", {}).get("width")
            height = exiftool_data.get("ImageHeight") or fallback.get("dimensions", {}).get("height")
            aspect = f"{round(width / max(height, 1), 2)}:1" if width and height else None

            # GPS Coordinates strictly if genuine
            has_gps = False
            lat = exiftool_data.get("GPSLatitude")
            lon = exiftool_data.get("GPSLongitude")
            alt = exiftool_data.get("GPSAltitude")
            if lat is not None and lon is not None:
                has_gps = True

            return {
                "dimensions": {"width": width, "height": height, "aspect_ratio": aspect} if width else fallback.get("dimensions"),
                "format": exiftool_data.get("FileType") or fallback.get("format"),
                "color_profile": exiftool_data.get("ColorSpaceData") or exiftool_data.get("ColorSpace") or fallback.get("color_profile"),
                "exif": {
                    "make": exiftool_data.get("Make") or fallback.get("exif", {}).get("make"),
                    "model": exiftool_data.get("Model") or fallback.get("exif", {}).get("model"),
                    "software": exiftool_data.get("Software") or fallback.get("exif", {}).get("software"),
                    "lens": exiftool_data.get("LensModel") or fallback.get("exif", {}).get("lens"),
                    "f_number": exiftool_data.get("FNumber"),
                    "exposure_time": exiftool_data.get("ExposureTime"),
                    "iso": exiftool_data.get("ISO"),
                    "focal_length": exiftool_data.get("FocalLength"),
                    "captured_at": exiftool_data.get("DateTimeOriginal") or fallback.get("exif", {}).get("captured_at")
                },
                "gps": {
                    "has_gps": has_gps,
                    "latitude": lat if has_gps else None,
                    "longitude": lon if has_gps else None,
                    "altitude": alt if has_gps else None
                },
                "provenance_clues": fallback.get("provenance_clues", {})
            }
        return fallback

    elif media_type == "audio":
        ffprobe_data = await inspect_with_ffprobe(file_path)
        fallback = inspect_audio_fallback(file_path)

        if ffprobe_data:
            format_info = ffprobe_data.get("format", {})
            streams = ffprobe_data.get("streams", [])
            audio_stream = next((s for s in streams if s.get("codec_type") == "audio"), {})

            sample_rate = int(audio_stream.get("sample_rate")) if audio_stream.get("sample_rate") else fallback.get("sample_rate")
            channels = int(audio_stream.get("channels")) if audio_stream.get("channels") else fallback.get("channels")
            duration = float(format_info.get("duration")) if format_info.get("duration") else fallback.get("duration_seconds")
            bitrate = int(format_info.get("bit_rate")) // 1000 if format_info.get("bit_rate") else fallback.get("bitrate_kbps")

            return {
                "container": format_info.get("format_long_name") or format_info.get("format_name") or fallback.get("container"),
                "codec": audio_stream.get("codec_long_name") or audio_stream.get("codec_name") or fallback.get("codec"),
                "duration_seconds": duration,
                "sample_rate": sample_rate,
                "channels": channels,
                "bitrate_kbps": bitrate,
                "tags": format_info.get("tags", {}),
                "ai_acoustic_markers": fallback.get("ai_acoustic_markers", [])
            }
        return fallback

    elif media_type == "video":
        ffprobe_data = await inspect_with_ffprobe(file_path)
        fallback = inspect_video_fallback(file_path)

        if ffprobe_data:
            format_info = ffprobe_data.get("format", {})
            streams = ffprobe_data.get("streams", [])
            video_stream = next((s for s in streams if s.get("codec_type") == "video"), {})
            audio_stream = next((s for s in streams if s.get("codec_type") == "audio"), {})

            width = video_stream.get("width")
            height = video_stream.get("height")
            fps = eval(video_stream.get("r_frame_rate", "0/1")) if "/" in video_stream.get("r_frame_rate", "") else None

            return {
                "container": format_info.get("format_long_name") or format_info.get("format_name"),
                "duration_seconds": float(format_info.get("duration", 0)),
                "dimensions": {"width": width, "height": height, "aspect_ratio": f"{round(width / max(height, 1), 2)}:1"} if width and height else fallback.get("dimensions"),
                "codecs": {
                    "video": video_stream.get("codec_name"),
                    "audio": audio_stream.get("codec_name") if audio_stream else None
                },
                "fps": round(fps, 2) if fps else None,
                "bitrate_kbps": int(format_info.get("bit_rate", 0)) // 1000 if format_info.get("bit_rate") else None,
                "audio_tracks": len([s for s in streams if s.get("codec_type") == "audio"]),
                "tags": format_info.get("tags", {})
            }
        return fallback

    return {}


__all__ = ["detect_media_signature", "extract_media_metadata"]
