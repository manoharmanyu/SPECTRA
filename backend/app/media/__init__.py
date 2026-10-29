from typing import Dict, Any
from app.media.detector import detect_media_signature
from app.media.inspector import (
    inspect_with_exiftool,
    inspect_with_ffprobe,
    decode_camera_makernotes,
    inspect_image_fallback,
    inspect_audio_fallback,
    inspect_video_fallback
)
from app.media.provenance import evaluate_media_provenance
from app.media.pipelines.image import ImageDetectionService
from app.media.pipelines.audio import AudioDetectionService
from app.media.pipelines.video import VideoDetectionService
from app.media.fusion import EvidenceFusionEngine


async def extract_media_metadata(file_path: str, media_type: str, mime_type: str) -> Dict[str, Any]:
    """
    Extract technical metadata, stream metrics, provenance clues, and camera-specific MakerNotes
    using ExifTool / ffprobe with graceful native Python fallbacks.
    Supports all image, audio, video, container, and camera RAW formats.
    """
    exiftool_data = await inspect_with_exiftool(file_path)

    if media_type == "image":
        fallback = inspect_image_fallback(file_path)

        if exiftool_data:
            fallback_exif = fallback.get("exif") or {}
            fallback_dims = fallback.get("dimensions") or {}
            fallback_provenance = fallback.get("provenance_clues") or {}
            makernote = decode_camera_makernotes(exiftool_data)

            width = exiftool_data.get("ImageWidth") or fallback_dims.get("width")
            height = exiftool_data.get("ImageHeight") or fallback_dims.get("height")
            aspect = f"{round(width / max(height, 1), 2)}:1" if width and height else None

            # GPS Coordinates strictly if genuine
            has_gps = False
            lat = exiftool_data.get("GPSLatitude")
            lon = exiftool_data.get("GPSLongitude")
            alt = exiftool_data.get("GPSAltitude")
            if lat is not None and lon is not None:
                has_gps = True

            return {
                "dimensions": {"width": width, "height": height, "aspect_ratio": aspect} if width else fallback_dims,
                "format": exiftool_data.get("FileType") or fallback.get("format"),
                "color_profile": exiftool_data.get("ColorSpaceData") or exiftool_data.get("ColorSpace") or fallback.get("color_profile"),
                "exif": {
                    "make": exiftool_data.get("Make") or fallback_exif.get("make"),
                    "model": exiftool_data.get("Model") or fallback_exif.get("model"),
                    "software": exiftool_data.get("Software") or fallback_exif.get("software"),
                    "lens": exiftool_data.get("LensModel") or exiftool_data.get("Lens") or fallback_exif.get("lens"),
                    "f_number": exiftool_data.get("FNumber"),
                    "exposure_time": exiftool_data.get("ExposureTime"),
                    "iso": exiftool_data.get("ISO"),
                    "focal_length": exiftool_data.get("FocalLength"),
                    "captured_at": exiftool_data.get("DateTimeOriginal") or fallback_exif.get("captured_at")
                },
                "makernote": makernote,
                "gps": {
                    "has_gps": has_gps,
                    "latitude": lat if has_gps else None,
                    "longitude": lon if has_gps else None,
                    "altitude": alt if has_gps else None
                },
                "provenance_clues": fallback_provenance
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
        elif exiftool_data:
            # ExifTool audio container extraction (WAV, MP3, FLAC, M4A, etc.)
            duration = exiftool_data.get("Duration") or fallback.get("duration_seconds")
            if isinstance(duration, str):
                try:
                    duration = float(duration.replace("s", "").strip())
                except Exception:
                    duration = fallback.get("duration_seconds")

            sample_rate = exiftool_data.get("SampleRate") or exiftool_data.get("AudioSampleRate") or fallback.get("sample_rate")
            channels = exiftool_data.get("AudioChannels") or exiftool_data.get("Channels") or fallback.get("channels")
            bitrate = exiftool_data.get("AudioBitrate") or fallback.get("bitrate_kbps")
            codec = exiftool_data.get("AudioFormat") or exiftool_data.get("CompressorName") or fallback.get("codec")

            return {
                "container": exiftool_data.get("FileType") or fallback.get("container"),
                "codec": str(codec) if codec else fallback.get("codec"),
                "duration_seconds": duration,
                "sample_rate": int(sample_rate) if sample_rate else fallback.get("sample_rate"),
                "channels": int(channels) if channels else fallback.get("channels"),
                "bitrate_kbps": int(bitrate) if isinstance(bitrate, (int, float)) else fallback.get("bitrate_kbps"),
                "tags": {k: v for k, v in exiftool_data.items() if k in ["Artist", "Title", "Album", "Year", "Genre", "Encoder"]},
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
        elif exiftool_data:
            # ExifTool video container extraction (MP4, QuickTime, AVI, MKV, WebM)
            width = exiftool_data.get("ImageWidth") or fallback.get("dimensions", {}).get("width")
            height = exiftool_data.get("ImageHeight") or fallback.get("dimensions", {}).get("height")
            duration = exiftool_data.get("Duration") or fallback.get("duration_seconds")
            if isinstance(duration, str):
                try:
                    duration = float(duration.replace("s", "").strip())
                except Exception:
                    duration = fallback.get("duration_seconds")

            fps = exiftool_data.get("VideoFrameRate") or fallback.get("fps")
            video_codec = exiftool_data.get("CompressorID") or exiftool_data.get("VideoCodec") or fallback.get("codecs", {}).get("video")
            audio_codec = exiftool_data.get("AudioFormat") or fallback.get("codecs", {}).get("audio")

            return {
                "container": exiftool_data.get("FileType") or fallback.get("container"),
                "duration_seconds": duration,
                "dimensions": {"width": width, "height": height, "aspect_ratio": f"{round(width / max(height, 1), 2)}:1"} if width and height else fallback.get("dimensions"),
                "codecs": {
                    "video": str(video_codec) if video_codec else "Video Stream",
                    "audio": str(audio_codec) if audio_codec else None
                },
                "fps": round(float(fps), 2) if fps else None,
                "bitrate_kbps": exiftool_data.get("AvgBitrate") or fallback.get("bitrate_kbps"),
                "audio_tracks": 1 if audio_codec else 0,
                "tags": {k: v for k, v in exiftool_data.items() if k in ["Title", "Encoder", "HandlerDescription", "MajorBrand"]}
            }
        return fallback

    return {}


__all__ = ["detect_media_signature", "extract_media_metadata", "decode_camera_makernotes"]
