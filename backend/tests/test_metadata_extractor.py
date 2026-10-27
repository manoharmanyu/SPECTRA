import io
import pytest
from app.media.detector import detect_media_signature
from app.media.inspector import decode_camera_makernotes, inspect_image_fallback, inspect_video_fallback, inspect_audio_fallback


def test_metadata_extractor_file_types_detection(tmp_path):
    """
    Test format detection for all formats specified in metadata-extractor:
    JPEG, TIFF (including BigTIFF), WebP, WAV, AVI, PSD, PNG, BMP, GIF,
    HEIF (HEIC & AVIF), ICO, PCX, QuickTime, MP4, Matroska (MKV, MKA, MKS, MK3D), WebM,
    and Camera Raw (NEF, CR2, CR3, ORF, ARW, RW2, RWL, SRW).
    """
    test_cases = [
        ("test.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 30, "image", "image/jpeg"),
        ("test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 30, "image", "image/png"),
        ("test.psd", b"8BPS" + b"\x00" * 30, "image", "image/vnd.adobe.photoshop"),
        ("test.bmp", b"BM" + b"\x00" * 30, "image", "image/bmp"),
        ("test.gif", b"GIF89a" + b"\x00" * 30, "image", "image/gif"),
        ("test.ico", b"\x00\x00\x01\x00\x01\x00\x10\x10" + b"\x00" * 20, "image", "image/x-icon"),
        ("test.pcx", b"\x0a\x05\x01\x08" + b"\x00" * 30, "image", "image/x-pcx"),
        ("test.webp", b"RIFF\x20\x00\x00\x00WEBPVP8 " + b"\x00" * 20, "image", "image/webp"),
        ("test.wav", b"RIFF\x20\x00\x00\x00WAVEfmt " + b"\x00" * 20, "audio", "audio/wav"),
        ("test.avi", b"RIFF\x20\x00\x00\x00AVI LIST" + b"\x00" * 20, "video", "video/x-msvideo"),
        ("test.tif", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/tiff"),
        ("test.btf", b"II+\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/tiff"),
        ("test.heic", b"\x00\x00\x00\x18ftypheic" + b"\x00" * 20, "image", "image/heic"),
        ("test.avif", b"\x00\x00\x00\x18ftypavif" + b"\x00" * 20, "image", "image/avif"),
        ("test.mov", b"\x00\x00\x00\x18ftypqt  " + b"\x00" * 20, "video", "video/quicktime"),
        ("test.mp4", b"\x00\x00\x00\x18ftypisom" + b"\x00" * 20, "video", "video/mp4"),
        ("test.m4a", b"\x00\x00\x00\x18ftypM4A " + b"\x00" * 20, "audio", "audio/mp4"),
        ("test.mkv", b"\x1a\x45\xdf\xa3" + b"\x00" * 30, "video", "video/x-matroska"),
        ("test.mka", b"\x1a\x45\xdf\xa3" + b"\x00" * 30, "audio", "audio/x-matroska"),
        ("test.mks", b"\x1a\x45\xdf\xa3" + b"\x00" * 30, "video", "video/x-matroska"),
        ("test.mk3d", b"\x1a\x45\xdf\xa3" + b"\x00" * 30, "video", "video/x-matroska"),
        ("test.webm", b"\x1a\x45\xdf\xa3" + b"\x00" * 30, "video", "video/webm"),
        ("test.weba", b"\x1a\x45\xdf\xa3" + b"\x00" * 30, "audio", "audio/webm"),
        # Camera RAW formats
        ("test.nef", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/x-nikon-nef"),
        ("test.cr2", b"II*\x00\x10\x00\x00\x00CR\x02\x00" + b"\x00" * 20, "image", "image/x-canon-cr2"),
        ("test.cr3", b"\x00\x00\x00\x18ftypcrx " + b"\x00" * 20, "image", "image/x-canon-cr3"),
        ("test.orf", b"IIRO\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/x-olympus-orf"),
        ("test.arw", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/x-sony-arw"),
        ("test.rw2", b"IIU\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/x-panasonic-rw2"),
        ("test.rwl", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/x-leica-rwl"),
        ("test.srw", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 20, "image", "image/x-samsung-srw"),
    ]

    for filename, raw_bytes, expected_media_type, expected_mime in test_cases:
        file_path = tmp_path / filename
        file_path.write_bytes(raw_bytes)
        media_type, mime = detect_media_signature(str(file_path), filename)
        assert media_type == expected_media_type, f"Failed for {filename}: expected {expected_media_type}, got {media_type}"
        assert mime == expected_mime, f"Failed for {filename}: expected {expected_mime}, got {mime}"


def test_decode_all_18_camera_makernotes():
    """
    Test decoding of camera-specific makernote data for all 18 manufacturers:
    Agfa, Apple, Canon, Casio, Epson, Fujifilm, Kodak, Kyocera, Leica,
    Minolta, Nikon, Olympus, Panasonic, Pentax, Reconyx, Sanyo, Sigma/Foveon, Sony.
    """
    manufacturers_test_data = [
        ("Agfa", {"Make": "AgfaPhoto", "Model": "Selecta 16", "AgfaModel": "Selecta", "SerialNumber": "AG12345"}),
        ("Apple", {"Make": "Apple", "Model": "iPhone 15 Pro", "RunTime": 1283921, "AccelerationVector": "-0.01 0.98 -0.12", "HDRImageType": 3}),
        ("Canon", {"Make": "Canon", "Model": "EOS 5D Mark IV", "CanonModelID": 384, "CanonFirmwareVersion": "1.3.3", "ShutterCount": 24150, "LensModel": "EF 24-70mm f/2.8L II USM"}),
        ("Casio", {"Make": "CASIO COMPUTER CO.,LTD.", "Model": "EX-ZR1000", "RecordMode": 2, "ObjectDistance": 120}),
        ("Epson", {"Make": "SEIKO EPSON CORP.", "Model": "R-D1", "Software": "Epson Digital Camera", "SerialNumber": "EP9876"}),
        ("Fujifilm", {"Make": "FUJIFILM", "Model": "X-T5", "FilmMode": "Classic Chrome", "DynamicRange": 400, "InternalSerialNumber": "FF5544"}),
        ("Kodak", {"Make": "Eastman Kodak Company", "Model": "DC290", "YearCreated": 2001, "BurstMode": 0}),
        ("Kyocera", {"Make": "KYOCERA", "Model": "Finecam S5", "PrintImageMatching": "PIM II"}),
        ("Leica", {"Make": "Leica Camera AG", "Model": "M11", "LeicaCameraType": "Rangefinder", "ColorTemperature": 5200}),
        ("Minolta", {"Make": "Minolta", "Model": "DiMAGE 7", "MinoltaQuality": "RAW", "MinoltaModelID": 10}),
        ("Nikon", {"Make": "NIKON CORPORATION", "Model": "Z 8", "NikonCaptureVersion": "1.2", "ShutterCount": 8412, "VibrationReduction": "On"}),
        ("Olympus", {"Make": "OLYMPUS CORPORATION", "Model": "OM-1", "EquipmentVersion": "0100", "SpecialMode": 1}),
        ("Panasonic", {"Make": "Panasonic", "Model": "DC-GH6", "PanasonicImageQuality": "Fine", "MacroMode": 1}),
        ("Pentax", {"Make": "PENTAX", "Model": "K-3 Mark III", "PentaxModelID": 204, "ShakeReduction": "On", "ShutterCount": 11200}),
        ("Reconyx", {"Make": "RECONYX", "Model": "HyperFire 2", "MotionTrigger": "PIR Sensor", "AmbientTemperature": 22}),
        ("Sanyo", {"Make": "SANYO Electric Co.,Ltd.", "Model": "VPC-HD2000", "SanyoQuality": "SuperFine"}),
        ("Sigma/Foveon", {"Make": "SIGMA", "Model": "fp L", "FoveonSensorData": "Full-frame", "ColorMode": "Teal and Orange"}),
        ("Sony", {"Make": "SONY", "Model": "ILCE-7RM5", "SonyModelID": 395, "ShutterCount": 4320, "DynamicRangeOptimizer": "Auto"}),
    ]

    for expected_mfg, mock_data in manufacturers_test_data:
        decoded = decode_camera_makernotes(mock_data)
        assert decoded["makernote_present"] is True, f"Makernote should be present for {expected_mfg}"
        assert decoded["manufacturer_matched"] == expected_mfg, f"Expected {expected_mfg}, got {decoded['manufacturer_matched']}"
        assert decoded["provenance_tier"] == "GENUINE_OPTICAL_SENSOR_VERIFIED"
        assert decoded["camera_make"] == mock_data["Make"]
        assert decoded["camera_model"] == mock_data["Model"]
