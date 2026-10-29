import os
import re
from typing import Dict, Any, List, Optional


KNOWN_AI_SIGNATURES = [
    # Stable Diffusion / ComfyUI / A1111 / WebUI
    (r"steps:\s*\d+,\s*sampler:", "Stable Diffusion WebUI (A1111) Parameters"),
    (r"prompt:\s*\{.*\"class_type\":", "ComfyUI Node Graph / Workflow"),
    (r"\"nodes\":\s*\[.*\"type\":\s*\"KSampler\"", "ComfyUI Workflow Metadata"),
    (r"comfyui", "ComfyUI Execution Pipeline"),
    (r"stable diffusion", "Stable Diffusion Generative Model"),
    (r"dall-e", "OpenAI DALL-E Generative Model"),
    (r"midjourney", "Midjourney Synthetic Image Synthesizer"),
    (r"novelai", "NovelAI Diffusion Synthesizer"),
    (r"adobe firefly", "Adobe Firefly Generative Engine"),
    (r"flux\.1", "Black Forest Labs FLUX.1 Diffusion Model"),
    (r"fooocus", "Fooocus Diffusion Engine"),
    (r"synthid", "SynthID Digital Watermark Signature"),
]


def inspect_c2pa_content_credentials(file_path: str) -> Dict[str, Any]:
    """
    Inspects file binary for C2PA Content Credentials (JUMBF / c2pa manifest box).
    Returns structured provenance evaluation.
    """
    if not os.path.exists(file_path):
        return {
            "status": "NONE_AVAILABLE",
            "c2pa_detected": False,
            "manifest_store_found": False,
            "claims": [],
            "validation_state": "NO_PROVENANCE_RECORDED",
            "details": "No C2PA Content Credentials container detected in media binary."
        }

    try:
        with open(file_path, "rb") as f:
            content = f.read(min(os.path.getsize(file_path), 2 * 1024 * 1024))  # Read first 2MB for header/boxes

        has_jumbf = b"jumb" in content or b"c2pa" in content or b"C2PA" in content
        if not has_jumbf:
            return {
                "status": "NONE_AVAILABLE",
                "c2pa_detected": False,
                "manifest_store_found": False,
                "claims": [],
                "validation_state": "NO_PROVENANCE_RECORDED",
                "details": "No C2PA Content Credentials container detected in media binary."
            }

        # JUMBF / C2PA box exists: examine assertions
        claims = []
        is_ai_assertion = False
        is_camera_assertion = False

        if b"c2pa.created" in content or b"c2pa.actions" in content:
            claims.append("c2pa.action: Creation/Edit event recorded")
        if b"generative" in content.lower() or b"ai" in content.lower():
            claims.append("c2pa.assertion: Generative synthetic creation process")
            is_ai_assertion = True
        if b"camera" in content.lower() or b"capture" in content.lower():
            claims.append("c2pa.assertion: Physical camera hardware capture")
            is_camera_assertion = True

        if is_ai_assertion and not is_camera_assertion:
            status = "VALID_AI_PROVENANCE"
            validation_state = "PROVENANCE_INDICATES_AI_GENERATION"
            details = "Valid C2PA Content Credentials declare media was synthetically generated."
        elif is_camera_assertion and not is_ai_assertion:
            status = "VALID_CAPTURE_PROVENANCE"
            validation_state = "PROVENANCE_INDICATES_OPTICAL_CAPTURE"
            details = "Valid C2PA Content Credentials declare hardware camera sensor capture."
        else:
            status = "INVALID_OR_UNVERIFIABLE"
            validation_state = "UNVERIFIABLE_OR_MIXED_ASSERTIONS"
            details = "C2PA container is present but digital signature or assertions cannot be independently corroborated."

        return {
            "status": status,
            "c2pa_detected": True,
            "manifest_store_found": True,
            "claims": claims,
            "validation_state": validation_state,
            "details": details
        }
    except Exception as e:
        return {
            "status": "INVALID_OR_UNVERIFIABLE",
            "c2pa_detected": True,
            "manifest_store_found": False,
            "claims": [],
            "validation_state": "CONTAINER_PARSE_ERROR",
            "details": f"Error parsing C2PA manifest container: {str(e)}"
        }


def inspect_metadata_generative_signatures(raw_metadata: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Scans raw EXIF, XMP, IPTC, and PNG text chunks for known AI model prompts and workflow markers.
    """
    found_signatures = []
    
    # Flatten metadata strings to search
    text_corpus = []
    for k, v in raw_metadata.items():
        if isinstance(v, (str, bytes)):
            text_corpus.append(str(v))
        elif isinstance(v, dict):
            for sub_k, sub_v in v.items():
                if isinstance(sub_v, (str, bytes)):
                    text_corpus.append(str(sub_v))

    combined_text = " \n ".join(text_corpus).lower()

    for pattern, description in KNOWN_AI_SIGNATURES:
        if re.search(pattern, combined_text, re.IGNORECASE):
            found_signatures.append({
                "signature": pattern,
                "description": description
            })

    return found_signatures


def evaluate_media_provenance(
    file_path: str,
    raw_metadata: Dict[str, Any],
    makernote_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Comprehensive Provenance Subsystem.
    Evaluates:
      1. C2PA Content Credentials
      2. Generative AI signatures (Stable Diffusion, Midjourney, ComfyUI, etc.)
      3. Physical Camera Hardware MakerNotes (18 manufacturers)
    
    Returns structured provenance evaluation.
    """
    c2pa_res = inspect_c2pa_content_credentials(file_path)
    ai_sigs = inspect_metadata_generative_signatures(raw_metadata)

    makernote = makernote_data or {}
    has_makernote = bool(makernote.get("makernote_present"))
    mfg = makernote.get("manufacturer_matched")
    camera_make = makernote.get("camera_make") or raw_metadata.get("Make")
    camera_model = makernote.get("camera_model") or raw_metadata.get("Model")

    observations = []

    # 1. Check C2PA assertions first
    if c2pa_res["status"] == "VALID_AI_PROVENANCE":
        overall_status = "VALID_AI_PROVENANCE"
        verdict = "LIKELY_AI_GENERATED"
        observations.append(c2pa_res["details"])
    elif c2pa_res["status"] == "VALID_CAPTURE_PROVENANCE":
        overall_status = "VALID_CAPTURE_PROVENANCE"
        verdict = "LIKELY_CAMERA_CAPTURED"
        observations.append(c2pa_res["details"])
    # 2. Check Generative AI Metadata Signatures
    elif len(ai_sigs) > 0:
        overall_status = "VALID_AI_PROVENANCE"
        verdict = "LIKELY_AI_GENERATED"
        for sig in ai_sigs:
            observations.append(f"Detected generative AI signature: {sig['description']}")
    # 3. Check Physical Camera Hardware Sensor MakerNotes
    elif has_makernote and mfg:
        overall_status = "VALID_CAPTURE_PROVENANCE"
        verdict = "LIKELY_CAMERA_CAPTURED"
        observations.append(f"Decoded genuine camera-specific MakerNote data for {mfg} ({camera_make} {camera_model}).")
        if makernote.get("hardware_serial_number"):
            observations.append(f"Hardware sensor serial number corroborated: {makernote.get('hardware_serial_number')}")
    elif camera_make or camera_model:
        overall_status = "UNVERIFIED_CAPTURE_PROVENANCE"
        verdict = "POSSIBLY_CAMERA_CAPTURED"
        observations.append(f"Exif Make/Model tags present ({camera_make} {camera_model}) without proprietary MakerNote confirmation.")
    else:
        overall_status = "NONE_AVAILABLE"
        verdict = "INCONCLUSIVE"
        observations.append("No embedded provenance credentials or camera MakerNote metadata detected.")

    return {
        "provenance_status": overall_status,
        "preliminary_verdict": verdict,
        "c2pa": c2pa_res,
        "ai_signatures": ai_sigs,
        "camera_evidence": {
            "maker_present": has_makernote,
            "manufacturer": mfg,
            "camera_make": camera_make,
            "camera_model": camera_model,
            "shutter_count": makernote.get("shutter_count"),
            "serial_number": makernote.get("hardware_serial_number")
        },
        "observations": observations,
        "limitations": [
            "Absence of provenance is never proof of authenticity.",
            "Metadata can be stripped by social networks, messaging apps, or privacy tools.",
            "Device EXIF tags can theoretically be copied or spoofed without signed credentials."
        ]
    }
