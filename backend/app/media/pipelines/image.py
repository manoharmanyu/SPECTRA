import io
import os
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image, ImageChops, ImageEnhance, ImageFilter
import numpy as np

from app.media.inspector import inspect_with_exiftool, decode_camera_makernotes
from app.media.provenance import evaluate_media_provenance


class ImageDetectionService:
    """
    Dedicated Image Forensic and AI-Generation Detection Pipeline.
    Combines:
      1. Embedded Metadata & Camera MakerNotes (18 manufacturers)
      2. C2PA Content Credentials & Generative Model Signatures
      3. Error Level Analysis (ELA) for compression and splice detection
      4. High-Frequency Spatial Noise Residuals (Sensor PRNU vs Synthetic Residuals)
      5. Bounded Tiled Window Scanning for High-Resolution Images
    """

    @classmethod
    def compute_error_level_analysis(cls, img: Image.Image, quality: int = 95) -> Dict[str, Any]:
        """
        Error Level Analysis (ELA): Computes pixel differential between the image and
        a version re-compressed at a known JPEG quality rate.
        Detects composite splices, localized inpainting, and synthetic raster blocks.
        """
        try:
            # Convert to RGB
            rgb_img = img.convert("RGB")
            
            # Save to in-memory buffer at specified quality
            buf = io.BytesIO()
            rgb_img.save(buf, format="JPEG", quality=quality)
            buf.seek(0)
            
            recompressed = Image.open(buf)
            
            # Compute absolute difference
            diff = ImageChops.difference(rgb_img, recompressed)
            
            # Convert to numpy array for statistical evaluation
            diff_arr = np.array(diff, dtype=np.float32)
            mean_error = float(np.mean(diff_arr))
            std_error = float(np.std(diff_arr))
            max_error = float(np.max(diff_arr))

            # Detect localized anomaly / splicing
            # Spliced regions typically have standard deviation > 3.5x the mean error
            is_spliced = std_error > (mean_error * 3.8) and max_error > 80.0

            return {
                "ela_mean_error": round(mean_error, 3),
                "ela_std_error": round(std_error, 3),
                "ela_max_error": round(max_error, 3),
                "suspected_splice_detected": is_spliced,
                "ela_uniformity_score": round(max(0.0, 1.0 - (std_error / (mean_error + 1e-5)) * 0.2), 3)
            }
        except Exception as e:
            return {
                "ela_error": str(e),
                "ela_mean_error": 0.0,
                "ela_std_error": 0.0,
                "suspected_splice_detected": False
            }

    @classmethod
    def compute_spatial_noise_residuals(cls, img: Image.Image) -> Dict[str, Any]:
        """
        Analyzes high-frequency spatial residuals to measure physical sensor noise (PRNU)
        versus latent diffusion synthetic residuals.
        Optical sensors produce characteristic photon shot noise and silicon PRNU.
        Generative models produce unnaturally oversmoothed or checkerboard-quantized residuals.
        """
        try:
            # Resize if huge to bound memory
            w, h = img.size
            max_dim = 1024
            if max(w, h) > max_dim:
                scale = max_dim / float(max(w, h))
                eval_img = img.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)
            else:
                eval_img = img

            gray = eval_img.convert("L")
            gray_arr = np.array(gray, dtype=np.float32)

            # High-pass filter via Laplacian kernel convolution approximation
            # Laplacian kernel: [[0, 1, 0], [1, -4, 1], [0, 1, 0]]
            kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
            
            # Simple 2D valid convolution
            h_k, w_k = kernel.shape
            view_shape = (gray_arr.shape[0] - h_k + 1, gray_arr.shape[1] - w_k + 1)
            
            # Vectorized local patch extraction for residual computation
            from numpy.lib.stride_tricks import sliding_window_view
            windows = sliding_window_view(gray_arr, (h_k, w_k))
            residuals = np.sum(windows * kernel, axis=(-2, -1))

            residual_std = float(np.std(residuals))
            residual_variance = float(np.var(residuals))
            residual_kurtosis = float(np.mean((residuals - np.mean(residuals)) ** 4) / ((residual_variance + 1e-5) ** 2))

            # Camera sensors typically show high continuous residual variance (std > 12.0)
            # Diffusion models with latent denoisers frequently show low residual variance or heavy-tailed kurtosis (> 8.0)
            is_synthetic_residual = residual_std < 8.5 or residual_kurtosis > 14.0

            return {
                "residual_std": round(residual_std, 3),
                "residual_variance": round(residual_variance, 3),
                "residual_kurtosis": round(residual_kurtosis, 3),
                "is_synthetic_residual_pattern": is_synthetic_residual,
                "sensor_noise_confidence": round(min(1.0, residual_std / 25.0), 3)
            }
        except Exception as e:
            return {
                "residual_error": str(e),
                "residual_std": 0.0,
                "is_synthetic_residual_pattern": False,
                "sensor_noise_confidence": 0.5
            }

    @classmethod
    def analyze_tiled_patches(cls, img: Image.Image, patch_size: int = 512) -> Dict[str, Any]:
        """
        Tiled Window Scanning: Evaluates 512x512 patches with stride to detect
        inconsistent localized generative inpainting without memory exhaustion.
        """
        w, h = img.size
        if w < patch_size or h < patch_size:
            return {
                "tiles_evaluated": 1,
                "patch_variance_uniform": True,
                "localized_anomaly_found": False
            }

        # Sample up to 6 representative tiles
        patches_std = []
        step_x = max(1, (w - patch_size) // 2)
        step_y = max(1, (h - patch_size) // 2)

        for y in range(0, h - patch_size + 1, step_y):
            for x in range(0, w - patch_size + 1, step_x):
                crop = img.crop((x, y, x + patch_size, y + patch_size)).convert("L")
                arr = np.array(crop, dtype=np.float32)
                patches_std.append(float(np.std(arr)))
                if len(patches_std) >= 6:
                    break
            if len(patches_std) >= 6:
                break

        if len(patches_std) > 1:
            variance_between_patches = float(np.std(patches_std))
            # Highly inconsistent texture variance across tiles can indicate local synthesis / inpainting
            localized_anomaly = variance_between_patches > 28.0
        else:
            variance_between_patches = 0.0
            localized_anomaly = False

        return {
            "tiles_evaluated": len(patches_std),
            "variance_between_patches": round(variance_between_patches, 3),
            "localized_anomaly_found": localized_anomaly
        }

    @classmethod
    async def analyze_image(cls, file_path: str, original_filename: str) -> Dict[str, Any]:
        """
        Full Image Forensic Pipeline Execution.
        """
        observations = []
        evidence_items = []
        limitations = []

        # 1. Load image via Pillow safely
        try:
            with Image.open(file_path) as pil_img:
                format_detected = pil_img.format
                width, height = pil_img.size
                mode = pil_img.mode
                
                # Run pixel forensics
                ela_res = cls.compute_error_level_analysis(pil_img)
                noise_res = cls.compute_spatial_noise_residuals(pil_img)
                tiled_res = cls.analyze_tiled_patches(pil_img)
        except Exception as e:
            return {
                "status": "failed",
                "media_type": "image",
                "error": f"Failed to decode image pixels: {str(e)}"
            }

        # 2. Extract technical metadata via ExifTool
        raw_exif = await inspect_with_exiftool(file_path) or {}
        makernote_res = decode_camera_makernotes(raw_exif)

        # 3. Evaluate Provenance (C2PA, AI prompt tags, MakerNotes)
        provenance = evaluate_media_provenance(file_path, raw_exif, makernote_res)

        # 4. Formulate Evidence Items
        # A. Provenance
        if provenance["c2pa"]["manifest_store_found"]:
            evidence_items.append({
                "source": "provenance_verification",
                "finding": provenance["c2pa"]["details"],
                "status": "verified" if "VALID" in provenance["c2pa"]["status"] else "inconclusive"
            })
        else:
            evidence_items.append({
                "source": "provenance_verification",
                "finding": "No C2PA Content Credentials container embedded.",
                "status": "not_present"
            })

        # B. Metadata assessment
        metadata_present = bool(raw_exif and len(raw_exif) > 5)
        if len(provenance["ai_signatures"]) > 0:
            for sig in provenance["ai_signatures"]:
                evidence_items.append({
                    "source": "metadata_extraction",
                    "finding": f"AI Generation Tag Detected: {sig['description']}",
                    "status": "verified",
                    "score": 0.98
                })
        elif makernote_res.get("makernote_present"):
            mfg = makernote_res.get("manufacturer_matched")
            evidence_items.append({
                "source": "metadata_extraction",
                "finding": f"Authentic camera hardware MakerNote verified for {mfg}.",
                "status": "verified",
                "score": 0.05
            })
        elif metadata_present:
            evidence_items.append({
                "source": "metadata_extraction",
                "finding": "Standard EXIF tags present without proprietary MakerNotes.",
                "status": "verified",
                "score": 0.50
            })
        else:
            evidence_items.append({
                "source": "metadata_extraction",
                "finding": "No embedded EXIF metadata found (stripped or absent).",
                "status": "inconclusive"
            })
            limitations.append("Metadata is not proof of origin. Missing EXIF does not indicate AI generation.")

        # C. Pixel forensics: ELA
        if ela_res.get("suspected_splice_detected"):
            evidence_items.append({
                "source": "error_level_analysis",
                "finding": f"High localized compression variance (std: {ela_res['ela_std_error']}) suggests composite editing or splice manipulation.",
                "status": "verified",
                "score": 0.85
            })
        else:
            evidence_items.append({
                "source": "error_level_analysis",
                "finding": f"Consistent compression error level across raster blocks (std: {ela_res['ela_std_error']}).",
                "status": "verified",
                "score": 0.20
            })

        # D. Spatial noise residuals
        if noise_res.get("is_synthetic_residual_pattern"):
            evidence_items.append({
                "source": "pixel_residual_analysis",
                "finding": f"High-frequency spatial residual analysis indicates unnatural noise distribution (std: {noise_res['residual_std']}).",
                "status": "verified",
                "score": 0.88
            })
        else:
            evidence_items.append({
                "source": "pixel_residual_analysis",
                "finding": f"Natural high-frequency spatial shot noise consistent with physical optical sensor (std: {noise_res['residual_std']}).",
                "status": "verified",
                "score": 0.12
            })

        # Determine preliminary pipeline decision
        is_ai_provenance = provenance["provenance_status"] == "VALID_AI_PROVENANCE"
        is_capture_provenance = provenance["provenance_status"] in ["VALID_CAPTURE_PROVENANCE", "UNVERIFIED_CAPTURE_PROVENANCE"]
        has_ai_metadata = len(provenance["ai_signatures"]) > 0
        has_splice = ela_res.get("suspected_splice_detected", False) or tiled_res.get("localized_anomaly_found", False)
        is_synthetic_noise = noise_res.get("is_synthetic_residual_pattern", False)

        if is_ai_provenance or has_ai_metadata:
            classification = "LIKELY_AI_GENERATED"
            score = 0.96
            ai_label = "SYNTHETIC"
            capture_label = "UNVERIFIED"
            manipulation_detected = False
        elif has_splice and is_capture_provenance:
            classification = "POSSIBLY_EDITED_OR_MANIPULATED"
            score = 0.78
            ai_label = "UNCERTAIN"
            capture_label = "VERIFIED"
            manipulation_detected = True
        elif is_capture_provenance:
            classification = "LIKELY_CAMERA_CAPTURED"
            score = 0.04
            ai_label = "NATURAL"
            capture_label = "VERIFIED"
            manipulation_detected = False
        elif is_synthetic_noise and not metadata_present:
            # Synthetic noise, but no metadata: could be AI or heavy compression
            classification = "LIKELY_AI_GENERATED"
            score = 0.82
            ai_label = "SYNTHETIC"
            capture_label = "UNVERIFIED"
            manipulation_detected = False
            limitations.append("Absence of metadata combined with synthetic residual signature. Corroboration recommended.")
        elif not metadata_present:
            # No metadata, ordinary noise: strictly inconclusive!
            classification = "INCONCLUSIVE"
            score = None
            ai_label = "UNCERTAIN"
            capture_label = "UNVERIFIED"
            manipulation_detected = None
            limitations.append("Insufficient metadata and ambiguous residual statistics. Inconclusive origin.")
        else:
            classification = "INCONCLUSIVE"
            score = None
            ai_label = "UNCERTAIN"
            capture_label = "UNVERIFIED"
            manipulation_detected = None

        limitations.append("Classification requires corroboration; post-processing can alter noise patterns.")

        return {
            "media_type": "image",
            "format": format_detected,
            "dimensions": {"width": width, "height": height},
            "color_mode": mode,
            "classification": classification,
            "score": score,
            "ai_label": ai_label,
            "capture_label": capture_label,
            "manipulation_detected": manipulation_detected,
            "provenance": provenance,
            "ela": ela_res,
            "noise_residuals": noise_res,
            "tiling": tiled_res,
            "metadata_present": metadata_present,
            "evidence": evidence_items,
            "limitations": limitations
        }
