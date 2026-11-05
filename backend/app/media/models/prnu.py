import os
from typing import Dict, Any, Optional, Tuple
from PIL import Image
import numpy as np


class SensorPRNUAnalyzer:
    """
    Physical Camera Sensor PRNU (Photo-Response Non-Uniformity) Forensic Module.
    
    IMPORTANT FORENSIC PRINCIPLE:
    PRNU is the unique deterministic sensor noise pattern created by silicon manufacturing tolerances.
    A high-pass filter or Laplacian residual alone evaluates spatial texture variance, NOT PRNU proof.
    Genuine PRNU verification mathematically requires:
      1. A reference sensor fingerprint (K) acquired from flatfield calibration frames of the physical camera.
      2. Normalized Cross-Correlation (NCC) or Peak-to-Correlation Energy (PCE) between query residual (W) and K.
    """

    @classmethod
    def extract_noise_residual(cls, img: Image.Image, max_dim: int = 1024) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Extracts zero-mean high-frequency noise residual W = I - Denoise(I) from image.
        Uses 2D adaptive local variance filter.
        """
        w, h = img.size
        if max(w, h) > max_dim:
            scale = max_dim / float(max(w, h))
            eval_img = img.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)
        else:
            eval_img = img

        gray = eval_img.convert("L")
        gray_arr = np.array(gray, dtype=np.float32)

        # 3x3 local mean filter approximation for low-pass F(I)
        from numpy.lib.stride_tricks import sliding_window_view
        pad_img = np.pad(gray_arr, 1, mode="reflect")
        windows = sliding_window_view(pad_img, (3, 3))
        local_mean = np.mean(windows, axis=(-2, -1))
        local_sq_mean = np.mean(windows ** 2, axis=(-2, -1))
        local_var = np.maximum(0.0, local_sq_mean - local_mean ** 2)

        # Wiener-type adaptive filter noise residual
        noise_var = float(np.median(local_var)) or 1.0
        weight = np.maximum(0.0, local_var - noise_var) / (local_var + 1e-5)
        denoised = local_mean + weight * (gray_arr - local_mean)
        residual = gray_arr - denoised

        # Zero-mean normalization
        residual = residual - np.mean(residual)
        res_std = float(np.std(residual))
        res_var = float(np.var(residual))

        # Kurtosis to measure Gaussianity (optical sensor shot noise is near-Gaussian, kurtosis ~ 3.0)
        kurtosis = float(np.mean(residual ** 4) / ((res_var + 1e-6) ** 2)) if res_var > 0 else 0.0

        stats = {
            "residual_mean": float(np.mean(residual)),
            "residual_std": round(res_std, 4),
            "residual_variance": round(res_var, 4),
            "residual_kurtosis": round(kurtosis, 3),
            "dimensions_evaluated": f"{gray_arr.shape[1]}x{gray_arr.shape[0]}"
        }
        return residual, stats

    @classmethod
    def evaluate_sensor_prnu_correlation(
        cls,
        img: Image.Image,
        camera_make: Optional[str] = None,
        camera_model: Optional[str] = None,
        reference_fingerprint: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Performs genuine PRNU correlation against an enrolled reference sensor fingerprint if available.
        When reference fingerprint is not enrolled, transparently reports REFERENCE_FINGERPRINT_UNAVAILABLE
        rather than claiming or faking PRNU proof.
        """
        residual, residual_stats = cls.extract_noise_residual(img)

        # If reference camera fingerprint is provided, compute 2D Normalized Cross Correlation (NCC)
        if reference_fingerprint is not None:
            # Resize or crop to common overlap
            min_h = min(residual.shape[0], reference_fingerprint.shape[0])
            min_w = min(residual.shape[1], reference_fingerprint.shape[1])
            W_sub = residual[:min_h, :min_w]
            K_sub = reference_fingerprint[:min_h, :min_w]

            # Compute NCC: rho = sum((W - mean(W)) * (K - mean(K))) / (norm(W) * norm(K))
            W_norm = np.linalg.norm(W_sub)
            K_norm = np.linalg.norm(K_sub)
            if W_norm > 1e-6 and K_norm > 1e-6:
                ncc = float(np.sum(W_sub * K_sub) / (W_norm * K_norm))
            else:
                ncc = 0.0

            is_sensor_match = ncc >= 0.12  # Standard forensic threshold for 1024x1024 crop
            return {
                "status": "REFERENCE_FINGERPRINT_VERIFIED" if is_sensor_match else "CORRELATION_BELOW_THRESHOLD",
                "normalized_cross_correlation": round(ncc, 4),
                "sensor_match_verified": is_sensor_match,
                "camera_model": camera_model,
                "residual_stats": residual_stats,
                "explanation": f"PRNU correlation {round(ncc, 4)} evaluated against enrolled reference sensor fingerprint."
            }

        # Scientific transparency: Reference fingerprint not enrolled
        return {
            "status": "REFERENCE_FINGERPRINT_UNAVAILABLE",
            "sensor_match_verified": False,
            "normalized_cross_correlation": None,
            "camera_model": camera_model or "Unknown",
            "residual_stats": residual_stats,
            "explanation": (
                "Camera PRNU verification requires reference calibration frames from the physical camera sensor. "
                "In the absence of an enrolled sensor fingerprint, physical device correlation cannot be mathematically claimed. "
                "High-frequency spatial noise variance is evaluated independently without claiming PRNU proof."
            ),
            "limitations": [
                "PRNU correlation requires reference calibration frames from the physical device.",
                "Spatial noise residual variance indicates texture smoothness, but cannot uniquely bind to a physical serial number without enrolled calibration."
            ]
        }
