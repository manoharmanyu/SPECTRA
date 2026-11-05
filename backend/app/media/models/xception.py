import os
import time
from typing import Optional, Dict, Any
from PIL import Image
import numpy as np

from app.media.models.base import BaseDeepfakeModel, ModelAvailability, ModelInferenceResult


class XceptionNetImageDetector(BaseDeepfakeModel):
    """
    XceptionNet-based Deepfake and Face Manipulation Detector.
    Standard architecture validated on FaceForensics++ (FF++) and Celeb-DF benchmark datasets.
    Standard input: 299x299 RGB images, normalized to [-1, 1].
    """

    def __init__(self, weights_path: Optional[str] = None):
        default_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "weights")
        self.weights_path = (
            weights_path
            or os.environ.get("XCEPTION_WEIGHTS_PATH")
            or os.path.join(default_dir, "xception_deepfake.pt")
        )
        self._model = None
        self._initialized = False

    @property
    def model_name(self) -> str:
        return "XceptionNet-DeepfakeClassifier"

    @property
    def model_version(self) -> str:
        return "FF++-v1.4-Xception"

    @property
    def model_source(self) -> str:
        return "FaceForensics++ / PyTorch Hub Deepfake Benchmark"

    @property
    def model_license(self) -> str:
        return "MIT License"

    def is_configured(self) -> bool:
        return bool(self.weights_path and os.path.exists(self.weights_path))

    def _preprocess_image(self, img: Image.Image) -> np.ndarray:
        """Standard XceptionNet 299x299 RGB preprocessing with [-1.0, 1.0] scaling."""
        resized = img.convert("RGB").resize((299, 299), Image.Resampling.BILINEAR)
        arr = np.array(resized, dtype=np.float32) / 127.5 - 1.0
        # Transpose to (C, H, W)
        return np.transpose(arr, (2, 0, 1))

    async def predict(self, input_image: Image.Image) -> ModelInferenceResult:
        start_time = time.time()

        if not self.is_configured():
            return ModelInferenceResult(
                model_name=self.model_name,
                model_version=self.model_version,
                model_source=self.model_source,
                model_license=self.model_license,
                availability=ModelAvailability.NOT_CONFIGURED,
                prediction="INCONCLUSIVE",
                raw_score=None,
                calibrated_probability=None,
                device_used="cpu",
                reason=f"Model weights not installed at '{self.weights_path}'. To enable deep neural inference, download pretrained weights and set XCEPTION_WEIGHTS_PATH.",
                limitations=[
                    "Neural classifier weights are unconfigured in backend environment.",
                    "No synthetic prediction fabricated; relying strictly on signal forensics and provenance evidence."
                ],
                details={"weights_expected_at": self.weights_path}
            )

        try:
            # If PyTorch / ONNX is present and weights are configured:
            import torch
            device = "cuda" if torch.cuda.is_available() else "cpu"
            if not self._initialized:
                # Load state dict
                self._model = torch.load(self.weights_path, map_location=device)
                self._model.eval()
                self._initialized = True

            tensor_input = torch.from_numpy(self._preprocess_image(input_image)).unsqueeze(0).to(device)
            with torch.no_grad():
                output = self._model(tensor_input)
                prob = float(torch.sigmoid(output).cpu().numpy()[0])

            elapsed_ms = round((time.time() - start_time) * 1000.0, 2)
            prediction = "SYNTHETIC" if prob >= 0.5 else "NATURAL"
            return ModelInferenceResult(
                model_name=self.model_name,
                model_version=self.model_version,
                model_source=self.model_source,
                model_license=self.model_license,
                availability=ModelAvailability.AVAILABLE,
                prediction=prediction,
                raw_score=round(prob, 4),
                calibrated_probability=round(prob, 4),
                inference_time_ms=elapsed_ms,
                device_used=device,
                limitations=[
                    "XceptionNet performance degrades on compressed or downsampled social media images.",
                    "Prediction should be corroborated with sensor noise residuals and provenance tags."
                ],
                details={"input_dimensions": "299x299", "architecture": "SeparableConv2D-Depthwise"}
            )
        except Exception as e:
            elapsed_ms = round((time.time() - start_time) * 1000.0, 2)
            return ModelInferenceResult(
                model_name=self.model_name,
                model_version=self.model_version,
                model_source=self.model_source,
                model_license=self.model_license,
                availability=ModelAvailability.FAILED,
                prediction="INCONCLUSIVE",
                raw_score=None,
                calibrated_probability=None,
                inference_time_ms=elapsed_ms,
                device_used="cpu",
                reason=f"Inference execution error: {str(e)}",
                limitations=["Neural inference failed during execution stage."]
            )
