import os
import time
from typing import Optional, Dict, Any
from PIL import Image
import numpy as np

from app.media.models.base import BaseDeepfakeModel, ModelAvailability, ModelInferenceResult


class EfficientNetImageDetector(BaseDeepfakeModel):
    """
    EfficientNet-B4 Image Manipulation and Deepfake Comparison Detector.
    Evaluates compound-scaled feature pyramids for generative artifacts.
    Standard input: 380x380 RGB image normalized using ImageNet statistics.
    """

    def __init__(self, weights_path: Optional[str] = None):
        default_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "weights")
        self.weights_path = (
            weights_path
            or os.environ.get("EFFICIENTNET_WEIGHTS_PATH")
            or os.path.join(default_dir, "efficientnet_deepfake.pt")
        )
        self._model = None
        self._initialized = False

    @property
    def model_name(self) -> str:
        return "EfficientNet-B4-Classifier"

    @property
    def model_version(self) -> str:
        return "EfficientNet-B4-DF-v2.1"

    @property
    def model_source(self) -> str:
        return "Torchvision / Deepfake Detection Benchmark"

    @property
    def model_license(self) -> str:
        return "Apache 2.0"

    def is_configured(self) -> bool:
        return bool(self.weights_path and os.path.exists(self.weights_path))

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
                reason=f"Model weights not installed at '{self.weights_path}'. Set EFFICIENTNET_WEIGHTS_PATH once weights are present.",
                limitations=[
                    "EfficientNet comparison model is not configured; execution bypassed.",
                    "No synthetic prediction fabricated."
                ],
                details={"weights_expected_at": self.weights_path}
            )

        try:
            import torch
            device = "cuda" if torch.cuda.is_available() else "cpu"
            if not self._initialized:
                self._model = torch.load(self.weights_path, map_location=device)
                self._model.eval()
                self._initialized = True

            resized = input_image.convert("RGB").resize((380, 380), Image.Resampling.BILINEAR)
            arr = np.array(resized, dtype=np.float32) / 255.0
            mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
            std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
            normalized = (arr - mean) / std
            tensor_input = torch.from_numpy(np.transpose(normalized, (2, 0, 1))).unsqueeze(0).to(device)

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
                limitations=["Classifier subject to false positives on heavy post-processing filters."],
                details={"input_dimensions": "380x380"}
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
