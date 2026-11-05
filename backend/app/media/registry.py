import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.media.models.base import BaseDeepfakeModel, ModelAvailability, ModelInferenceResult
from app.media.models.xception import XceptionNetImageDetector
from app.media.models.efficientnet import EfficientNetImageDetector
from app.media.models.wav2vec import Wav2Vec2AudioDetector
from app.media.models.cnn_lstm import CNNLSTMTemporalDetector
from app.providers.hive import HiveProvider
from app.providers.gemini import GeminiProvider


class UnifiedDetectorReport(BaseModel):
    provider_name: str
    provider_version: str
    status: str  # available | not_configured | failed | unassessed
    model_identifier: str
    prediction: Optional[str] = None
    raw_score: Optional[float] = None
    calibrated_probability: Optional[float] = None
    processing_time_ms: Optional[float] = None
    failure_reason: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class DetectorRegistry:
    """
    Centralized Detector Registry managing all local neural models,
    forensic inspection engines, external API providers (Hive),
    and explanatory services (Gemini).
    """

    def __init__(self):
        self.image_model_xception = XceptionNetImageDetector()
        self.image_model_efficientnet = EfficientNetImageDetector()
        self.audio_model_wav2vec2 = Wav2Vec2AudioDetector()
        self.video_model_cnn_lstm = CNNLSTMTemporalDetector()
        self.hive_provider = HiveProvider()
        self.gemini_explainer = GeminiProvider()

    def get_registered_detectors(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": self.image_model_xception.model_name,
                "category": "image_neural",
                "version": self.image_model_xception.model_version,
                "is_configured": self.image_model_xception.is_configured(),
                "license": self.image_model_xception.model_license
            },
            {
                "name": self.image_model_efficientnet.model_name,
                "category": "image_neural_comparison",
                "version": self.image_model_efficientnet.model_version,
                "is_configured": self.image_model_efficientnet.is_configured(),
                "license": self.image_model_efficientnet.model_license
            },
            {
                "name": self.audio_model_wav2vec2.model_name,
                "category": "audio_neural",
                "version": self.audio_model_wav2vec2.model_version,
                "is_configured": self.audio_model_wav2vec2.is_configured(),
                "license": self.audio_model_wav2vec2.model_license
            },
            {
                "name": self.video_model_cnn_lstm.model_name,
                "category": "video_temporal_neural",
                "version": self.video_model_cnn_lstm.model_version,
                "is_configured": self.video_model_cnn_lstm.is_configured(),
                "license": self.video_model_cnn_lstm.model_license
            },
            {
                "name": "Hive-Media-Deepfake-API",
                "category": "external_api",
                "version": "v2.0",
                "is_configured": self.hive_provider.provider_name == "hive" and bool(self.hive_provider.ENDPOINT_SYNC),
                "license": "Commercial API"
            },
            {
                "name": "Gemini-Context-Explainer",
                "category": "explanatory_service_only",
                "version": "gemini-1.5-flash",
                "is_configured": bool(self.gemini_explainer),
                "license": "Google Cloud",
                "note": "EXPLANATORY CONTEXT ONLY — Gemini is not an authenticity classifier."
            }
        ]

    async def execute_image_detectors(self, img_pil, file_path: str, raw_metadata: dict) -> List[UnifiedDetectorReport]:
        reports = []

        # 1. Local XceptionNet
        x_res = await self.image_model_xception.predict(img_pil)
        reports.append(UnifiedDetectorReport(
            provider_name=self.image_model_xception.model_name,
            provider_version=self.image_model_xception.model_version,
            status=x_res.availability.value.lower(),
            model_identifier=self.image_model_xception.model_name,
            prediction=x_res.prediction,
            raw_score=x_res.raw_score,
            calibrated_probability=x_res.calibrated_probability,
            processing_time_ms=x_res.inference_time_ms,
            failure_reason=x_res.reason,
            limitations=x_res.limitations,
            details=x_res.details
        ))

        # 2. Local EfficientNet comparison
        e_res = await self.image_model_efficientnet.predict(img_pil)
        reports.append(UnifiedDetectorReport(
            provider_name=self.image_model_efficientnet.model_name,
            provider_version=self.image_model_efficientnet.model_version,
            status=e_res.availability.value.lower(),
            model_identifier=self.image_model_efficientnet.model_name,
            prediction=e_res.prediction,
            raw_score=e_res.raw_score,
            calibrated_probability=e_res.calibrated_probability,
            processing_time_ms=e_res.inference_time_ms,
            failure_reason=e_res.reason,
            limitations=e_res.limitations,
            details=e_res.details
        ))

        # 3. External Hive API (if configured)
        hive_res = await self.hive_provider.detect(file_path, "image", raw_metadata)
        reports.append(UnifiedDetectorReport(
            provider_name=self.hive_provider.provider_name,
            provider_version="v2",
            status=hive_res.status,
            model_identifier=hive_res.model or "hive_media_forensics_v2",
            prediction="SYNTHETIC" if (hive_res.score and hive_res.score >= 0.5) else ("NATURAL" if hive_res.score is not None else None),
            raw_score=hive_res.score,
            calibrated_probability=hive_res.score,
            failure_reason=hive_res.reason,
            limitations=["Third-party cloud inference subject to network conditions and API rate limits."],
            details=hive_res.raw_response or {}
        ))

        return reports

    async def execute_audio_detectors(self, audio_samples, sample_rate: int, file_path: str, raw_metadata: dict) -> List[UnifiedDetectorReport]:
        reports = []

        # 1. Local Wav2Vec 2.0 acoustic classifier
        w_res = await self.audio_model_wav2vec2.predict(audio_samples, sample_rate=sample_rate)
        reports.append(UnifiedDetectorReport(
            provider_name=self.audio_model_wav2vec2.model_name,
            provider_version=self.audio_model_wav2vec2.model_version,
            status=w_res.availability.value.lower(),
            model_identifier=self.audio_model_wav2vec2.model_name,
            prediction=w_res.prediction,
            raw_score=w_res.raw_score,
            calibrated_probability=w_res.calibrated_probability,
            processing_time_ms=w_res.inference_time_ms,
            failure_reason=w_res.reason,
            limitations=w_res.limitations,
            details=w_res.details
        ))

        # 2. External Hive API (if configured)
        hive_res = await self.hive_provider.detect(file_path, "audio", raw_metadata)
        reports.append(UnifiedDetectorReport(
            provider_name=self.hive_provider.provider_name,
            provider_version="v2",
            status=hive_res.status,
            model_identifier=hive_res.model or "hive_audio_forensics_v2",
            prediction="SYNTHETIC" if (hive_res.score and hive_res.score >= 0.5) else ("NATURAL" if hive_res.score is not None else None),
            raw_score=hive_res.score,
            calibrated_probability=hive_res.score,
            failure_reason=hive_res.reason,
            limitations=["Third-party cloud inference subject to network conditions and API rate limits."],
            details=hive_res.raw_response or {}
        ))

        return reports

    async def execute_video_detectors(self, frame_sequence, file_path: str, raw_metadata: dict) -> List[UnifiedDetectorReport]:
        reports = []

        # 1. Local CNN-LSTM recurrent temporal detector
        c_res = await self.video_model_cnn_lstm.predict(frame_sequence)
        reports.append(UnifiedDetectorReport(
            provider_name=self.video_model_cnn_lstm.model_name,
            provider_version=self.video_model_cnn_lstm.model_version,
            status=c_res.availability.value.lower(),
            model_identifier=self.video_model_cnn_lstm.model_name,
            prediction=c_res.prediction,
            raw_score=c_res.raw_score,
            calibrated_probability=c_res.calibrated_probability,
            processing_time_ms=c_res.inference_time_ms,
            failure_reason=c_res.reason,
            limitations=c_res.limitations,
            details=c_res.details
        ))

        # 2. External Hive API (if configured)
        hive_res = await self.hive_provider.detect(file_path, "video", raw_metadata)
        reports.append(UnifiedDetectorReport(
            provider_name=self.hive_provider.provider_name,
            provider_version="v2",
            status=hive_res.status,
            model_identifier=hive_res.model or "hive_video_forensics_v2",
            prediction="SYNTHETIC" if (hive_res.score and hive_res.score >= 0.5) else ("NATURAL" if hive_res.score is not None else None),
            raw_score=hive_res.score,
            calibrated_probability=hive_res.score,
            failure_reason=hive_res.reason,
            limitations=["Third-party cloud inference subject to network conditions and API rate limits."],
            details=hive_res.raw_response or {}
        ))

        return reports


registry = DetectorRegistry()
