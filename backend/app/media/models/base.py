from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class ModelAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    FAILED = "FAILED"


class ModelInferenceResult(BaseModel):
    model_name: str
    model_version: str
    model_source: str
    model_license: str
    availability: ModelAvailability
    prediction: Optional[str] = None  # SYNTHETIC | NATURAL | MANIPULATED | INCONCLUSIVE
    raw_score: Optional[float] = None
    calibrated_probability: Optional[float] = None
    inference_time_ms: Optional[float] = None
    device_used: str = "cpu"
    reason: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class BaseDeepfakeModel(ABC):
    """
    Abstract interface for all deep learning forensic classifiers in SPECTRA.
    Guarantees:
      - Never fabricates scores or fake predictions.
      - If weights or runtime dependencies are missing, explicitly reports NOT_CONFIGURED.
      - Records model source, license, version, and hardware execution device.
    """

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_version(self) -> str:
        pass

    @property
    @abstractmethod
    def model_source(self) -> str:
        pass

    @property
    @abstractmethod
    def model_license(self) -> str:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if required pretrained weights and runtimes are installed."""
        pass

    @abstractmethod
    async def predict(self, input_data: Any) -> ModelInferenceResult:
        """Executes inference on preprocessed data and returns structured findings."""
        pass
