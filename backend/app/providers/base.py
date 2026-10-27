from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel


class DetectorResult(BaseModel):
    provider: str
    model: Optional[str] = None
    status: str  # assessed | not_assessed | inconclusive | failed
    reason: Optional[str] = None
    score: Optional[float] = None
    score_type: Optional[str] = None  # model_score | probability | confidence
    raw_response: Optional[Dict[str, Any]] = None
    analyzed_at: Optional[str] = None


class BaseDetectorProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def detect(self, file_path: str, media_type: str, metadata: Dict[str, Any]) -> DetectorResult:
        """
        Run configured detector against media file.
        Must return not_assessed or inconclusive when API key is missing or response is ambiguous.
        Never invent scores.
        """
        pass
