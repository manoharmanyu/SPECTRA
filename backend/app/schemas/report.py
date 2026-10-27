from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class FileSummary(BaseModel):
    sha256: str
    size_bytes: int
    mime_type: str
    original_filename: str


class DetectorItem(BaseModel):
    provider: str
    model: Optional[str] = None
    status: str  # assessed | not_assessed | inconclusive | failed
    reason: Optional[str] = None
    score: Optional[float] = None
    score_type: Optional[str] = None  # model_score | probability | confidence
    raw_response: Optional[Dict[str, Any]] = None
    analyzed_at: Optional[str] = None


class AssessmentResult(BaseModel):
    label: str  # likely_ai_generated | likely_not_ai_detected | inconclusive | not_assessed
    score: Optional[float] = None
    score_type: Optional[str] = "model_score"
    explanation: str


class FinalReport(BaseModel):
    job_id: str
    status: str  # completed | failed | processing
    media_type: str  # image | audio | video
    file: FileSummary
    metadata: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    detectors: List[DetectorItem] = Field(default_factory=list)
    assessment: AssessmentResult
    limitations: List[str] = Field(default_factory=list)
    created_at: str
    completed_at: Optional[str] = None
