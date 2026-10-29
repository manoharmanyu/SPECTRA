from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ConfidenceDetail(BaseModel):
    score: Optional[float] = None
    interpretation: str = "Uncalibrated detector score"


class EvidenceItem(BaseModel):
    source: str
    finding: str
    status: str = "verified"  # verified | requires_actual_verification | inconclusive | not_present
    score: Optional[float] = None
    model_version: Optional[str] = None


class AIGenerationAssessment(BaseModel):
    label: str = "UNCERTAIN"  # SYNTHETIC | NATURAL | UNCERTAIN
    score: Optional[float] = None
    model_version: Optional[str] = None
    explanation: Optional[str] = None


class CaptureAssessment(BaseModel):
    label: str = "UNVERIFIED"  # VERIFIED | UNVERIFIED | CONFLICTING
    device_evidence_found: bool = False
    trusted_provenance_verified: bool = False
    sensor_make: Optional[str] = None
    sensor_model: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class MetadataAssessment(BaseModel):
    metadata_present: bool = False
    observations: List[str] = Field(default_factory=list)
    tags_count: int = 0
    origin_conclusion: str = "INCONCLUSIVE_FROM_METADATA_ALONE"


class MediaDetectionResponse(BaseModel):
    project: str = "SPECTRA"
    analysis_id: str
    job_id: Optional[str] = None
    media_type: str  # image | audio | video
    sha256: str
    file_size_bytes: int
    classification: str  # LIKELY_AI_GENERATED | LIKELY_CAMERA_CAPTURED | POSSIBLY_EDITED_OR_MANIPULATED | INCONCLUSIVE
    confidence: ConfidenceDetail
    ai_generation_assessment: AIGenerationAssessment
    capture_assessment: CaptureAssessment
    metadata_assessment: MetadataAssessment
    evidence: List[EvidenceItem] = Field(default_factory=list)
    manipulation_detected: Optional[bool] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
    processing_status: str = "completed"  # completed | processing | failed
    processing_time_ms: Optional[float] = None
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DetectorHealthItem(BaseModel):
    name: str
    category: str  # image | audio | video | metadata | provenance
    status: str  # available | degraded | unavailable
    version: Optional[str] = None
    details: Optional[str] = None


class DetectorHealthResponse(BaseModel):
    status: str  # healthy | degraded | offline
    service: str = "SPECTRA AI-Generated Media & Digital Forensics Engine"
    detectors: List[DetectorHealthItem] = Field(default_factory=list)
    supported_media_types: List[str] = Field(default_factory=lambda: ["image", "audio", "video"])
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
