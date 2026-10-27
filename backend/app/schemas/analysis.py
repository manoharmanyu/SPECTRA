from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.report import FinalReport


class AnalysisCreateResponse(BaseModel):
    job_id: str
    status: str
    media_type: str
    status_url: str
    report_url: str


class AssessmentSummary(BaseModel):
    label: str
    score: Optional[float] = None
    score_type: Optional[str] = None
    explanation: Optional[str] = None


class AnalysisStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str
    status: str
    media_type: str
    original_filename: str
    size_bytes: int
    mime_type: str
    sha256: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    assessment_summary: Optional[AssessmentSummary] = None
    error_message: Optional[str] = None


class InternalStageResponse(BaseModel):
    job_id: str
    media_type: str
    status: str
    stage: str
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


class InternalFailedRequest(BaseModel):
    error: Optional[str] = "Processing failed in stage"
    stage: Optional[str] = "pipeline"
