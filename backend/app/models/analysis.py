import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    capture_session_id = Column(String(36), ForeignKey("device_sessions.id", ondelete="SET NULL"), nullable=True)
    source_origin = Column(String(64), default="web_upload", nullable=False)  # phone_simulator | web_upload
    source_device_id = Column(String(255), nullable=True)
    client_captured_at = Column(DateTime(timezone=True), nullable=True)

    media_type = Column(String(32), nullable=False)  # image | audio | video
    detected_mime_type = Column(String(128), nullable=False)
    original_filename = Column(String(512), nullable=False)
    storage_key = Column(String(512), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)

    status = Column(String(32), default="queued", nullable=False, index=True)  # queued | processing | completed | failed
    error_message = Column(Text, nullable=True)

    assessment_label = Column(String(64), nullable=True)  # likely_ai_generated | likely_not_ai_detected | inconclusive | not_assessed
    assessment_score = Column(Float, nullable=True)
    final_report = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    stage_outputs = relationship("AnalysisStageOutput", back_populates="job", cascade="all, delete-orphan")


class AnalysisStageOutput(Base):
    __tablename__ = "analysis_stage_outputs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_name = Column(String(64), nullable=False)  # metadata | detect | finalize | failed
    output_data = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    job = relationship("AnalysisJob", back_populates="stage_outputs")

    __table_args__ = (
        Index("idx_job_stage", "job_id", "stage_name"),
    )
