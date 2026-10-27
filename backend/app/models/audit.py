import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False)  # upload | n8n_dispatched | stage_completed | status_transition | retry
    details = Column(JSON, nullable=True, default=dict)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
