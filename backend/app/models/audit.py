import json
import hashlib
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, JSON, ForeignKey, Index
from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


GENESIS_HASH = "0" * 64


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(String(64), nullable=True, index=True)
    sequence_number = Column(Integer, default=1, nullable=False)
    event_type = Column(String(64), nullable=False)  # evidence_intake | stage_completed | model_inference | report_finalized | report_accessed | retry
    actor_id = Column(String(64), nullable=True, default="system")
    actor_role = Column(String(32), nullable=True, default="service")
    details = Column(JSON, nullable=True, default=dict)
    ip_address = Column(String(64), nullable=True)
    prev_hash = Column(String(64), nullable=False, default=GENESIS_HASH)
    entry_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("idx_audit_chain", "evidence_id", "sequence_number"),
    )

    @staticmethod
    def calculate_hash(prev_hash: str, sequence_number: int, timestamp_iso: str, event_type: str, actor_id: str, details: dict) -> str:
        """
        Deterministic, canonical cryptographic hash calculation for tamper-evident audit chaining.
        Standardizes ISO timestamps to withstand DB datetime round-tripping across PostgreSQL and SQLite.
        """
        ts_norm = str(timestamp_iso).replace(" ", "T")
        if "+" in ts_norm:
            ts_norm = ts_norm.split("+")[0]
        if ts_norm.endswith("Z"):
            ts_norm = ts_norm[:-1]

        canonical_details = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        payload = f"{prev_hash}|{sequence_number}|{ts_norm}|{event_type}|{actor_id}|{canonical_details}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
