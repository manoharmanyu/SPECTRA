import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, String, DateTime, Boolean, JSON
from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class DeviceSession(Base):
    __tablename__ = "device_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_name = Column(String(255), nullable=True, default="Mobile Capture Probe")
    device_fingerprint = Column(String(255), nullable=True)
    client_metadata = Column(JSON, nullable=True, default=dict)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(
        DateTime(timezone=True),
        default=lambda: utc_now() + timedelta(days=7),
        nullable=False
    )
