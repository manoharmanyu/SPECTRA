from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class DeviceSessionCreate(BaseModel):
    device_name: Optional[str] = Field(default="Mobile Capture Probe", max_length=255)
    device_fingerprint: Optional[str] = Field(default=None, max_length=255)
    client_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class DeviceSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    capture_session_id: str
    device_name: Optional[str]
    created_at: datetime
    expires_at: datetime
    is_active: bool
