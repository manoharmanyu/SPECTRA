from typing import Dict, Any
import httpx
from app.config import settings


async def dispatch_n8n_webhook(job_id: str, media_type: str) -> bool:
    """
    POST { "job_id": "...", "media_type": "image|audio|video" } to N8N_WEBHOOK_URL
    with header X-SPECTRA-WEBHOOK-TOKEN: SPECTRA_WEBHOOK_TOKEN.
    Does NOT send media bytes through n8n.
    Returns True if dispatched successfully, False on outage or network failure.
    """
    url = settings.N8N_WEBHOOK_URL
    if not url:
        return False

    payload = {
        "job_id": str(job_id),
        "media_type": str(media_type)
    }

    headers = {
        "Content-Type": "application/json",
        "X-SPECTRA-WEBHOOK-TOKEN": settings.SPECTRA_WEBHOOK_TOKEN
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201, 202, 204):
                return True
    except Exception:
        pass

    return False
