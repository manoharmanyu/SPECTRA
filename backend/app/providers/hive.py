import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from app.providers.base import BaseDetectorProvider, DetectorResult
from app.config import settings


class HiveProvider(BaseDetectorProvider):
    ENDPOINT_SYNC = "https://api.thehive.ai/api/v2/task/sync"

    @property
    def provider_name(self) -> str:
        return "hive"

    async def detect(self, file_path: str, media_type: str, metadata: Dict[str, Any]) -> DetectorResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        api_key = settings.HIVE_API_KEY

        if not api_key:
            return DetectorResult(
                provider=self.provider_name,
                model="hive_media_forensics_v2",
                status="not_assessed",
                reason="HIVE_API_KEY is not configured in backend environment. Provider execution bypassed.",
                score=None,
                score_type=None,
                analyzed_at=now_iso
            )

        headers = {
            "Authorization": f"token {api_key}",
            "Accept": "application/json"
        }

        try:
            filename = os.path.basename(file_path)
            async with httpx.AsyncClient(timeout=15.0) as client:
                with open(file_path, "rb") as f:
                    files = {"media": (filename, f)}
                    resp = await client.post(self.ENDPOINT_SYNC, headers=headers, files=files)

                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("status", [{}])[0].get("response", {})
                    output = status.get("output", [{}])[0]
                    classes = output.get("classes", [])

                    # Find ai_generated or synthetic class
                    ai_class = next(
                        (c for c in classes if "ai_generated" in c.get("class", "").lower() or "synthetic" in c.get("class", "").lower()),
                        None
                    )

                    if ai_class:
                        score = float(ai_class.get("score", 0.0))
                        return DetectorResult(
                            provider=self.provider_name,
                            model="hive_deepfake_synthetic_v2",
                            status="assessed",
                            score=round(score, 4),
                            score_type="model_score",
                            raw_response={"classes": classes[:5]},
                            analyzed_at=now_iso
                        )

                    return DetectorResult(
                        provider=self.provider_name,
                        model="hive_media_forensics_v2",
                        status="inconclusive",
                        reason="Hive API response did not contain recognized synthetic media classes.",
                        score=None,
                        score_type=None,
                        analyzed_at=now_iso
                    )
                else:
                    return DetectorResult(
                        provider=self.provider_name,
                        model="hive_media_forensics_v2",
                        status="failed",
                        reason=f"Hive API returned status code {resp.status_code}.",
                        score=None,
                        score_type=None,
                        analyzed_at=now_iso
                    )

        except httpx.TimeoutException:
            return DetectorResult(
                provider=self.provider_name,
                model="hive_media_forensics_v2",
                status="failed",
                reason="Hive detection request timed out after 15 seconds.",
                score=None,
                score_type=None,
                analyzed_at=now_iso
            )
        except Exception as e:
            return DetectorResult(
                provider=self.provider_name,
                model="hive_media_forensics_v2",
                status="failed",
                reason="Unexpected error during Hive detection call.",
                score=None,
                score_type=None,
                analyzed_at=now_iso
            )
