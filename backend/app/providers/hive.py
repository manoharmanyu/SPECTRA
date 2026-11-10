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
                    status_obj = data.get("status", [{}])[0].get("response", {})
                    output = status_obj.get("output", [{}])[0]
                    classes = output.get("classes", [])

                    # Separate AI-Generation from Face-Deepfake Manipulation
                    ai_classes = [c for c in classes if any(k in c.get("class", "").lower() for k in ("ai_generated", "synthetic", "generative"))]
                    deepfake_classes = [c for c in classes if any(k in c.get("class", "").lower() for k in ("deepfake", "face_swap", "face_manipulation"))]

                    ai_score = max([float(c.get("score", 0.0)) for c in ai_classes], default=None)
                    df_score = max([float(c.get("score", 0.0)) for c in deepfake_classes], default=None)

                    # Determine primary score and model version
                    primary_score = None
                    if ai_score is not None and df_score is not None:
                        primary_score = max(ai_score, df_score)
                    elif ai_score is not None:
                        primary_score = ai_score
                    elif df_score is not None:
                        primary_score = df_score

                    if primary_score is not None:
                        return DetectorResult(
                            provider=self.provider_name,
                            model="hive_deepfake_synthetic_v2",
                            status="assessed",
                            score=round(primary_score, 4),
                            score_type="model_score",
                            raw_response={
                                "classes": classes[:10],
                                "ai_generated_score": round(ai_score, 4) if ai_score is not None else None,
                                "face_deepfake_score": round(df_score, 4) if df_score is not None else None
                            },
                            analyzed_at=now_iso
                        )

                    return DetectorResult(
                        provider=self.provider_name,
                        model="hive_media_forensics_v2",
                        status="inconclusive",
                        reason="Hive API response did not contain recognized synthetic media or deepfake classes.",
                        score=None,
                        score_type=None,
                        analyzed_at=now_iso
                    )
                elif resp.status_code in (401, 403):
                    return DetectorResult(
                        provider=self.provider_name,
                        model="hive_media_forensics_v2",
                        status="failed",
                        reason="Authentication failure: Invalid or expired HIVE_API_KEY.",
                        score=None,
                        score_type=None,
                        analyzed_at=now_iso
                    )
                elif resp.status_code == 429:
                    return DetectorResult(
                        provider=self.provider_name,
                        model="hive_media_forensics_v2",
                        status="failed",
                        reason="Hive API rate limit or quota exceeded.",
                        score=None,
                        score_type=None,
                        analyzed_at=now_iso
                    )
                else:
                    return DetectorResult(
                        provider=self.provider_name,
                        model="hive_media_forensics_v2",
                        status="failed",
                        reason=f"Hive API returned HTTP error {resp.status_code}.",
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
