from typing import Dict, Any, Optional
import httpx
from app.config import settings


class GeminiProvider:
    """
    Optional contextual explanatory summarizer only.
    Gemini is NOT a forensic detector and does not output probability or proof of authenticity.
    """
    ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

    @property
    def provider_name(self) -> str:
        return "gemini_context_explainer"

    async def generate_explanation(self, metadata: Dict[str, Any], detector_findings: list) -> Optional[str]:
        api_key = settings.GEMINI_API_KEY
        if not api_key:
            return None

        prompt = (
            "You are a media forensics technical explainer. Provide a 2-sentence objective summary "
            f"of these technical metadata clues: {metadata}. Note: you are only summarizing clues, not certifying truth."
        )

        try:
            url = f"{self.ENDPOINT}?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 100}
            }
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        return text.strip()
        except Exception:
            pass
        return None
