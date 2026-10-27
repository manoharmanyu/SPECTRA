from typing import List, Dict, Any
from app.providers.base import BaseDetectorProvider, DetectorResult
from app.providers.hive import HiveProvider
from app.providers.gemini import GeminiProvider


class DetectorRegistry:
    def __init__(self):
        self.providers: List[BaseDetectorProvider] = [
            HiveProvider()
        ]
        self.explainer = GeminiProvider()

    async def run_all(self, file_path: str, media_type: str, metadata: Dict[str, Any]) -> List[DetectorResult]:
        results = []
        for p in self.providers:
            res = await p.detect(file_path, media_type, metadata)
            results.append(res)
        return results

    async def get_summary_explanation(self, metadata: Dict[str, Any], detector_findings: list) -> str:
        explanation = await self.explainer.generate_explanation(metadata, detector_findings)
        return explanation


detector_registry = DetectorRegistry()

__all__ = ["DetectorRegistry", "detector_registry", "DetectorResult"]
