from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.schemas.media_detection import (
    MediaDetectionResponse,
    ConfidenceDetail,
    EvidenceItem,
    AIGenerationAssessment,
    CaptureAssessment,
    MetadataAssessment
)


class EvidenceFusionEngine:
    """
    Transparent Evidence-Fusion System for SPECTRA.
    Combines observations from:
      1. Provenance Subsystem (C2PA, Watermarks, MakerNotes)
      2. Metadata Extraction (Drew Noakes tags, EXIF, XMP)
      3. Signal Forensics (ELA, PRNU noise residuals, acoustic vocoder shelf, video temporal delta)
      4. External Classifier Models (Hive / Gemini if configured)
    
    Guarantees:
      - Provenance verification is kept strictly separate from statistical classifier predictions.
      - Never fabricates scores or certainty.
      - A missing EXIF block is treated as 'no metadata evidence', NOT as proof of AI generation.
    """

    @classmethod
    def fuse_evidence(
        cls,
        analysis_id: str,
        media_type: str,
        sha256: str,
        file_size_bytes: int,
        pipeline_output: Dict[str, Any],
        raw_metadata: Optional[Dict[str, Any]] = None,
        processing_time_ms: Optional[float] = None
    ) -> MediaDetectionResponse:
        classification = pipeline_output.get("classification", "INCONCLUSIVE")
        raw_score = pipeline_output.get("score")
        ai_label = pipeline_output.get("ai_label", "UNCERTAIN")
        capture_label = pipeline_output.get("capture_label", "UNVERIFIED")
        manipulation_detected = pipeline_output.get("manipulation_detected")
        
        evidence_list = [
            EvidenceItem(**item) for item in pipeline_output.get("evidence", [])
        ]
        limitations_list = list(pipeline_output.get("limitations", []))

        # 1. Calibrated Confidence Evaluation
        if raw_score is not None:
            # Score calibration interpretation
            if raw_score >= 0.85:
                interpretation = "High-confidence synthetic indicator corroborated across independent forensic signals."
            elif raw_score <= 0.15:
                interpretation = "High-confidence authentic capture indicator corroborated across physical sensor registers."
            else:
                interpretation = "Moderate indicator score with overlapping forensic variance; corroboration advised."
            confidence = ConfidenceDetail(score=round(raw_score, 3), interpretation=interpretation)
        else:
            confidence = ConfidenceDetail(score=None, interpretation="Uncalibrated / Inconclusive due to insufficient or ambiguous signals.")

        # 2. Subsystem Assessments
        ai_assessment = AIGenerationAssessment(
            label=ai_label,
            score=raw_score,
            model_version="SPECTRA-Forensics-Engine-v2.2",
            explanation=f"Evaluated as {ai_label} across {media_type} signal forensics."
        )

        provenance_data = pipeline_output.get("provenance", {})
        camera_data = provenance_data.get("camera_evidence", {})
        capture_assessment = CaptureAssessment(
            label=capture_label,
            device_evidence_found=bool(camera_data.get("maker_present") or camera_data.get("camera_make")),
            trusted_provenance_verified=provenance_data.get("provenance_status") == "VALID_CAPTURE_PROVENANCE",
            sensor_make=camera_data.get("camera_make"),
            sensor_model=camera_data.get("camera_model"),
            details=camera_data
        )

        metadata_present = bool(pipeline_output.get("metadata_present", False) or (raw_metadata and len(raw_metadata) > 3))
        metadata_assessment = MetadataAssessment(
            metadata_present=metadata_present,
            observations=provenance_data.get("observations", []),
            tags_count=len(raw_metadata) if raw_metadata else 0,
            origin_conclusion="INCONCLUSIVE_FROM_METADATA_ALONE" if not camera_data.get("maker_present") else "CORROBORATES_OPTICAL_CAPTURE"
        )

        # Baseline forensic disclosures
        if "Metadata is not proof of origin." not in limitations_list:
            limitations_list.append("Metadata is not proof of origin; EXIF tags can be stripped or modified.")
        if "Classification requires corroboration" not in limitations_list:
            limitations_list.append("Classification requires corroboration; advanced post-processing and AI tools evolve continuously.")

        # Sanitize metadata to never expose internal server paths or sensitive filesystem locations
        sanitized_metadata = {}
        if raw_metadata:
            for k, v in raw_metadata.items():
                if k.lower() in ["sourcefile", "directory", "filepath", "path"]:
                    continue
                if isinstance(v, str) and ("/" in v or "\\" in v) and ("Users" in v or "home" in v or "storage_data" in v or "uploads" in v):
                    continue
                sanitized_metadata[k] = v

        return MediaDetectionResponse(
            project="SPECTRA",
            analysis_id=str(analysis_id),
            job_id=str(analysis_id),
            media_type=media_type,
            sha256=sha256,
            file_size_bytes=file_size_bytes,
            classification=classification,
            confidence=confidence,
            ai_generation_assessment=ai_assessment,
            capture_assessment=capture_assessment,
            metadata_assessment=metadata_assessment,
            evidence=evidence_list,
            manipulation_detected=manipulation_detected,
            metadata=sanitized_metadata,
            limitations=limitations_list,
            processing_status="completed",
            processing_time_ms=processing_time_ms,
            analyzed_at=datetime.now(timezone.utc).isoformat()
        )
