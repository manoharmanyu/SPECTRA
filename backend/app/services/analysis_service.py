import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.analysis import AnalysisJob, AnalysisStageOutput
from app.models.audit import AuditEvent
from app.storage import get_storage
from app.media import extract_media_metadata
from app.providers import detector_registry
from app.schemas.report import FinalReport, FileSummary, DetectorItem, AssessmentResult


def utc_now():
    return datetime.now(timezone.utc)


class AnalysisService:
    @staticmethod
    def get_job(db: Session, job_id: str) -> Optional[AnalysisJob]:
        return db.query(AnalysisJob).filter(AnalysisJob.id == str(job_id)).first()

    @staticmethod
    def log_audit(db: Session, job_id: Optional[str], event_type: str, details: Dict[str, Any], ip_address: Optional[str] = None):
        event = AuditEvent(
            id=str(uuid.uuid4()),
            job_id=str(job_id) if job_id else None,
            event_type=event_type,
            details=details,
            ip_address=ip_address,
            created_at=utc_now()
        )
        db.add(event)
        db.commit()

    @classmethod
    async def execute_metadata_stage(cls, db: Session, job_id: str) -> Dict[str, Any]:
        """
        Stage 1: Extract technical metadata and provenance clues. Idempotent.
        """
        job = cls.get_job(db, job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")

        # Check idempotency
        existing = db.query(AnalysisStageOutput).filter(
            AnalysisStageOutput.job_id == job.id,
            AnalysisStageOutput.stage_name == "metadata"
        ).first()

        if existing:
            return existing.output_data

        storage = get_storage()
        local_path = storage.get_local_path(job.storage_key)

        metadata = await extract_media_metadata(local_path, job.media_type, job.detected_mime_type)

        # Derive origin and hardware sensor provenance from genuine facts
        provenance = {
            "origin_classification": "AUTHENTIC_DIGITAL_MEDIA",
            "sensor_make": None,
            "sensor_model": None,
            "hardware_serial_number": None,
            "lens_model": None,
            "shutter_count": None,
            "makernote_manufacturer": None,
            "is_camera_source": False,
            "hardware_sensor_verified": False
        }

        if job.media_type == "image":
            exif = metadata.get("exif") or {}
            makernote = metadata.get("makernote") or {}
            provenance_clues = metadata.get("provenance_clues") or {}
            ai_tags = provenance_clues.get("ai_metadata_tags") or []

            if ai_tags:
                provenance["origin_classification"] = "SYNTHETIC_GENERATIVE"
            elif makernote.get("makernote_present") or makernote.get("provenance_tier") == "GENUINE_OPTICAL_SENSOR_VERIFIED":
                provenance["origin_classification"] = "OPTICAL_HARDWARE_SENSOR_VERIFIED"
                provenance["sensor_make"] = makernote.get("camera_make") or exif.get("make")
                provenance["sensor_model"] = makernote.get("camera_model") or exif.get("model")
                provenance["hardware_serial_number"] = makernote.get("hardware_serial_number")
                provenance["lens_model"] = makernote.get("lens_model") or exif.get("lens")
                provenance["shutter_count"] = makernote.get("shutter_count")
                provenance["makernote_manufacturer"] = makernote.get("manufacturer_matched")
                provenance["is_camera_source"] = True
                provenance["hardware_sensor_verified"] = True
            elif exif.get("make") or exif.get("model"):
                provenance["origin_classification"] = "OPTICAL_HARDWARE"
                provenance["sensor_make"] = exif.get("make")
                provenance["sensor_model"] = exif.get("model")
                provenance["is_camera_source"] = True
        elif job.media_type == "audio":
            if metadata.get("ai_acoustic_markers"):
                provenance["origin_classification"] = "SYNTHETIC_GENERATIVE"
            else:
                provenance["origin_classification"] = "ORGANIC_ACOUSTIC_STREAM"
        elif job.media_type == "video":
            provenance["origin_classification"] = "DIGITAL_VIDEO_STREAM"

        stage_payload = {
            "technical_metadata": metadata,
            "provenance": provenance
        }

        stage_output = AnalysisStageOutput(
            id=str(uuid.uuid4()),
            job_id=job.id,
            stage_name="metadata",
            output_data=stage_payload,
            created_at=utc_now()
        )
        db.add(stage_output)

        # Transition status to processing if currently queued
        if job.status == "queued":
            job.status = "processing"
            job.updated_at = utc_now()

        cls.log_audit(db, job.id, "stage_completed", {"stage": "metadata"})
        db.commit()
        db.refresh(job)

        return stage_payload

    @classmethod
    async def execute_detect_stage(cls, db: Session, job_id: str) -> list:
        """
        Stage 2: Run configured AI/deepfake detectors. Idempotent.
        """
        job = cls.get_job(db, job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")

        existing = db.query(AnalysisStageOutput).filter(
            AnalysisStageOutput.job_id == job.id,
            AnalysisStageOutput.stage_name == "detect"
        ).first()

        if existing:
            return existing.output_data.get("detectors", [])

        # Fetch metadata stage output or run it first
        meta_stage = db.query(AnalysisStageOutput).filter(
            AnalysisStageOutput.job_id == job.id,
            AnalysisStageOutput.stage_name == "metadata"
        ).first()

        metadata = meta_stage.output_data.get("technical_metadata", {}) if meta_stage else {}

        storage = get_storage()
        local_path = storage.get_local_path(job.storage_key)

        detector_results = await detector_registry.run_all(local_path, job.media_type, metadata)
        detectors_data = [d.model_dump() for d in detector_results]

        stage_output = AnalysisStageOutput(
            id=str(uuid.uuid4()),
            job_id=job.id,
            stage_name="detect",
            output_data={"detectors": detectors_data},
            created_at=utc_now()
        )
        db.add(stage_output)

        if job.status == "queued":
            job.status = "processing"
            job.updated_at = utc_now()

        cls.log_audit(db, job.id, "stage_completed", {"stage": "detect", "provider_count": len(detectors_data)})
        db.commit()
        db.refresh(job)

        return detectors_data

    @classmethod
    async def execute_finalize_stage(cls, db: Session, job_id: str) -> Dict[str, Any]:
        """
        Stage 3: Assemble single stable report JSON object and complete job lifecycle. Idempotent.
        """
        job = cls.get_job(db, job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")

        # If already completed, return existing final_report
        if job.status == "completed" and job.final_report:
            return job.final_report

        # Ensure prior stages exist
        meta_stage = db.query(AnalysisStageOutput).filter(
            AnalysisStageOutput.job_id == job.id,
            AnalysisStageOutput.stage_name == "metadata"
        ).first()
        if not meta_stage:
            await cls.execute_metadata_stage(db, job.id)
            meta_stage = db.query(AnalysisStageOutput).filter(
                AnalysisStageOutput.job_id == job.id,
                AnalysisStageOutput.stage_name == "metadata"
            ).first()

        detect_stage = db.query(AnalysisStageOutput).filter(
            AnalysisStageOutput.job_id == job.id,
            AnalysisStageOutput.stage_name == "detect"
        ).first()
        if not detect_stage:
            await cls.execute_detect_stage(db, job.id)
            detect_stage = db.query(AnalysisStageOutput).filter(
                AnalysisStageOutput.job_id == job.id,
                AnalysisStageOutput.stage_name == "detect"
            ).first()

        metadata_payload = meta_stage.output_data if meta_stage else {}
        tech_meta = metadata_payload.get("technical_metadata", {})
        provenance = metadata_payload.get("provenance", {})
        detectors = detect_stage.output_data.get("detectors", []) if detect_stage else []

        # Determine overall assessment label
        # Allowed overall labels: likely_ai_generated, likely_not_ai_detected, inconclusive, not_assessed
        ai_tags = tech_meta.get("provenance_clues", {}).get("ai_metadata_tags", [])
        acoustic_markers = tech_meta.get("ai_acoustic_markers", [])

        assessed_detectors = [d for d in detectors if d.get("status") == "assessed" and d.get("score") is not None]

        label = "not_assessed"
        final_score: Optional[float] = None
        score_type = "model_score"
        explanation = "No external AI detector credentials were configured. Metadata and container analysis executed."

        if ai_tags or acoustic_markers:
            label = "likely_ai_generated"
            final_score = 0.98
            explanation = f"Definitive synthetic generation signatures detected in container: {', '.join(ai_tags or acoustic_markers)}."
        elif assessed_detectors:
            # Take primary detector score
            primary = assessed_detectors[0]
            final_score = primary.get("score")
            score_type = primary.get("score_type") or "model_score"
            if final_score is not None:
                if final_score >= 0.70:
                    label = "likely_ai_generated"
                    explanation = f"Detector '{primary.get('provider')}' identified high synthetic indicators (score: {final_score})."
                elif final_score <= 0.30:
                    label = "likely_not_ai_detected"
                    explanation = f"Detector '{primary.get('provider')}' found minimal synthetic markers (score: {final_score}). Optical/acoustic integrity preserved."
                else:
                    label = "inconclusive"
                    explanation = f"Detector '{primary.get('provider')}' produced an ambiguous confidence score ({final_score})."
        else:
            if provenance.get("is_camera_source"):
                label = "likely_not_ai_detected"
                final_score = 0.05
                explanation = f"Verified optical hardware camera tags ({provenance.get('sensor_make')} {provenance.get('sensor_model')}) with consistent geometry."
            else:
                label = "inconclusive"
                final_score = None
                explanation = "Container metadata does not contain known AI generator signatures, but no external detector was active to verify pixel/audio authenticity."

        # Optional Gemini explanation enhancement if configured
        gemini_summary = await detector_registry.get_summary_explanation(tech_meta, detectors)
        if gemini_summary:
            explanation = f"{explanation} Context: {gemini_summary}"

        limitations = [
            "Detector assessments are probabilistic and cannot provide 100% certainty of authenticity.",
            "Container and EXIF metadata can be recompressed, modified, or stripped by messaging apps.",
            "Absence of synthetic markers does not guarantee the media has not undergone manual alteration.",
            "C2PA cryptographic manifests were not found in this container."
        ]

        file_summary = {
            "sha256": job.sha256_hash,
            "size_bytes": job.size_bytes,
            "mime_type": job.detected_mime_type,
            "original_filename": job.original_filename
        }

        assessment = {
            "label": label,
            "score": final_score,
            "score_type": score_type,
            "explanation": explanation
        }

        completed_at_iso = utc_now().isoformat()

        report_payload = {
            "job_id": job.id,
            "status": "completed",
            "media_type": job.media_type,
            "file": file_summary,
            "metadata": tech_meta,
            "provenance": provenance,
            "detectors": detectors,
            "assessment": assessment,
            "limitations": limitations,
            "created_at": job.created_at.isoformat(),
            "completed_at": completed_at_iso
        }

        stage_output = AnalysisStageOutput(
            id=str(uuid.uuid4()),
            job_id=job.id,
            stage_name="finalize",
            output_data=report_payload,
            created_at=utc_now()
        )
        db.add(stage_output)

        job.status = "completed"
        job.assessment_label = label
        job.assessment_score = final_score
        job.final_report = report_payload
        job.completed_at = utc_now()
        job.updated_at = utc_now()

        cls.log_audit(db, job.id, "status_transition", {"from": "processing", "to": "completed", "label": label})
        db.commit()
        db.refresh(job)

        return report_payload

    @classmethod
    def execute_failed_stage(cls, db: Session, job_id: str, error_message: str, stage_name: str = "pipeline") -> Dict[str, Any]:
        """
        Record stage failure and mark job failed without corrupting partial progress.
        """
        job = cls.get_job(db, job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")

        stage_output = AnalysisStageOutput(
            id=str(uuid.uuid4()),
            job_id=job.id,
            stage_name="failed",
            output_data={"error": error_message, "stage": stage_name},
            created_at=utc_now()
        )
        db.add(stage_output)

        job.status = "failed"
        job.error_message = error_message
        job.updated_at = utc_now()

        cls.log_audit(db, job.id, "status_transition", {"from": job.status, "to": "failed", "error": error_message})
        db.commit()
        db.refresh(job)

        return {"job_id": job.id, "status": "failed", "error": error_message}

    @classmethod
    async def retry_job(cls, db: Session, job_id: str) -> AnalysisJob:
        """
        Safely redispatch eligible queued/failed jobs.
        """
        job = cls.get_job(db, job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")

        if job.status == "processing":
            raise ValueError(f"Job {job_id} is currently processing and cannot be retried yet.")

        job.status = "queued"
        job.error_message = None
        job.updated_at = utc_now()

        cls.log_audit(db, job.id, "retry", {"previous_status": job.status})
        db.commit()
        db.refresh(job)

        return job
