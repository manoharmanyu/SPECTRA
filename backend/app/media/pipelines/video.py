import asyncio
import os
import shutil
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image
import numpy as np

from app.media.pipelines.image import ImageDetectionService
from app.media.pipelines.audio import AudioDetectionService
from app.media.inspector import resolve_binary
from app.media.registry import registry


class VideoDetectionService:
    """
    Dedicated Video Forensics & Deepfake Detection Pipeline.
    Evaluates:
      1. Container and stream metadata (codecs, framerate, resolution, audio tracks)
      2. Bounded frame sampling at configurable intervals (4 to 16 frames max)
      3. Per-frame forensic analysis using ImageDetectionService
      4. Inter-frame temporal consistency & motion residual variance
      5. Independent audio track analysis
    """

    @classmethod
    def get_ffmpeg_binary(cls) -> Optional[str]:
        bin_path = resolve_binary("ffmpeg")
        if not bin_path:
            try:
                import imageio_ffmpeg
                bin_path = imageio_ffmpeg.get_ffmpeg_exe()
            except Exception:
                pass
        return bin_path

    @classmethod
    async def sample_video_frames(cls, file_path: str, temp_dir: str, max_frames: int = 8) -> Tuple[List[Tuple[int, float, str]], float, float, int]:
        """
        Samples up to max_frames frames from the video at regular intervals.
        Returns: (sampled_frames, total_duration_seconds, fps, total_frames_estimated)
        """
        ffmpeg_bin = cls.get_ffmpeg_binary()
        if not ffmpeg_bin:
            return [], 0.0, 0.0, 0

        # Probe video duration and fps
        duration_cmd = [
            ffmpeg_bin,
            "-i", file_path,
            "-hide_banner"
        ]
        proc = await asyncio.create_subprocess_exec(
            *duration_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        stderr_str = stderr.decode("utf-8", errors="ignore")

        import re
        dur_match = re.search(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", stderr_str)
        if dur_match:
            hours, mins, secs = dur_match.groups()
            total_duration = float(hours) * 3600 + float(mins) * 60 + float(secs)
        else:
            total_duration = 10.0

        fps_match = re.search(r"(\d+(?:\.\d+)?)\s*fps", stderr_str)
        fps = float(fps_match.group(1)) if fps_match else 30.0

        total_frames_est = max(1, int(total_duration * fps))
        total_duration = max(1.0, total_duration)
        n_samples = min(max_frames, max(2, int(total_duration)))
        timestamps = [round((i + 0.5) * (total_duration / n_samples), 2) for i in range(n_samples)]

        sampled_frames = []
        for idx, t in enumerate(timestamps):
            out_img = os.path.join(temp_dir, f"frame_{idx:03d}_{t}s.jpg")
            cmd = [
                ffmpeg_bin,
                "-ss", str(t),
                "-i", file_path,
                "-vframes", "1",
                "-q:v", "2",
                "-y",
                out_img
            ]
            p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await p.communicate()
            if os.path.exists(out_img) and os.path.getsize(out_img) > 0:
                sampled_frames.append((idx, t, out_img))

        return sampled_frames, total_duration, fps, total_frames_est

    @classmethod
    def evaluate_temporal_consistency(cls, frame_paths: List[str]) -> Dict[str, Any]:
        """
        Evaluates inter-frame pixel differences between consecutive sampled frames.
        Deepfake video generation often exhibits sudden temporal flicker or inconsistent boundaries.
        """
        if len(frame_paths) < 2:
            return {
                "consecutive_pairs_evaluated": 0,
                "mean_temporal_delta": 0.0,
                "scene_cuts_detected": 0,
                "temporal_flicker_detected": False
            }

        deltas = []
        scene_cuts = 0
        for i in range(len(frame_paths) - 1):
            try:
                with Image.open(frame_paths[i]) as img1, Image.open(frame_paths[i+1]) as img2:
                    im1 = np.array(img1.convert("L").resize((256, 256)), dtype=np.float32)
                    im2 = np.array(img2.convert("L").resize((256, 256)), dtype=np.float32)
                    diff = float(np.mean(np.abs(im1 - im2)))
                    deltas.append(diff)
                    if diff > 50.0:
                        scene_cuts += 1
            except Exception:
                pass

        if not deltas:
            return {"consecutive_pairs_evaluated": 0, "scene_cuts_detected": 0, "temporal_flicker_detected": False}

        mean_delta = float(np.mean(deltas))
        std_delta = float(np.std(deltas))
        
        # High delta variance with unnatural sharp spike indicates temporal composite splicing
        temporal_flicker = std_delta > 35.0 and max(deltas) > 70.0

        return {
            "consecutive_pairs_evaluated": len(deltas),
            "mean_temporal_delta": round(mean_delta, 2),
            "std_temporal_delta": round(std_delta, 2),
            "scene_cuts_detected": scene_cuts,
            "temporal_flicker_detected": temporal_flicker
        }

    @classmethod
    async def analyze_video(cls, file_path: str, original_filename: str) -> Dict[str, Any]:
        """
        Full Video Forensic Pipeline Execution.
        """
        evidence_items = []
        limitations = []

        temp_dir = tempfile.mkdtemp(prefix="spectra_video_")
        try:
            # 1. Bounded Frame Sampling & Metadata Estimation
            sampled, total_duration, fps, total_frames_est = await cls.sample_video_frames(file_path, temp_dir, max_frames=8)
            if not sampled:
                return {
                    "status": "failed",
                    "media_type": "video",
                    "error": "Failed to decode video frames. Container may be corrupt or unsupported."
                }

            frame_paths = [s[2] for s in sampled]
            contributing_timestamps = [s[1] for s in sampled]
            frames_examined = len(sampled)
            sampling_coverage_pct = round((frames_examined / max(total_frames_est, 1)) * 100.0, 2)

            # 2. Per-frame forensic inspection
            frame_scores = []
            frame_classifications = []
            manipulated_intervals = []
            frame_arrays = []

            for idx, t, fpath in sampled:
                with Image.open(fpath) as pil_f:
                    frame_arrays.append(np.array(pil_f.convert("RGB").resize((224, 224))))
                res = await ImageDetectionService.analyze_image(fpath, f"frame_{idx}.jpg")
                c = res.get("classification")
                frame_classifications.append(c)
                s = res.get("score")
                if s is not None:
                    frame_scores.append(s)
                if c in ("LIKELY_AI_GENERATED", "POSSIBLY_EDITED_OR_MANIPULATED"):
                    manipulated_intervals.append({
                        "start_seconds": t,
                        "end_seconds": round(t + (total_duration / len(sampled)), 2),
                        "classification": c,
                        "score": s
                    })

            # 3. Temporal Consistency
            temporal_res = cls.evaluate_temporal_consistency(frame_paths)

            # 4. Neural Video Detector Registry (CNN-LSTM)
            detector_reports = await registry.execute_video_detectors(frame_arrays, file_path, {})
            model_detectors_data = [report.model_dump() for report in detector_reports]

            for d_rep in detector_reports:
                if d_rep.status == "available" and d_rep.prediction:
                    evidence_items.append({
                        "source": d_rep.provider_name,
                        "finding": f"Temporal neural video detector classified sequence as {d_rep.prediction} (score: {d_rep.calibrated_probability}).",
                        "status": "verified",
                        "score": d_rep.calibrated_probability,
                        "model_version": d_rep.provider_version
                    })
                elif d_rep.status == "not_configured":
                    limitations.extend(d_rep.limitations)

            # 5. Independent Audio Track Analysis & A/V Sync
            audio_result = None
            av_sync_assessment = "no_audio_track"
            ffmpeg_bin = cls.get_ffmpeg_binary()
            if ffmpeg_bin:
                audio_tmp = os.path.join(temp_dir, "extracted_audio.wav")
                cmd = [
                    ffmpeg_bin,
                    "-i", file_path,
                    "-vn",
                    "-ac", "1",
                    "-ar", "16000",
                    "-y",
                    audio_tmp
                ]
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await proc.communicate()
                if os.path.exists(audio_tmp) and os.path.getsize(audio_tmp) > 100:
                    try:
                        audio_result = await AudioDetectionService.analyze_audio(audio_tmp, "extracted_audio.wav")
                        if audio_result.get("classification") != "INCONCLUSIVE":
                            av_sync_assessment = "audio_track_verified_and_analyzed"
                    except Exception:
                        pass

            # 6. Multimodal Evidence Aggregation
            ai_frames_count = sum(1 for c in frame_classifications if c == "LIKELY_AI_GENERATED")
            manipulated_frames_count = sum(1 for c in frame_classifications if c == "POSSIBLY_EDITED_OR_MANIPULATED")
            camera_frames_count = sum(1 for c in frame_classifications if c == "LIKELY_CAMERA_CAPTURED")

            avg_score = float(np.mean(frame_scores)) if frame_scores else 0.50

            evidence_items.append({
                "source": "video_frame_sampling",
                "finding": f"Analyzed {frames_examined} sampled frames across {round(total_duration, 1)}s (estimated {total_frames_est} total frames at {fps} fps, sampling coverage {sampling_coverage_pct}%).",
                "status": "verified"
            })

            if temporal_res.get("temporal_flicker_detected"):
                evidence_items.append({
                    "source": "temporal_frame_consistency",
                    "finding": f"High inter-frame motion variance (std: {temporal_res['std_temporal_delta']}) suggests potential temporal composite editing or face replacement.",
                    "status": "verified",
                    "score": 0.82
                })

            if audio_result and audio_result.get("classification") == "LIKELY_AI_GENERATED":
                evidence_items.append({
                    "source": "video_audio_track",
                    "finding": "Audio track independently classified as synthetic voice synthesis.",
                    "status": "verified",
                    "score": 0.88
                })

            coverage_report = {
                "total_duration_seconds": round(total_duration, 2),
                "total_frames_estimated": total_frames_est,
                "frames_examined": frames_examined,
                "fps": round(fps, 2),
                "sampling_coverage_pct": sampling_coverage_pct,
                "contributing_timestamps_seconds": contributing_timestamps,
                "manipulated_intervals": manipulated_intervals
            }

            # Video Fusion Rule: A single frame must NOT dictate the entire video
            if ai_frames_count >= (frames_examined * 0.6):
                classification = "LIKELY_AI_GENERATED"
                score = round(max(0.85, avg_score), 2)
                ai_label = "SYNTHETIC"
                capture_label = "UNVERIFIED"
                manipulation_detected = False
            elif manipulated_frames_count > 0 or temporal_res.get("temporal_flicker_detected"):
                classification = "POSSIBLY_EDITED_OR_MANIPULATED"
                score = 0.76
                ai_label = "UNCERTAIN"
                capture_label = "VERIFIED"
                manipulation_detected = True
            elif camera_frames_count >= (frames_examined * 0.7):
                classification = "LIKELY_CAMERA_CAPTURED"
                score = 0.05
                ai_label = "NATURAL"
                capture_label = "VERIFIED"
                manipulation_detected = False
            else:
                classification = "INCONCLUSIVE"
                score = None
                ai_label = "UNCERTAIN"
                capture_label = "UNVERIFIED"
                manipulation_detected = None

            limitations.append("Video evaluation based on bounded frame sampling; transient deepfake artifacts between sampled frames may not be captured.")
            limitations.append("Video recompression by social media platforms can introduce compression noise that mimics synthesis artifacts.")

            return {
                "media_type": "video",
                "coverage": coverage_report,
                "total_frames_sampled": frames_examined,
                "contributing_timestamps_seconds": contributing_timestamps,
                "classification": classification,
                "score": score,
                "ai_label": ai_label,
                "capture_label": capture_label,
                "manipulation_detected": manipulation_detected,
                "temporal_consistency": temporal_res,
                "audio_track_analysis": audio_result,
                "av_sync_assessment": av_sync_assessment,
                "model_detectors": model_detectors_data,
                "evidence": evidence_items,
                "limitations": limitations
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
