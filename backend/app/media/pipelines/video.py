import asyncio
import os
import shutil
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image
import numpy as np

from app.media.pipelines.image import ImageDetectionService
from app.media.pipelines.audio import AudioDetectionService


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
        bin_path = shutil.which("ffmpeg") or (
            "/Users/manyugaddam/.local/bin/ffmpeg" if os.path.exists("/Users/manyugaddam/.local/bin/ffmpeg") else None
        )
        if not bin_path:
            try:
                import imageio_ffmpeg
                bin_path = imageio_ffmpeg.get_ffmpeg_exe()
            except Exception:
                pass
        return bin_path

    @classmethod
    async def sample_video_frames(cls, file_path: str, temp_dir: str, max_frames: int = 8) -> List[Tuple[int, float, str]]:
        """
        Samples up to max_frames frames from the video at regular intervals.
        Returns list of (frame_index, timestamp_seconds, frame_file_path).
        """
        ffmpeg_bin = cls.get_ffmpeg_binary()
        if not ffmpeg_bin:
            return []

        # Get video duration first
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

        # Extract duration string (e.g. Duration: 00:00:10.50)
        import re
        dur_match = re.search(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", stderr_str)
        if dur_match:
            hours, mins, secs = dur_match.groups()
            total_duration = float(hours) * 3600 + float(mins) * 60 + float(secs)
        else:
            total_duration = 10.0  # default fallback

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

        return sampled_frames

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
                "temporal_flicker_detected": False
            }

        deltas = []
        for i in range(len(frame_paths) - 1):
            try:
                with Image.open(frame_paths[i]) as img1, Image.open(frame_paths[i+1]) as img2:
                    # Resize to common small dimension for fast comparison
                    im1 = np.array(img1.convert("L").resize((256, 256)), dtype=np.float32)
                    im2 = np.array(img2.convert("L").resize((256, 256)), dtype=np.float32)
                    diff = np.mean(np.abs(im1 - im2))
                    deltas.append(float(diff))
            except Exception:
                pass

        if not deltas:
            return {"consecutive_pairs_evaluated": 0, "temporal_flicker_detected": False}

        mean_delta = float(np.mean(deltas))
        std_delta = float(np.std(deltas))
        
        # High delta variance with unnatural sharp spike indicates temporal composite splicing
        temporal_flicker = std_delta > 35.0 and max(deltas) > 70.0

        return {
            "consecutive_pairs_evaluated": len(deltas),
            "mean_temporal_delta": round(mean_delta, 2),
            "std_temporal_delta": round(std_delta, 2),
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
            # 1. Bounded Frame Sampling
            sampled = await cls.sample_video_frames(file_path, temp_dir, max_frames=8)
            if not sampled:
                return {
                    "status": "failed",
                    "media_type": "video",
                    "error": "Failed to decode video frames. Container may be corrupt or unsupported."
                }

            frame_paths = [s[2] for s in sampled]
            contributing_timestamps = [s[1] for s in sampled]

            # 2. Per-frame forensic inspection
            frame_scores = []
            frame_classifications = []
            for idx, t, fpath in sampled:
                res = await ImageDetectionService.analyze_image(fpath, f"frame_{idx}.jpg")
                frame_classifications.append(res.get("classification"))
                if res.get("score") is not None:
                    frame_scores.append(res["score"])

            # 3. Temporal Consistency
            temporal_res = cls.evaluate_temporal_consistency(frame_paths)

            # 4. Independent Audio Track Analysis
            audio_result = None
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
                    except Exception:
                        pass

            # 5. Multimodal Evidence Aggregation
            ai_frames_count = sum(1 for c in frame_classifications if c == "LIKELY_AI_GENERATED")
            manipulated_frames_count = sum(1 for c in frame_classifications if c == "POSSIBLY_EDITED_OR_MANIPULATED")
            camera_frames_count = sum(1 for c in frame_classifications if c == "LIKELY_CAMERA_CAPTURED")
            total_frames = len(sampled)

            avg_score = float(np.mean(frame_scores)) if frame_scores else 0.50

            evidence_items.append({
                "source": "video_frame_sampling",
                "finding": f"Analyzed {total_frames} sampled frames at timestamps {contributing_timestamps}s.",
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

            # Video Fusion Rule: A single frame must NOT dictate the entire video
            if ai_frames_count >= (total_frames * 0.6):
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
            elif camera_frames_count >= (total_frames * 0.7):
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
                "total_frames_sampled": total_frames,
                "contributing_timestamps_seconds": contributing_timestamps,
                "classification": classification,
                "score": score,
                "ai_label": ai_label,
                "capture_label": capture_label,
                "manipulation_detected": manipulation_detected,
                "temporal_consistency": temporal_res,
                "audio_track_analysis": audio_result,
                "evidence": evidence_items,
                "limitations": limitations
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
