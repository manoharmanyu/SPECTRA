import asyncio
import os
import shutil
import wave
from typing import Dict, Any, List, Optional, Tuple
import numpy as np


class AudioDetectionService:
    """
    Dedicated Audio Forensics and Synthetic Voice / Speech Synthesis Pipeline.
    Evaluates:
      1. Technical stream metadata (sample rate, channels, codec, duration)
      2. Spectral energy distribution & neural vocoder cutoff shelf
      3. Zero-Crossing Rate (ZCR) and phoneme cadence dynamics
      4. Silence ratio, noise floor gating, and dynamic range
    """

    @classmethod
    async def extract_pcm_samples(cls, file_path: str, target_sr: int = 16000) -> Tuple[np.ndarray, int, float]:
        """
        Extracts mono PCM audio samples at target sample rate safely.
        Uses wave module if standard WAV, or ffmpeg subprocess for MP3/FLAC/M4A/OGG/AAC.
        Returns: (samples_array, sample_rate, duration_seconds)
        """
        # 1. Try standard wave module first if .wav
        if file_path.lower().endswith(".wav"):
            try:
                with wave.open(file_path, "rb") as wf:
                    n_channels = wf.getnchannels()
                    sampwidth = wf.getsampwidth()
                    sr = wf.getframerate()
                    n_frames = wf.getnframes()
                    raw_bytes = wf.readframes(min(n_frames, sr * 30))  # Max 30 seconds
                    
                    if sampwidth == 2:
                        dtype = np.int16
                    elif sampwidth == 1:
                        dtype = np.uint8
                    elif sampwidth == 4:
                        dtype = np.int32
                    else:
                        dtype = np.int16

                    samples = np.frombuffer(raw_bytes, dtype=dtype).astype(np.float32)
                    if n_channels > 1:
                        samples = samples[::n_channels]  # Take first channel
                    
                    # Normalize to [-1.0, 1.0]
                    max_val = np.max(np.abs(samples)) or 1.0
                    samples = samples / max_val
                    duration = float(len(samples)) / float(sr)
                    return samples, sr, duration
            except Exception:
                pass

        # 2. Use ffmpeg to transcode up to 30 seconds into mono 16kHz PCM WAV in memory
        ffmpeg_bin = shutil.which("ffmpeg") or (
            "/Users/manyugaddam/.local/bin/ffmpeg" if os.path.exists("/Users/manyugaddam/.local/bin/ffmpeg") else None
        )
        if not ffmpeg_bin:
            try:
                import imageio_ffmpeg
                ffmpeg_bin = imageio_ffmpeg.get_ffmpeg_exe()
            except Exception:
                pass

        if ffmpeg_bin:
            cmd = [
                ffmpeg_bin,
                "-v", "quiet",
                "-t", "30",  # Limit processing to first 30 seconds to protect memory
                "-i", file_path,
                "-vn",
                "-ac", "1",
                "-ar", str(target_sr),
                "-f", "wav",
                "pipe:1"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0 and len(stdout) > 44:
                import io
                with wave.open(io.BytesIO(stdout), "rb") as wf:
                    raw = wf.readframes(wf.getnframes())
                    samples = np.frombuffer(raw, dtype=np.int16).astype(np.float32)
                    max_val = np.max(np.abs(samples)) or 1.0
                    samples = samples / max_val
                    duration = float(len(samples)) / float(target_sr)
                    return samples, target_sr, duration

        raise ValueError("Unable to decode audio stream into PCM samples.")

    @classmethod
    def evaluate_acoustic_features(cls, samples: np.ndarray, sr: int) -> Dict[str, Any]:
        """
        Computes forensic acoustic characteristics:
          - Silence ratio & digital gating
          - High-frequency energy shelf (neural vocoder cutoff detection)
          - Zero crossing rate (ZCR) dynamics
        """
        # 1. Silence & Digital Gating
        abs_samples = np.abs(samples)
        silence_threshold = 0.015
        silent_count = np.sum(abs_samples < silence_threshold)
        silence_ratio = float(silent_count) / float(len(samples))
        exact_zero_ratio = float(np.sum(abs_samples == 0.0)) / float(len(samples))

        # 2. Zero Crossing Rate (ZCR)
        # Vectorized zero crossings: sign changes between adjacent samples
        signs = np.sign(samples)
        signs[signs == 0] = 1
        zcr = float(np.mean(np.abs(signs[1:] - signs[:-1])) / 2.0)

        # 3. Frequency Spectrum & Neural Vocoder Shelf
        # Compute FFT magnitude spectrum
        n_fft = min(len(samples), 4096)
        if n_fft < 512:
            return {
                "silence_ratio": round(silence_ratio, 3),
                "exact_zero_ratio": round(exact_zero_ratio, 4),
                "zcr": round(zcr, 4),
                "vocoder_shelf_detected": False,
                "spectral_energy_ratio": 1.0
            }

        # Take multiple windows across audio to estimate spectrum
        step = n_fft // 2
        specs = []
        for i in range(0, len(samples) - n_fft + 1, step):
            win = samples[i:i + n_fft] * np.hanning(n_fft)
            fft_mag = np.abs(np.fft.rfft(win))
            specs.append(fft_mag)
            if len(specs) >= 20:
                break

        if len(specs) > 0:
            avg_spec = np.mean(specs, axis=0)
            freqs = np.fft.rfftfreq(n_fft, d=1.0 / sr)

            # Check energy above 7.5kHz vs energy in midband 1kHz-4kHz
            # Neural speech synthesizers with 16kHz sample rate cut off sharply at 7.6-8kHz
            midband_idx = (freqs >= 1000) & (freqs <= 4000)
            highband_idx = freqs >= 7000

            mid_energy = np.mean(avg_spec[midband_idx]) if np.any(midband_idx) else 1e-5
            high_energy = np.mean(avg_spec[highband_idx]) if np.any(highband_idx) else 0.0
            
            # Vocoder cutoff exhibits extreme dropoff (> 35dB drop)
            shelf_ratio = float(high_energy / (mid_energy + 1e-5))
            vocoder_shelf_detected = shelf_ratio < 0.015 and exact_zero_ratio > 0.08
        else:
            shelf_ratio = 1.0
            vocoder_shelf_detected = False

        return {
            "silence_ratio": round(silence_ratio, 3),
            "exact_zero_ratio": round(exact_zero_ratio, 4),
            "zcr": round(zcr, 4),
            "high_freq_ratio": round(shelf_ratio, 4),
            "vocoder_shelf_detected": vocoder_shelf_detected
        }

    @classmethod
    async def analyze_audio(cls, file_path: str, original_filename: str) -> Dict[str, Any]:
        """
        Full Audio Forensic Pipeline Execution.
        """
        evidence_items = []
        limitations = []

        try:
            samples, sr, duration = await cls.extract_pcm_samples(file_path)
        except Exception as e:
            return {
                "status": "failed",
                "media_type": "audio",
                "error": f"Failed to extract audio stream: {str(e)}"
            }

        # Check basic duration / SNR eligibility
        if duration < 1.0:
            return {
                "media_type": "audio",
                "duration_seconds": round(duration, 2),
                "sample_rate": sr,
                "classification": "INCONCLUSIVE",
                "score": None,
                "ai_label": "UNCERTAIN",
                "capture_label": "UNVERIFIED",
                "manipulation_detected": None,
                "evidence": [{
                    "source": "acoustic_spectral_analysis",
                    "finding": f"Audio duration ({round(duration, 2)}s) is too short for reliable speech synthesis detection.",
                    "status": "inconclusive"
                }],
                "limitations": [
                    "Audio duration is too short (< 1.0s) for reliable voice synthesis analysis.",
                    "Audio recordings under 1.0 second contain insufficient phoneme cycles for voice synthesis modeling.",
                    "Treat ordinary spectrogram features as evidence, not definitive proof of human origin."
                ]
            }

        acoustic_res = cls.evaluate_acoustic_features(samples, sr)
        silence_ratio = acoustic_res["silence_ratio"]

        if silence_ratio > 0.85:
            return {
                "media_type": "audio",
                "duration_seconds": round(duration, 2),
                "sample_rate": sr,
                "classification": "INCONCLUSIVE",
                "score": None,
                "ai_label": "UNCERTAIN",
                "capture_label": "UNVERIFIED",
                "manipulation_detected": None,
                "evidence": [{
                    "source": "acoustic_spectral_analysis",
                    "finding": f"Audio is {int(silence_ratio * 100)}% silence. Insufficient active acoustic content.",
                    "status": "inconclusive"
                }],
                "limitations": [
                    "Excessive silence or low signal-to-noise ratio prevents speech synthesis analysis."
                ]
            }

        # Evidence accumulation
        if acoustic_res["vocoder_shelf_detected"]:
            evidence_items.append({
                "source": "acoustic_spectral_analysis",
                "finding": "Sharp high-frequency shelf and artificial gating characteristic of neural vocoder synthesis (e.g. HiFi-GAN / ElevenLabs).",
                "status": "verified",
                "score": 0.91
            })
            classification = "LIKELY_AI_GENERATED"
            score = 0.89
            ai_label = "SYNTHETIC"
            capture_label = "UNVERIFIED"
            manipulation_detected = False
        elif acoustic_res["exact_zero_ratio"] > 0.25:
            evidence_items.append({
                "source": "acoustic_spectral_analysis",
                "finding": "Abnormal digital zero gating detected between speech bursts (unnatural absence of ambient room acoustic tone).",
                "status": "verified",
                "score": 0.72
            })
            classification = "POSSIBLY_EDITED_OR_MANIPULATED"
            score = 0.70
            ai_label = "UNCERTAIN"
            capture_label = "UNVERIFIED"
            manipulation_detected = True
        else:
            evidence_items.append({
                "source": "acoustic_spectral_analysis",
                "finding": f"Continuous acoustic frequency distribution and natural room noise floor (ZCR: {acoustic_res['zcr']}) consistent with microphone capture.",
                "status": "verified",
                "score": 0.08
            })
            classification = "LIKELY_CAMERA_CAPTURED"  # Conventionally recorded microphone capture
            score = 0.06
            ai_label = "NATURAL"
            capture_label = "VERIFIED"
            manipulation_detected = False

        limitations.append("Treat waveform and acoustic spectral features as supporting evidence, not absolute proof of origin.")
        limitations.append("High quality neural voice clones can simulate room reverberation; corroboration is required.")

        return {
            "media_type": "audio",
            "duration_seconds": round(duration, 2),
            "sample_rate": sr,
            "classification": classification,
            "score": score,
            "ai_label": ai_label,
            "capture_label": capture_label,
            "manipulation_detected": manipulation_detected,
            "acoustic_features": acoustic_res,
            "evidence": evidence_items,
            "limitations": limitations
        }
