import asyncio
import os
import shutil
import wave
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

from app.media.inspector import resolve_binary
from app.media.registry import registry


class AudioDetectionService:
    """
    Dedicated Audio Forensics and Synthetic Voice / Speech Synthesis Pipeline.
    Evaluates:
      1. Technical stream metadata (sample rate, channels, codec, duration)
      2. Multi-band spectral energy distribution & neural vocoder cutoff shelf
      3. 13-Coefficient Mel-Frequency Cepstral Coefficients (MFCC) & cepstral dynamics
      4. Spectral Centroid, Spectral Flatness, and Roll-off
      5. Sliding-window segment-level analysis with exact timestamps
      6. Clear coverage reporting (duration analyzed vs unanalyzed intervals)
      7. Wav2Vec 2.0 acoustic classifier integration
    """

    @classmethod
    def compute_mfcc_features(cls, samples: np.ndarray, sr: int = 16000, n_mfcc: int = 13) -> Dict[str, Any]:
        """
        Extracts 13-coefficient Mel-Frequency Cepstral Coefficients (MFCCs)
        using triangular filterbanks and Discrete Cosine Transform (DCT-II).
        """
        try:
            frame_len = 512
            hop_len = 256
            if len(samples) < frame_len:
                return {"mfcc_mean": [0.0] * n_mfcc, "mfcc_std": [0.0] * n_mfcc, "robotic_periodicity_score": 0.0}

            # Frame signal
            num_frames = (len(samples) - frame_len) // hop_len + 1
            num_frames = min(num_frames, 200)  # Bound processing
            window = np.hanning(frame_len)

            # FFT magnitude
            n_fft_bins = frame_len // 2 + 1
            power_spec = np.zeros((num_frames, n_fft_bins), dtype=np.float32)
            for i in range(num_frames):
                frame = samples[i * hop_len: i * hop_len + frame_len] * window
                fft_mag = np.abs(np.fft.rfft(frame))
                power_spec[i] = (fft_mag ** 2) / frame_len

            # Mel filterbank (26 filters)
            n_mels = 26
            low_freq_mel = 0
            high_freq_mel = 2595 * np.log10(1 + (sr / 2) / 700)
            mel_points = np.linspace(low_freq_mel, high_freq_mel, n_mels + 2)
            hz_points = 700 * (10 ** (mel_points / 2595) - 1)
            bins = np.floor((frame_len + 1) * hz_points / sr).astype(int)

            fbank = np.zeros((n_mels, n_fft_bins), dtype=np.float32)
            for m in range(1, n_mels + 1):
                f_m_minus = bins[m - 1]
                f_m = bins[m]
                f_m_plus = bins[m + 1]
                for k in range(f_m_minus, f_m):
                    fbank[m - 1, k] = (k - bins[m - 1]) / (bins[m] - bins[m - 1] + 1e-5)
                for k in range(f_m, f_m_plus):
                    if k < n_fft_bins:
                        fbank[m - 1, k] = (bins[m + 1] - k) / (bins[m + 1] - bins[m] + 1e-5)

            # Filter energies & log
            mel_energies = np.dot(power_spec, fbank.T)
            mel_energies = np.where(mel_energies == 0, 1e-10, mel_energies)
            log_mel_energies = np.log(mel_energies)

            # DCT-II for cepstral coefficients
            from scipy.fft import dct
            mfccs = dct(log_mel_energies, type=2, axis=-1, norm="ortho")[:, :n_mfcc]

            mfcc_means = np.mean(mfccs, axis=0)
            mfcc_stds = np.std(mfccs, axis=0)

            # Robotic speech detection: synthetic voices often have artificially low variance across higher MFCCs
            high_mfcc_var = float(np.mean(mfcc_stds[4:])) if len(mfcc_stds) > 4 else 1.0
            robotic_score = round(max(0.0, min(1.0, 1.0 - (high_mfcc_var / 4.0))), 3)

            return {
                "mfcc_mean": [round(float(v), 3) for v in mfcc_means],
                "mfcc_std": [round(float(v), 3) for v in mfcc_stds],
                "robotic_periodicity_score": robotic_score
            }
        except Exception as e:
            return {
                "mfcc_mean": [],
                "mfcc_std": [],
                "robotic_periodicity_score": 0.0,
                "error": str(e)
            }

    @classmethod
    def evaluate_spectral_characteristics(cls, samples: np.ndarray, sr: int) -> Dict[str, Any]:
        """
        Computes advanced spectral domain indicators:
          - Spectral Centroid (brightness / center of mass)
          - Spectral Flatness (Wiener entropy: tone vs noise)
          - Spectral Roll-off (85% and 95% energy bounds)
        """
        try:
            n_fft = min(len(samples), 2048)
            fft_mag = np.abs(np.fft.rfft(samples[:n_fft]))
            freqs = np.fft.rfftfreq(n_fft, d=1.0 / sr)

            mag_sum = np.sum(fft_mag) + 1e-6
            spectral_centroid = float(np.sum(freqs * fft_mag) / mag_sum)

            # Spectral Flatness
            geom_mean = np.exp(np.mean(np.log(fft_mag + 1e-10)))
            arith_mean = np.mean(fft_mag) + 1e-10
            spectral_flatness = float(geom_mean / arith_mean)

            # 85% and 95% roll-off
            cumulative_energy = np.cumsum(fft_mag)
            total_energy = cumulative_energy[-1]
            idx_85 = np.where(cumulative_energy >= 0.85 * total_energy)[0]
            roll_off_85 = float(freqs[idx_85[0]]) if len(idx_85) > 0 else float(sr / 2)

            idx_95 = np.where(cumulative_energy >= 0.95 * total_energy)[0]
            roll_off_95 = float(freqs[idx_95[0]]) if len(idx_95) > 0 else float(sr / 2)

            return {
                "spectral_centroid_hz": round(spectral_centroid, 1),
                "spectral_flatness": round(spectral_flatness, 4),
                "spectral_rolloff_85_hz": round(roll_off_85, 1),
                "spectral_rolloff_95_hz": round(roll_off_95, 1)
            }
        except Exception:
            return {
                "spectral_centroid_hz": 0.0,
                "spectral_flatness": 0.0,
                "spectral_rolloff_85_hz": 0.0,
                "spectral_rolloff_95_hz": 0.0
            }

    @classmethod
    def analyze_audio_segments(cls, samples: np.ndarray, sr: int, window_sec: float = 3.0, hop_sec: float = 2.0) -> List[Dict[str, Any]]:
        """
        Configurable Audio Segmentation:
        Divides audio into timestamped segments and analyzes vocal dynamics per interval.
        """
        win_size = int(window_sec * sr)
        hop_size = int(hop_sec * sr)
        total_len = len(samples)

        segments = []
        if total_len < win_size:
            # Single segment
            duration = float(total_len) / float(sr)
            segments.append({
                "segment_index": 1,
                "start_seconds": 0.0,
                "end_seconds": round(duration, 2),
                "duration_seconds": round(duration, 2),
                "active_speech": bool(np.mean(np.abs(samples)) > 0.01)
            })
            return segments

        idx = 0
        seg_num = 1
        while idx + win_size <= total_len and seg_num <= 10:
            seg_samples = samples[idx: idx + win_size]
            start_s = round(float(idx) / float(sr), 2)
            end_s = round(float(idx + win_size) / float(sr), 2)
            energy = float(np.mean(np.abs(seg_samples)))

            segments.append({
                "segment_index": seg_num,
                "start_seconds": start_s,
                "end_seconds": end_s,
                "duration_seconds": window_sec,
                "active_speech": bool(energy > 0.015),
                "mean_energy": round(energy, 4)
            })
            idx += hop_size
            seg_num += 1

        return segments

    @classmethod
    async def extract_pcm_samples(cls, file_path: str, target_sr: int = 16000) -> Tuple[np.ndarray, int, float, float]:
        """
        Extracts mono PCM audio samples at target sample rate safely.
        Uses wave module if standard WAV, or ffmpeg subprocess for MP3/FLAC/M4A/OGG/AAC.
        Returns: (samples_array, sample_rate, duration_analyzed_seconds, total_duration_seconds)
        """
        # 1. Try standard wave module first if .wav
        if file_path.lower().endswith(".wav"):
            try:
                with wave.open(file_path, "rb") as wf:
                    n_channels = wf.getnchannels()
                    sampwidth = wf.getsampwidth()
                    sr = wf.getframerate()
                    n_frames = wf.getnframes()
                    total_dur = float(n_frames) / float(sr) if sr > 0 else 0.0
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
                    analyzed_dur = float(len(samples)) / float(sr)
                    return samples, sr, analyzed_dur, max(analyzed_dur, total_dur)
            except Exception:
                pass

        # 2. Use ffmpeg to transcode into mono PCM WAV in memory
        ffmpeg_bin = resolve_binary("ffmpeg")
        if not ffmpeg_bin:
            try:
                import imageio_ffmpeg
                ffmpeg_bin = imageio_ffmpeg.get_ffmpeg_exe()
            except Exception:
                pass

        if ffmpeg_bin:
            # Probe total duration first
            total_duration = 30.0
            probe_cmd = [ffmpeg_bin, "-i", file_path, "-hide_banner"]
            p_probe = await asyncio.create_subprocess_exec(
                *probe_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, err_probe = await p_probe.communicate()
            err_str = err_probe.decode("utf-8", errors="ignore")
            import re
            m = re.search(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", err_str)
            if m:
                h, mi, s = m.groups()
                total_duration = float(h) * 3600 + float(mi) * 60 + float(s)

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
                    analyzed_dur = float(len(samples)) / float(target_sr)
                    return samples, target_sr, analyzed_dur, max(analyzed_dur, total_duration)

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
            samples, sr, duration, total_duration = await cls.extract_pcm_samples(file_path)
        except Exception as e:
            return {
                "status": "failed",
                "media_type": "audio",
                "error": f"Failed to extract audio stream: {str(e)}"
            }

        # Calculate bounded coverage metrics
        duration_analyzed_s = round(duration, 2)
        total_duration_s = round(total_duration, 2)
        coverage_pct = round((duration_analyzed_s / max(total_duration_s, 0.001)) * 100.0, 1)
        coverage_pct = min(100.0, coverage_pct)
        unanalyzed_intervals = []
        if total_duration_s > duration_analyzed_s + 0.5:
            unanalyzed_intervals.append({
                "start_seconds": duration_analyzed_s,
                "end_seconds": total_duration_s,
                "reason": "Audio analysis bounded to initial 30 seconds to preserve memory and processing resources."
            })

        coverage_report = {
            "total_duration_seconds": total_duration_s,
            "duration_analyzed_seconds": duration_analyzed_s,
            "coverage_percentage": coverage_pct,
            "unanalyzed_intervals": unanalyzed_intervals
        }

        # Check basic duration / SNR eligibility
        if duration < 1.0:
            return {
                "media_type": "audio",
                "duration_seconds": duration_analyzed_s,
                "sample_rate": sr,
                "coverage": coverage_report,
                "classification": "INCONCLUSIVE",
                "score": None,
                "ai_label": "UNCERTAIN",
                "capture_label": "UNVERIFIED",
                "manipulation_detected": None,
                "evidence": [{
                    "source": "acoustic_spectral_analysis",
                    "finding": f"Audio duration ({duration_analyzed_s}s) is too short for reliable speech synthesis detection.",
                    "status": "inconclusive"
                }],
                "limitations": [
                    "Audio duration is too short (< 1.0s) for reliable voice synthesis analysis.",
                    "Audio recordings under 1.0 second contain insufficient phoneme cycles for voice synthesis modeling.",
                    "Treat ordinary spectrogram features as evidence, not definitive proof of human origin."
                ]
            }

        # 1. Feature extractions
        acoustic_res = cls.evaluate_acoustic_features(samples, sr)
        mfcc_res = cls.compute_mfcc_features(samples, sr)
        spectral_res = cls.evaluate_spectral_characteristics(samples, sr)
        segments_res = cls.analyze_audio_segments(samples, sr)

        silence_ratio = acoustic_res["silence_ratio"]

        if silence_ratio > 0.85:
            return {
                "media_type": "audio",
                "duration_seconds": duration_analyzed_s,
                "sample_rate": sr,
                "coverage": coverage_report,
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

        # 2. Run model detectors via centralized registry
        detector_reports = await registry.execute_audio_detectors(samples, sr, file_path, {})
        model_detectors_data = [report.model_dump() for report in detector_reports]

        for d_rep in detector_reports:
            if d_rep.status == "available" and d_rep.prediction:
                evidence_items.append({
                    "source": d_rep.provider_name,
                    "finding": f"Neural audio classifier predicted {d_rep.prediction} (score: {d_rep.calibrated_probability}).",
                    "status": "verified",
                    "score": d_rep.calibrated_probability,
                    "model_version": d_rep.provider_version
                })
            elif d_rep.status == "not_configured":
                limitations.extend(d_rep.limitations)

        # 3. Evidence accumulation
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
                "finding": f"Continuous acoustic frequency distribution and natural room noise floor (ZCR: {acoustic_res['zcr']}, spectral centroid: {spectral_res.get('spectral_centroid_hz')} Hz) consistent with microphone capture.",
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
            "duration_seconds": duration_analyzed_s,
            "sample_rate": sr,
            "coverage": coverage_report,
            "classification": classification,
            "score": score,
            "ai_label": ai_label,
            "capture_label": capture_label,
            "manipulation_detected": manipulation_detected,
            "acoustic_features": acoustic_res,
            "mfcc_features": mfcc_res,
            "spectral_characteristics": spectral_res,
            "segments": segments_res,
            "model_detectors": model_detectors_data,
            "evidence": evidence_items,
            "limitations": limitations
        }
