import io
import math
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from PIL import Image, ImageFilter
import numpy as np


@dataclass
class ConfusionMatrix:
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    total_samples: int

    def to_dict(self) -> Dict[str, int]:
        return {
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "total_samples": self.total_samples
        }


@dataclass
class EvaluationMetrics:
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float
    pr_auc: float
    brier_score: float
    expected_calibration_error: float
    confusion_matrix: ConfusionMatrix
    per_generator_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "roc_auc": round(self.roc_auc, 4),
            "pr_auc": round(self.pr_auc, 4),
            "brier_score": round(self.brier_score, 4),
            "expected_calibration_error": round(self.expected_calibration_error, 4),
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "per_generator_metrics": self.per_generator_metrics
        }


def compute_roc_auc(y_true: List[int], y_scores: List[float]) -> float:
    """Computes Area Under ROC Curve via Mann-Whitney U rank statistic."""
    pos = sum(1 for y in y_true if y == 1)
    neg = len(y_true) - pos
    if pos == 0 or neg == 0:
        return 0.5

    # Pairwise ranks
    indexed_scores = sorted(enumerate(y_scores), key=lambda x: x[1])
    rank_sum = 0.0
    for rank, (orig_idx, _) in enumerate(indexed_scores, start=1):
        if y_true[orig_idx] == 1:
            rank_sum += rank

    u_stat = rank_sum - (pos * (pos + 1)) / 2.0
    return float(max(0.0, min(1.0, u_stat / (pos * neg))))


def compute_pr_auc(y_true: List[int], y_scores: List[float]) -> float:
    """Computes Precision-Recall Area Under Curve using trapezoidal numerical integration."""
    thresholds = sorted(set(y_scores), reverse=True)
    if not thresholds:
        return 0.0

    precisions = []
    recalls = []

    pos_total = sum(y_true)
    if pos_total == 0:
        return 0.0

    for thresh in thresholds:
        tp = sum(1 for yt, s in zip(y_true, y_scores) if yt == 1 and s >= thresh)
        fp = sum(1 for yt, s in zip(y_true, y_scores) if yt == 0 and s >= thresh)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / pos_total
        precisions.append(prec)
        recalls.append(rec)

    # Trapezoid rule over sorted recall values
    rec_prec = sorted(zip(recalls, precisions), key=lambda x: x[0])
    auc = 0.0
    for i in range(len(rec_prec) - 1):
        r1, p1 = rec_prec[i]
        r2, p2 = rec_prec[i + 1]
        auc += (r2 - r1) * (p1 + p2) / 2.0

    return float(max(0.0, min(1.0, auc)))


def compute_expected_calibration_error(y_true: List[int], y_probs: List[float], n_bins: int = 5) -> float:
    """
    Computes Expected Calibration Error (ECE) across probability bins:
    ECE = sum(|B_m| / N * |acc(B_m) - conf(B_m)|)
    """
    if not y_true or len(y_true) != len(y_probs):
        return 0.0

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    total = len(y_true)

    for i in range(n_bins):
        b_low, b_high = bins[i], bins[i + 1]
        indices = [idx for idx, p in enumerate(y_probs) if b_low <= p < b_high or (i == n_bins - 1 and p == b_high)]
        if not indices:
            continue

        bin_size = len(indices)
        bin_acc = sum(y_true[idx] for idx in indices) / float(bin_size)
        bin_conf = sum(y_probs[idx] for idx in indices) / float(bin_size)
        ece += (bin_size / total) * abs(bin_acc - bin_conf)

    return float(ece)


def compute_evaluation_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_scores: List[float],
    generators: Optional[List[str]] = None
) -> EvaluationMetrics:
    """
    Computes complete digital forensic evaluation metrics:
    Accuracy, Precision, Recall, F1, FPR, FNR, ROC-AUC, PR-AUC, Brier Score, and ECE.
    """
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    accuracy = (tp + tn) / max(total, 1)
    precision = tp / max(tp + fp, 1) if (tp + fp) > 0 else 0.0
    recall = tp / max(tp + fn, 1) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / max(precision + recall, 1e-6) if (precision + recall) > 0 else 0.0

    fpr = fp / max(fp + tn, 1) if (fp + tn) > 0 else 0.0
    fnr = fn / max(fn + tp, 1) if (fn + tp) > 0 else 0.0

    roc_auc = compute_roc_auc(y_true, y_scores)
    pr_auc = compute_pr_auc(y_true, y_scores)

    # Brier Score: 1/N sum (p_i - y_i)^2
    brier = float(np.mean([(p - yt) ** 2 for p, yt in zip(y_scores, y_true)])) if total > 0 else 0.0

    # Expected Calibration Error
    ece = compute_expected_calibration_error(y_true, y_scores)

    # Per-generator breakdown
    per_gen = {}
    if generators and len(generators) == total:
        unique_gens = sorted(set(generators))
        for g in unique_gens:
            g_indices = [idx for idx, gen in enumerate(generators) if gen == g]
            g_yt = [y_true[idx] for idx in g_indices]
            g_yp = [y_pred[idx] for idx in g_indices]
            g_acc = sum(1 for a, b in zip(g_yt, g_yp) if a == b) / float(len(g_indices))
            per_gen[g] = {
                "sample_count": len(g_indices),
                "accuracy": round(g_acc, 4)
            }

    cm = ConfusionMatrix(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        total_samples=total
    )

    return EvaluationMetrics(
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        brier_score=brier,
        expected_calibration_error=ece,
        confusion_matrix=cm,
        per_generator_metrics=per_gen
    )


# --- ADVERSARIAL STRESS TEST PERTURBATIONS ---

def apply_image_adversarial_transforms(img: Image.Image) -> Dict[str, Image.Image]:
    """
    Applies standard adversarial and post-processing robustness perturbations:
      1. JPEG recompression (quality=50 and quality=30)
      2. Bilinear downsampling and restoration
      3. Spatial central crop (85% area)
      4. Gaussian noise injection
      5. Gaussian slight blur
    """
    transforms = {}

    # 1. JPEG Compression Quality 50
    buf50 = io.BytesIO()
    img.convert("RGB").save(buf50, format="JPEG", quality=50)
    buf50.seek(0)
    transforms["jpeg_q50"] = Image.open(buf50).copy()

    # 2. Heavy JPEG Compression Quality 30
    buf30 = io.BytesIO()
    img.convert("RGB").save(buf30, format="JPEG", quality=30)
    buf30.seek(0)
    transforms["jpeg_q30"] = Image.open(buf30).copy()

    # 3. Downscale 50% and Upscale (mimics social media messenger sharing)
    w, h = img.size
    small = img.resize((max(16, w // 2), max(16, h // 2)), Image.Resampling.BILINEAR)
    restored = small.resize((w, h), Image.Resampling.BILINEAR)
    transforms["resize_50pct"] = restored

    # 4. Central Spatial Crop (85% bounding box)
    cw, ch = int(w * 0.85), int(h * 0.85)
    cx, cy = (w - cw) // 2, (h - ch) // 2
    crop_img = img.crop((cx, cy, cx + cw, cy + ch)).resize((w, h), Image.Resampling.BILINEAR)
    transforms["central_crop_85pct"] = crop_img

    # 5. Gaussian Noise Injection (simulates sensor shot noise)
    arr = np.array(img.convert("RGB"), dtype=np.float32)
    noise = np.random.normal(0, 10.0, arr.shape)
    noisy_arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
    transforms["gaussian_noise_sigma10"] = Image.fromarray(noisy_arr)

    return transforms


def apply_audio_adversarial_transforms(samples: np.ndarray, sr: int = 16000) -> Dict[str, np.ndarray]:
    """
    Applies standard audio robustness perturbations:
      1. Additive Gaussian background noise (SNR ~ 15dB)
      2. 8-bit dynamic range quantization
      3. Mild amplitude gain scaling
    """
    transforms = {}

    # 1. Additive noise
    signal_power = np.mean(samples ** 2) + 1e-6
    target_noise_power = signal_power / (10 ** (15 / 10))  # 15 dB SNR
    noise = np.random.normal(0, np.sqrt(target_noise_power), samples.shape).astype(np.float32)
    transforms["noise_snr_15db"] = np.clip(samples + noise, -1.0, 1.0)

    # 2. Dynamic range quantization (8-bit re-quantization)
    quantized = np.round(samples * 127) / 127.0
    transforms["quantization_8bit"] = quantized.astype(np.float32)

    # 3. Gain scale (-3dB attenuation)
    transforms["attenuation_neg3db"] = (samples * 0.707).astype(np.float32)

    return transforms


@dataclass
class AdversarialStressTestResult:
    baseline_metrics: Dict[str, Any]
    perturbed_metrics: Dict[str, Dict[str, Any]]
    resilience_summary: str


def evaluate_dataset_cross_generator(
    samples: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Evaluates dataset cross-generator distribution preventing generator leakage.
    Each item in samples: {"label": 0|1, "score": float, "generator": str}
    """
    y_true = [s["label"] for s in samples]
    y_scores = [s["score"] for s in samples]
    y_pred = [1 if s >= 0.5 else 0 for s in y_scores]
    generators = [s.get("generator", "unknown") for s in samples]

    metrics = compute_evaluation_metrics(y_true, y_pred, y_scores, generators)
    return metrics.to_dict()
