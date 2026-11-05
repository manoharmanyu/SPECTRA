import math
import numpy as np
import pytest
from PIL import Image
import io

from app.media.models.base import ModelAvailability
from app.media.models.xception import XceptionNetImageDetector
from app.media.models.efficientnet import EfficientNetImageDetector
from app.media.models.wav2vec import Wav2Vec2AudioDetector
from app.media.models.cnn_lstm import CNNLSTMTemporalDetector
from app.media.models.prnu import SensorPRNUAnalyzer
from app.media.models.quantization import JPEGQuantizationAnalyzer
from app.media.models.face_analyzer import FaceRegionAnalyzer
from app.media.pipelines.image import ImageDetectionService


@pytest.mark.asyncio
async def test_unconfigured_models_do_not_fabricate_scores():
    """
    Verify that models without downloaded weights strictly return NOT_CONFIGURED
    and do not fabricate synthetic confidence scores or predictions.
    """
    img = Image.new("RGB", (256, 256), color=(100, 150, 200))

    # 1. XceptionNet
    x_det = XceptionNetImageDetector(weights_path="/nonexistent/xception.pth")
    assert not x_det.is_configured()
    x_res = await x_det.predict(img)
    assert x_res.availability == ModelAvailability.NOT_CONFIGURED
    assert x_res.raw_score is None
    assert x_res.prediction == "INCONCLUSIVE"
    assert "not installed" in x_res.reason

    # 2. EfficientNet
    e_det = EfficientNetImageDetector(weights_path="/nonexistent/effnet.pth")
    assert not e_det.is_configured()
    e_res = await e_det.predict(img)
    assert e_res.availability == ModelAvailability.NOT_CONFIGURED
    assert e_res.raw_score is None

    # 3. Wav2Vec 2.0
    w_det = Wav2Vec2AudioDetector(weights_path="/nonexistent/wav2vec")
    assert not w_det.is_configured()
    w_res = await w_det.predict(np.zeros(16000, dtype=np.float32), 16000)
    assert w_res.availability == ModelAvailability.NOT_CONFIGURED
    assert w_res.raw_score is None

    # 4. CNN-LSTM Video
    c_det = CNNLSTMTemporalDetector(weights_path="/nonexistent/cnn_lstm.pt")
    assert not c_det.is_configured()
    c_res = await c_det.predict([np.zeros((224, 224, 3), dtype=np.uint8)])
    assert c_res.availability == ModelAvailability.NOT_CONFIGURED
    assert c_res.raw_score is None


def test_prnu_sensor_correlation_separation():
    """
    Verify PRNU sensor noise residual computation is decoupled from reference camera matching.
    Without an enrolled reference camera, sensor_match_verified MUST be False and correlation None.
    """
    img = Image.new("RGB", (128, 128), color=(120, 120, 120))
    # Add minor deterministic spatial noise
    im_arr = np.array(img, dtype=np.float32)
    im_arr[::2, ::2] += 2.0
    noisy_img = Image.fromarray(np.clip(im_arr, 0, 255).astype(np.uint8))

    res = SensorPRNUAnalyzer.evaluate_sensor_prnu_correlation(noisy_img)
    assert res["status"] == "REFERENCE_FINGERPRINT_UNAVAILABLE"
    assert res["sensor_match_verified"] is False
    assert res["normalized_cross_correlation"] is None
    assert "residual_stats" in res
    assert res["residual_stats"]["residual_std"] > 0.0


def test_jpeg_quantization_analysis(tmp_path):
    """
    Verify JPEG DQT quantization table extraction, Q-factor estimation,
    and double-compression anomaly detection.
    """
    img = Image.new("RGB", (128, 128), color=(200, 100, 50))
    jpeg_file = tmp_path / "test_quant.jpg"
    img.save(str(jpeg_file), format="JPEG", quality=85)

    dqt_res = JPEGQuantizationAnalyzer.analyze_jpeg_compression(str(jpeg_file))
    assert dqt_res["quantization_present"] is True
    assert dqt_res["dqt_tables_count"] >= 1
    assert "estimated_quality_factor" in dqt_res
    assert 80 <= dqt_res["estimated_quality_factor"] <= 90
    assert "tables" in dqt_res
    assert len(dqt_res["tables"][0]["matrix"]) == 8


def test_face_boundary_seam_analysis():
    """
    Verify face region seam analysis evaluates border discontinuities without crashing.
    """
    face_img = Image.new("RGB", (100, 100), color=(220, 180, 140))
    face_res = FaceRegionAnalyzer.analyze_faces(face_img)
    assert "faces_detected_count" in face_res
    assert "face_swap_indicator_detected" in face_res
    assert isinstance(face_res["face_swap_indicator_detected"], bool)


from app.media.eval.benchmark import (
    compute_evaluation_metrics,
    apply_image_adversarial_transforms,
    apply_audio_adversarial_transforms,
    evaluate_dataset_cross_generator
)


def test_forensic_evaluation_benchmark_metrics():
    """
    Executes a calibrated verification benchmark and verifies statistical evaluation metrics:
    Accuracy, Precision, Recall, F1, FPR, FNR, ROC-AUC, PR-AUC, Brier score, and ECE.
    """
    # Ground-truth: 1 = synthetic/AI, 0 = authentic camera
    ground_truth = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
    predictions  = [1, 1, 1, 1, 0, 0, 0, 0, 0, 1]  # 4 TP, 1 FN, 4 TN, 1 FP
    scores       = [0.95, 0.92, 0.88, 0.84, 0.40, 0.12, 0.08, 0.15, 0.05, 0.75]
    generators   = ["Midjourney", "StableDiffusion", "DALL-E-3", "Flux", "StyleGAN",
                    "iPhone15", "CanonR5", "NikonZ9", "SonyA7IV", "Pixel8"]

    metrics = compute_evaluation_metrics(ground_truth, predictions, scores, generators)
    res = metrics.to_dict()

    assert res["accuracy"] == 0.8
    assert res["precision"] == 0.8
    assert res["recall"] == 0.8
    assert res["f1_score"] == 0.8
    assert res["false_positive_rate"] == 0.2
    assert res["false_negative_rate"] == 0.2
    assert res["roc_auc"] >= 0.85
    assert res["pr_auc"] >= 0.70
    assert 0.0 <= res["brier_score"] <= 1.0
    assert 0.0 <= res["expected_calibration_error"] <= 1.0
    assert res["confusion_matrix"]["true_positives"] == 4
    assert res["confusion_matrix"]["true_negatives"] == 4
    assert res["confusion_matrix"]["false_positives"] == 1
    assert res["confusion_matrix"]["false_negatives"] == 1
    assert res["confusion_matrix"]["total_samples"] == 10
    assert "Midjourney" in res["per_generator_metrics"]


def test_adversarial_perturbation_transforms():
    """
    Verifies that adversarial stress transforms (JPEG q50/q30, downscale, crop, noise)
    generate valid perturbed images and audio signals for robustness testing.
    """
    # 1. Image perturbations
    img = Image.new("RGB", (128, 128), color=(100, 150, 200))
    perturbed_images = apply_image_adversarial_transforms(img)
    assert "jpeg_q50" in perturbed_images
    assert "jpeg_q30" in perturbed_images
    assert "resize_50pct" in perturbed_images
    assert "central_crop_85pct" in perturbed_images
    assert "gaussian_noise_sigma10" in perturbed_images
    assert perturbed_images["jpeg_q50"].size == (128, 128)

    # 2. Audio perturbations
    samples = np.sin(2 * np.pi * 440 * np.linspace(0, 1.0, 16000)).astype(np.float32)
    perturbed_audio = apply_audio_adversarial_transforms(samples, sr=16000)
    assert "noise_snr_15db" in perturbed_audio
    assert "quantization_8bit" in perturbed_audio
    assert "attenuation_neg3db" in perturbed_audio
    assert len(perturbed_audio["noise_snr_15db"]) == 16000


def test_cross_generator_dataset_evaluation():
    """
    Verifies multi-generator dataset cross evaluation without generator leakage.
    """
    dataset_records = [
        {"label": 1, "score": 0.94, "generator": "Midjourney_v6"},
        {"label": 1, "score": 0.89, "generator": "StableDiffusion_XL"},
        {"label": 0, "score": 0.08, "generator": "Sony_Alpha_ILCE"},
        {"label": 0, "score": 0.12, "generator": "Apple_iPhone_15_Pro"}
    ]
    report = evaluate_dataset_cross_generator(dataset_records)
    assert report["accuracy"] == 1.0
    assert report["confusion_matrix"]["true_positives"] == 2
    assert report["confusion_matrix"]["true_negatives"] == 2
    assert "Midjourney_v6" in report["per_generator_metrics"]
    assert "Apple_iPhone_15_Pro" in report["per_generator_metrics"]
