"""
SPECTRA Digital Forensics & Adversarial Robustness Evaluation Framework
"""
from app.media.eval.benchmark import (
    compute_evaluation_metrics,
    apply_image_adversarial_transforms,
    apply_audio_adversarial_transforms,
    evaluate_dataset_cross_generator,
    AdversarialStressTestResult
)

__all__ = [
    "compute_evaluation_metrics",
    "apply_image_adversarial_transforms",
    "apply_audio_adversarial_transforms",
    "evaluate_dataset_cross_generator",
    "AdversarialStressTestResult"
]
