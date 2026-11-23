"""Evaluate the installed image detector against a labeled holdout set.

Expected layout (keep this split separate from training data)::

    test/real/*.jpg
    test/fake/*.jpg

Run from backend/ after installing the project dependencies::

    python ml/evaluate_detector.py --data data/test

The reported threshold matches the product's image/video flag threshold (0.6).
This measures the learned image classifier only; it does not evaluate the
heuristics or establish performance on generators absent from the test set.
"""

import argparse
import json
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from app.analysis import load_detector
from app.config import get_settings

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff"}


def roc_auc(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    ordered = sorted(zip(scores, labels))
    rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2
        rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def evaluate(data_dir: Path, threshold: float, onnx_path: str, weights_path: str) -> dict:
    detector = load_detector(onnx_path, weights_path)
    if not detector.available:
        reason = getattr(detector, "error", None) or "No detector model was found."
        raise RuntimeError(reason)

    labels: list[int] = []
    scores: list[float] = []
    skipped: list[str] = []
    for folder, label in (("real", 0), ("fake", 1)):
        root = data_dir / folder
        if not root.is_dir():
            raise ValueError(f"Missing class folder: {root}")
        for path in sorted(p for p in root.rglob("*") if p.suffix.lower() in IMAGE_EXTENSIONS):
            try:
                with Image.open(path) as image:
                    score = detector.predict(image.convert("RGB"))
                if not 0 <= score <= 1:
                    raise ValueError(f"Detector returned a probability outside [0, 1]: {score}")
            except (OSError, ValueError, UnidentifiedImageError) as exc:
                skipped.append(f"{path}: {exc}")
                continue
            labels.append(label)
            scores.append(score)

    if not labels:
        raise ValueError(f"No readable images found under {data_dir}")

    tp = sum(y == 1 and p >= threshold for y, p in zip(labels, scores))
    tn = sum(y == 0 and p < threshold for y, p in zip(labels, scores))
    fp = sum(y == 0 and p >= threshold for y, p in zip(labels, scores))
    fn = sum(y == 1 and p < threshold for y, p in zip(labels, scores))
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "model": getattr(detector, "name", type(detector).__name__),
        "data_dir": str(data_dir),
        "threshold": threshold,
        "samples": len(labels),
        "real": labels.count(0),
        "fake": labels.count(1),
        "skipped": len(skipped),
        "confusion_matrix": {"true_fake": tp, "true_real": tn, "false_fake": fp, "missed_fake": fn},
        "accuracy": (tp + tn) / len(labels),
        "precision_fake": precision,
        "recall_fake": recall,
        "specificity_real": ratio(tn, tn + fp),
        "f1_fake": ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None and precision + recall else None,
        "roc_auc": roc_auc(labels, scores),
        "skipped_files": skipped,
        "warning": "Holdout results only describe this sample and its generators; they are not a general accuracy guarantee.",
    }


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Folder containing real/ and fake/ subfolders")
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--onnx", default=settings.detector_onnx)
    parser.add_argument("--weights", default=settings.detector_weights)
    args = parser.parse_args()
    if not 0 <= args.threshold <= 1:
        parser.error("--threshold must be between 0 and 1")
    try:
        result = evaluate(args.data, args.threshold, args.onnx, args.weights)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
