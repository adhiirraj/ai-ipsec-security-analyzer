#!/usr/bin/env python3
"""Train the optional traffic-profile classifier from an explicitly supplied CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

try:  # Supports both ``python testbed/train_model.py`` and package imports.
    from .extract_features import FEATURE_COLUMNS, TESTBED_DIR
except ImportError:  # pragma: no cover - direct script execution path
    from extract_features import FEATURE_COLUMNS, TESTBED_DIR


PROJECT_ROOT = TESTBED_DIR.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "esp_traffic_classifier.pkl"


def train(dataset_path: Path, model_path: Path) -> tuple[RandomForestClassifier, float | None]:
    """Train a deterministic model; reject datasets that cannot support classification."""

    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    dataset = pd.read_csv(dataset_path)
    required = set(FEATURE_COLUMNS) | {"label"}
    missing = sorted(required.difference(dataset.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")
    if dataset.empty:
        raise ValueError("Dataset is empty")
    labels = dataset["label"].astype(str)
    if labels.nunique() < 2:
        raise ValueError("At least two traffic labels are required to train a classifier")
    features = dataset[list(FEATURE_COLUMNS)]
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    accuracy: float | None = None
    counts = labels.value_counts()
    if len(dataset) >= 20 and counts.min() >= 2:
        x_train, x_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.3, random_state=42, stratify=labels
        )
        model.fit(x_train, y_train)
        accuracy = float(accuracy_score(y_test, model.predict(x_test)))
    else:
        model.fit(features, labels)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    return model, accuracy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the optional ESP traffic-profile classifier")
    parser.add_argument("--dataset", type=Path, default=TESTBED_DIR / "dataset.csv")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    args = parser.parse_args(argv)
    try:
        _model, accuracy = train(args.dataset, args.model)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))
    if accuracy is None:
        print("Model trained without a held-out score because the dataset is too small or unbalanced.")
    else:
        print(f"Held-out accuracy: {accuracy:.2%}")
    print(f"Model saved to {args.model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
