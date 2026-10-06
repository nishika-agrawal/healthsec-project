"""
Trains a Random Forest risk-classification model on the synthetic
dataset (see dataset.py's docstring for why it's synthetic and its
documented limitations).

Usage (from the backend/ folder, with the virtualenv activated):

    python -m app.ml.train

Produces:
    app/ml/model/risk_model.joblib        - the trained model
    app/ml/model/model_metadata.json      - feature list, classes, training info
    app/ml/model/evaluation_report.json   - precision/recall/F1/confusion matrix
    app/ml/data/synthetic_vulnerability_dataset.csv - the generated dataset
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from app.ml.dataset import FEATURE_COLUMNS, RISK_CATEGORIES, generate_synthetic_dataset

MODULE_DIR = Path(__file__).resolve().parent
MODEL_DIR = MODULE_DIR / "model"
DATA_DIR = MODULE_DIR / "data"

MODEL_PATH = MODEL_DIR / "risk_model.joblib"
METADATA_PATH = MODEL_DIR / "model_metadata.json"
EVALUATION_PATH = MODEL_DIR / "evaluation_report.json"
DATASET_PATH = DATA_DIR / "synthetic_vulnerability_dataset.csv"


def train_and_evaluate(n_samples: int = 2000, random_state: int = 42):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    df = generate_synthetic_dataset(n_samples=n_samples, random_state=random_state)
    df.to_csv(DATASET_PATH, index=False)

    X = df[FEATURE_COLUMNS]
    y = df["risk_category"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        random_state=random_state,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    report = classification_report(
        y_test, y_pred, labels=RISK_CATEGORIES, output_dict=True, zero_division=0
    )
    matrix = confusion_matrix(y_test, y_pred, labels=RISK_CATEGORIES)

    evaluation = {
        "classification_report": report,
        "confusion_matrix": {
            "labels": RISK_CATEGORIES,
            "matrix": matrix.tolist(),
            "note": "Rows are true labels, columns are predicted labels, in the order given by 'labels'.",
        },
        "training_set_size": len(y_train),
        "test_set_size": len(y_test),
        "note": (
            "Evaluated against a held-out split of the SYNTHETIC dataset described in "
            "app/ml/dataset.py. These numbers show how well the model approximates the "
            "documented rule-based labels, not real-world deployment risk."
        ),
    }

    joblib.dump(model, MODEL_PATH)

    metadata = {
        "model_type": "RandomForestClassifier",
        "sklearn_params": {
            k: v for k, v in model.get_params().items() if isinstance(v, (int, float, str, bool)) or v is None
        },
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(model.classes_),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "type": "synthetic",
            "n_samples": n_samples,
            "note": (
                "Synthetic dataset with rule-derived labels - see app/ml/dataset.py "
                "docstring for full limitations. Not validated against real-world outcomes."
            ),
        },
        "feature_importances": dict(zip(FEATURE_COLUMNS, model.feature_importances_.tolist())),
    }

    METADATA_PATH.write_text(json.dumps(metadata, indent=2))
    EVALUATION_PATH.write_text(json.dumps(evaluation, indent=2))

    return model, metadata, evaluation


if __name__ == "__main__":
    _, metadata, evaluation = train_and_evaluate()
    print("Model trained and saved to:", MODEL_PATH)
    print("Classes:", metadata["classes"])
    print("Overall accuracy on held-out synthetic test split:", evaluation["classification_report"]["accuracy"])
    print("Per-class F1-score:")
    for cls in metadata["classes"]:
        print(f"  {cls}: {evaluation['classification_report'][cls]['f1-score']:.3f}")
    print("\nFeature importances:")
    for feature, importance in sorted(
        metadata["feature_importances"].items(), key=lambda item: item[1], reverse=True
    ):
        print(f"  {feature}: {importance:.3f}")
