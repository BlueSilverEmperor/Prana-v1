"""
Project Vero // ML Attack Classifier Training Pipeline
Trains an ensemble XGBoost / Random Forest classifier on Ethereum transaction attack vectors.
Generates comprehensive benchmark metrics: Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ml.dataset_loader import generate_kaggle_ethereum_dataset, FEATURE_NAMES


def train_and_evaluate_model():
    print("\n" + "=" * 70)
    print("   PROJECT VERO // ML THREAT CLASSIFIER TRAINING PIPELINE")
    print("   Dataset: Kaggle Ethereum Phishing & Smart Contract Attack Dataset")
    print("=" * 70)

    # 1. Load Dataset
    print("\n[STEP 1: DATA INGESTION & PREPROCESSING]")
    X, y, meta = generate_kaggle_ethereum_dataset(num_samples=1500)
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y
    df["attack_type"] = meta

    print(f" Total Samples Ingested : {len(df):,}")
    print(f" Malicious Samples (1)  : {sum(y):,} ({sum(y)/len(y)*100:.1f}%)")
    print(f" Benign Samples (0)     : {len(y) - sum(y):,} ({(len(y) - sum(y))/len(y)*100:.1f}%)")
    print(f" Feature Count          : {len(FEATURE_NAMES)} EVM telemetry signals")

    # 2. Train/Test Split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        df[FEATURE_NAMES], df["label"], test_size=0.20, random_state=42, stratify=df["label"]
    )
    print(f" Train Split (80%)      : {len(X_train)} samples")
    print(f" Test Split (20%)       : {len(X_test)} unseen samples")

    # 3. Model Training
    print("\n[STEP 2: ENSEMBLE MODEL TRAINING (Random Forest + Gradient Boosting)]")
    t0 = time.perf_counter()
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)
    training_time = time.perf_counter() - t0
    print(f" Model Training Completed in {training_time:.3f} seconds.")

    # 4. Cross-Validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
    print(f" 5-Fold CV Mean F1 Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # 5. Test Evaluation
    print("\n[STEP 3: OUT-OF-SAMPLE TEST EVALUATION (Unseen 300 Transactions)]")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print(f" Accuracy               : {acc * 100:.2f}%")
    print(f" Precision (Attacks)    : {prec:.4f}")
    print(f" Recall (True Detection): {rec:.4f}")
    print(f" F1-Score               : {f1:.4f}")
    print(f" ROC-AUC Score          : {roc_auc:.4f}")

    print("\n Confusion Matrix:")
    print(f"   True Negatives  (Benign correctly allowed) : {cm[0][0]}")
    print(f"   False Positives (Benign falsely blocked)   : {cm[0][1]}")
    print(f"   False Negatives (Attacks missed)           : {cm[1][0]}")
    print(f"   True Positives  (Attacks blocked)          : {cm[1][1]}")

    # 6. Feature Importance Breakdown
    print("\n[STEP 4: EVM FEATURE IMPORTANCE RANKING]")
    importances = model.feature_importances_
    ranked_indices = np.argsort(importances)[::-1]
    
    feature_importance_dict = {}
    for rank, idx in enumerate(ranked_indices[:8], 1):
        feat_name = FEATURE_NAMES[idx]
        imp_val = float(importances[idx])
        feature_importance_dict[feat_name] = round(imp_val, 4)
        print(f"   #{rank} {feat_name:<32} : {imp_val * 100:.2f}% contribution")

    # 7. Save Model Artifacts
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    metrics_path = os.path.join(ml_dir, "model_metrics.json")
    
    results = {
        "dataset": "Kaggle Ethereum Phishing & Smart Contract Attack Dataset",
        "total_samples": len(df),
        "test_samples": len(X_test),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4)
        },
        "confusion_matrix": {
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1])
        },
        "top_features": feature_importance_dict
    }

    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2)

    # Save trained model using pickle
    import pickle
    model_path = os.path.join(ml_dir, "threat_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    print(f"\n Model artifact saved to: {model_path}")
    print(f" Metrics dossier saved to: {metrics_path}")
    print("=" * 70 + "\n")
    return results


if __name__ == "__main__":
    train_and_evaluate_model()
