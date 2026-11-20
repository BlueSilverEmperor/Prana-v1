"""
Project Vero // Advanced Multi-Model EVM Threat Classifier
Trains an Ensemble Model (Random Forest + Gradient Boosting Soft-Voting)
on 10,000 diverse Web3 transactions ingested from:
- Real Mainnet Attacks (WazirX $230M, Bybit $1.5B, Euler, Curve)
- 55 Repository Benchmark Scenarios
- Kaggle / DeFiHackLabs Anomaly Distributions
- Etherscan Top-Contract Protocol Baselines (Uniswap v3, Aave v3, Gnosis Safe, Lido, Curve)

Contains 15 EVM Telemetry Features for maximal precision, recall, and zero-day detection.
"""

import os
import sys
import json
import time
import pickle
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
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

from ml.dataset_loader import generate_diverse_web3_dataset, FEATURE_NAMES


def train_and_evaluate_model():
    print("\n" + "=" * 78)
    print("   PROJECT VERO // ENSEMBLE EVM THREAT CLASSIFICATION BENCHMARK")
    print("   Dataset: Real Mainnet Incidents + 55 Scenarios + Synthesized Telemetry (10,000 Samples)")
    print("=" * 78)

    # 1. Dataset Generation & Ingestion
    print("\n[PHASE 1: INGESTION OF HIGH-VARIANCE WEB3 TELEMETRY DATASET]")
    X, y, meta = generate_diverse_web3_dataset(num_samples=10000, repo_root=REPO_ROOT)
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y
    df["protocol_category"] = meta

    real_count = sum(1 for m in meta if m.startswith("RealIncident_") or m.startswith("Scenario_") or m.startswith("Attacks_"))
    print(f" Total Ingested Transactions : {len(df):,}")
    print(f" Real Repository Incidents   : {real_count:,}")
    print(f" Malicious Attack Vectors (1): {sum(y):,} ({sum(y)/len(y)*100:.1f}%)")
    print(f" Benign Protocol Swaps (0)   : {len(y) - sum(y):,} ({(len(y) - sum(y))/len(y)*100:.1f}%)")
    print(f" Total Telemetry Features    : {len(FEATURE_NAMES)} on-chain signals")
    print(f" Unique Category Clusters    : {df['protocol_category'].nunique()} distinct protocol profiles")

    # 2. Stratified Train / Test Split (80% Train / 20% Test = 2,000 Test Samples)
    X_train, X_test, y_train, y_test = train_test_split(
        df[FEATURE_NAMES], df["label"], test_size=0.20, random_state=42, stratify=df["label"]
    )
    print(f" Training Partition (80%)    : {len(X_train):,} samples")
    print(f" Test Partition (20%)        : {len(X_test):,} unseen holdout samples")

    # 3. Ensemble Model Architecture
    print("\n[PHASE 2: ENSEMBLE CLASSIFIER TRAINING & CROSS-VALIDATION]")
    t0 = time.perf_counter()
    
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    gb = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.08,
        max_depth=5,
        subsample=0.85,
        random_state=42
    )

    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('gb', gb)],
        voting='soft',
        weights=[1.0, 1.2]
    )

    # 5-Fold Stratified Cross Validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    cv_results = cross_validate(ensemble, X_train, y_train, cv=cv, scoring=scoring, n_jobs=-1)

    # Fit final ensemble
    ensemble.fit(X_train, y_train)
    training_duration = time.perf_counter() - t0

    print(f" Training & Cross-Validation Duration : {training_duration:.3f} seconds")
    print(f" 5-Fold Stratified CV Mean Accuracy   : {cv_results['test_accuracy'].mean() * 100:.2f}% (+/- {cv_results['test_accuracy'].std() * 100:.2f}%)")
    print(f" 5-Fold Stratified CV Mean Precision  : {cv_results['test_precision'].mean() * 100:.2f}% (+/- {cv_results['test_precision'].std() * 100:.2f}%)")
    print(f" 5-Fold Stratified CV Mean Recall     : {cv_results['test_recall'].mean() * 100:.2f}% (+/- {cv_results['test_recall'].std() * 100:.2f}%)")
    print(f" 5-Fold Stratified CV Mean F1 Score   : {cv_results['test_f1'].mean():.4f} (+/- {cv_results['test_f1'].std():.4f})")
    print(f" 5-Fold Stratified CV Mean ROC-AUC    : {cv_results['test_roc_auc'].mean():.4f}")

    # 4. Out-of-Sample Test Evaluation
    print("\n[PHASE 3: OUT-OF-SAMPLE TEST EVALUATION (2,000 UNSEEN TRANSACTIONS)]")
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print(f" Out-of-Sample Accuracy  : {acc * 100:.2f}%")
    print(f" Attack Precision        : {prec * 100:.2f}% (Purity of blocked attacks)")
    print(f" Attack Recall           : {rec * 100:.2f}% (Detection rate of real attacks)")
    print(f" Harmonic Mean (F1-Score): {f1:.4f}")
    print(f" Discriminative ROC-AUC  : {roc_auc:.4f}")

    print("\n Confusion Matrix Breakdown:")
    print(f"   True Negatives  (Benign correctly allowed)  : {cm[0][0]:>4} / {cm[0][0] + cm[0][1]}")
    print(f"   False Positives (Complex benign edge-cases) : {cm[0][1]:>4} (FPR: {cm[0][1]/(cm[0][0]+cm[0][1])*100:.2f}%)")
    print(f"   False Negatives (Stealth evasion misses)    : {cm[1][0]:>4} (FNR: {cm[1][0]/(cm[1][0]+cm[1][1])*100:.2f}%)")
    print(f"   True Positives  (Exploits caught & blocked) : {cm[1][1]:>4} / {cm[1][0] + cm[1][1]}")

    # 5. Feature Importance Breakdown (Ensemble Weighted Average)
    print("\n[PHASE 4: ON-CHAIN TELEMETRY FEATURE IMPORTANCE]")
    rf_imp = ensemble.named_estimators_['rf'].feature_importances_
    gb_imp = ensemble.named_estimators_['gb'].feature_importances_
    importances = (1.0 * rf_imp + 1.2 * gb_imp) / 2.2
    
    # Store dynamic attribute on ensemble for direct inference access
    ensemble.feature_importances_ = importances
    ranked_indices = np.argsort(importances)[::-1]
    
    top_features = {}
    for rank, idx in enumerate(ranked_indices, 1):
        f_name = FEATURE_NAMES[idx]
        val = float(importances[idx])
        top_features[f_name] = round(val, 4)
        print(f"   #{rank:02d} {f_name:<33} : {val * 100:.2f}%")

    # 6. Save Model & Metrics
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    metrics_path = os.path.join(ml_dir, "model_metrics.json")
    model_path = os.path.join(ml_dir, "threat_model.pkl")

    dossier = {
        "dataset_name": "Multi-Protocol DeFi & Attack Vector Benchmark (Real Incidents + 55 Scenarios + Kaggle/DeFiHackLabs)",
        "total_samples": len(df),
        "real_incident_samples": real_count,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_count": len(FEATURE_NAMES),
        "model_architecture": "VotingClassifier(RandomForest[150] + GradientBoosting[150], soft voting, weights=[1.0, 1.2])",
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "cv_accuracy_mean": round(float(cv_results['test_accuracy'].mean()), 4),
            "cv_accuracy_std": round(float(cv_results['test_accuracy'].std()), 4),
            "cv_f1_mean": round(float(cv_results['test_f1'].mean()), 4),
            "cv_f1_std": round(float(cv_results['test_f1'].std()), 4),
            "cv_roc_auc_mean": round(float(cv_results['test_roc_auc'].mean()), 4)
        },
        "confusion_matrix": {
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1])
        },
        "feature_importance_ranking": top_features
    }

    with open(metrics_path, "w") as f:
        json.dump(dossier, f, indent=2)

    with open(model_path, "wb") as f:
        pickle.dump(ensemble, f)

    print(f"\n Model weights updated at: {model_path}")
    print(f" Metrics dossier saved to: {metrics_path}")
    print("=" * 78 + "\n")
    return dossier


if __name__ == "__main__":
    train_and_evaluate_model()
