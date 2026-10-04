"""Train the DNS tunneling classifier on CIC-Bell-DNS-EXF-2021 stateless
per-query features.

See dns/FEATURE_MAPPING.md for the full dataset -> live-packet -> model
feature mapping this script and dns_features.py both rely on (they import
the same STATELESS_FEATURES tuple, so the trained model and the live
extractor are guaranteed to agree on feature order and meaning).

Usage:
    python ml/train_dns_model.py
    python ml/train_dns_model.py --data-dir dataset/dns --out models/dns_tunnel_rf.pkl

Expects:
    <data-dir>/Attacks/stateless_features-*.csv  (labeled DNS_TUNNELING)
    <data-dir>/Benign/stateless_features-*.csv   (labeled BENIGN)
"""
import argparse
import glob
import json
import os
import pickle
import sys
import time

import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dns_features import STATELESS_FEATURES  # noqa: E402

LABEL_COLUMN = "label"
DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset", "dns")
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "dns_tunnel_rf.pkl")


def load_dataset(data_dir):
    attack_files = sorted(glob.glob(os.path.join(data_dir, "Attacks", "stateless_features-*.csv")))
    benign_files = sorted(glob.glob(os.path.join(data_dir, "Benign", "stateless_features-*.csv")))
    if not attack_files or not benign_files:
        raise FileNotFoundError(
            f"expected Attacks/stateless_features-*.csv and Benign/stateless_features-*.csv under {data_dir}"
        )
    frames = []
    for path in attack_files:
        df = pd.read_csv(path)
        df[LABEL_COLUMN] = "DNS_TUNNELING"
        df["_source_file"] = os.path.basename(path)
        frames.append(df)
    for path in benign_files:
        df = pd.read_csv(path)
        df[LABEL_COLUMN] = "BENIGN"
        df["_source_file"] = os.path.basename(path)
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    missing = [c for c in STATELESS_FEATURES if c not in full.columns]
    if missing:
        raise ValueError(f"dataset is missing expected columns: {missing}")
    return full, attack_files, benign_files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df, attack_files, benign_files = load_dataset(args.data_dir)
    X = df[list(STATELESS_FEATURES)].fillna(0).astype(float)
    y = df[LABEL_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=args.seed, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    matrix = confusion_matrix(y_test, y_pred, labels=sorted(y.unique())).tolist()
    macro_f1 = f1_score(y_test, y_pred, average="macro")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "wb") as fh:
        pickle.dump(model, fh)

    metadata = {
        "model_name": "dns_tunnel_rf",
        "version": "1.0.0",
        "model_type": "RandomForestClassifier",
        "training_dataset": "CIC-Bell-DNS-EXF-2021 (stateless per-query features, light subset)",
        "attack_files": [os.path.basename(f) for f in attack_files],
        "benign_files": [os.path.basename(f) for f in benign_files],
        "features": list(STATELESS_FEATURES),
        "class_labels": sorted(y.unique().tolist()),
        "training_timestamp": time.time(),
        "rows_total": int(len(df)),
        "rows_train": int(len(X_train)),
        "rows_test": int(len(X_test)),
        "macro_f1": round(float(macro_f1), 4),
        "classification_report": report,
        "confusion_matrix": matrix,
        "sklearn_version": sklearn.__version__,
    }
    metadata_path = os.path.splitext(args.out)[0] + ".metadata.json"
    with open(metadata_path, "w") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"Trained on {len(df)} rows ({len(X_train)} train / {len(X_test)} test)")
    print(f"Macro F1: {macro_f1:.4f}")
    print(json.dumps(report, indent=2))
    print(f"\nSaved model  -> {args.out}")
    print(f"Saved metadata -> {metadata_path}")


if __name__ == "__main__":
    main()
