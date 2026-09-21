"""CICIDS-2017 model training, persistence, evaluation, and live-flow helpers."""
import csv
import json
import os
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

try:
    import shap
except Exception:
    shap = None

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception:
    plt = None


MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "random_forest.pkl"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _normalize_friendly_name(value):
    cleaned = str(value or "").strip()
    if not cleaned:
        return ""
    cleaned = cleaned.replace("/", "_").replace("-", "_").replace("(", "").replace(")", "").replace(".", "_")
    cleaned = cleaned.replace(" ", "_")
    cleaned = "".join(ch for ch in cleaned if ch.isalnum() or ch in {"_"})
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_").lower()


def _discover_cicids_headers():
    data_dir = Path(__file__).resolve().with_name("dataset")
    default_paths = [
        data_dir / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    ]
    configured = os.getenv("NIDS_DATA_FILES", "").strip()
    if configured:
        candidate_paths = [Path(item.strip()) for item in configured.split(",") if item.strip()]
    else:
        candidate_paths = default_paths
    for path in candidate_paths:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.reader(handle)
                header = next(reader, [])
                if header and header[-1].strip().lower() == "label":
                    return [name.strip() for name in header[:-1]]
        except OSError:
            continue
    return [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Header Length",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]


FEATURE_NAMES = [_normalize_friendly_name(name) for name in _discover_cicids_headers()]
CLASS_NAMES = ("BENIGN", "DoS", "PortScan")
LEGACY_FEATURE_ALIASES = {
    "destination_port": ("destination_port",),
    "flow_duration": ("flow_duration", "flow_duration_us"),
    "total_fwd_packets": ("total_fwd_packets", "fwd_packets", "total_forward_packets"),
    "total_backward_packets": ("total_backward_packets", "total_bwd_packets"),
    "total_length_of_fwd_packets": ("total_length_of_fwd_packets",),
    "total_length_of_bwd_packets": ("total_length_of_bwd_packets",),
    "flow_bytes_per_s": ("flow_bytes_per_s", "flow_bytes_s"),
    "flow_packets_s": ("flow_packets_s", "flow_packets_per_s", "flow_packets_per_sec"),
    "flow_packets_per_s": ("flow_packets_s", "flow_packets_per_s", "flow_packets_per_sec"),
    "syn_flag_count": ("syn_flag_count",),
    "rst_flag_count": ("rst_flag_count",),
    "flow_iat_mean": ("flow_iat_mean",),
    "flow_iat_std": ("flow_iat_std",),
    "flow_iat_max": ("flow_iat_max",),
    "flow_iat_min": ("flow_iat_min",),
    "fwd_header_length": ("fwd_header_length", "total_length_of_fwd_packets"),
    "bwd_header_length": ("bwd_header_length", "total_length_of_bwd_packets"),
}


class AnomalyDetector:
    def __init__(self, seed=42, data_dir=None):
        self.seed = seed
        self.data_dir = Path(data_dir or Path(__file__).with_name("dataset")).resolve()
        self.model_dir = MODEL_DIR
        self.model_path = MODEL_PATH
        self.model_dir.mkdir(parents=True, exist_ok=True)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.model = RandomForestClassifier(
            n_estimators=220,
            max_depth=18,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed,
        )
        self.training_files = []
        self.training_rows = 0
        self.training_status = "not trained"
        self.explainer = None
        self.model_features = list(FEATURE_NAMES)
        self._load_or_train_model()
        if shap is not None:
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.explainer = None

    @staticmethod
    def _number(value):
        try:
            value = str(value).strip()
            if not value or value.lower() in {"nan", "inf", "-inf"}:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def dataset_available(self):
        return bool(self._paths())

    def _paths(self):
        configured = os.getenv("NIDS_DATA_FILES", "").strip()
        if configured:
            paths = [Path(item.strip()) for item in configured.split(",") if item.strip()]
        else:
            paths = [
                self.data_dir / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                self.data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            ]
        return [path for path in paths if path.is_file()]

    @staticmethod
    def _class_for(path, label):
        label = str(label or "").strip().upper()
        if label == "BENIGN":
            return "BENIGN"
        name = path.name.lower()
        if "portscan" in name:
            return "PortScan"
        if "ddos" in name or "dos" in name:
            return "DoS"
        return None

    def _read_rows(self):
        rows = []
        labels = []
        paths = self._paths()
        for path in paths:
            if not path.is_file():
                continue
            try:
                with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                    reader = csv.reader(handle)
                    header = next(reader, [])
                    if not header:
                        continue
                    feature_names = [self._normalize_header(name) for name in header[:-1]]
                    for raw in reader:
                        if len(raw) < len(header):
                            continue
                        line = raw[:-1]
                        label = raw[-1].strip()
                        class_name = self._class_for(path, label)
                        if class_name is None:
                            continue
                        values = []
                        for index, feature in enumerate(feature_names):
                            if index >= len(line):
                                values.append(0.0)
                                continue
                            value = self._number(line[index])
                            values.append(float(value if value is not None else 0.0))
                        rows.append(values)
                        labels.append(class_name)
                self.training_files.append(path.name)
            except OSError:
                continue
        if not rows:
            raise RuntimeError("CICIDS training requires BENIGN, DoS, and PortScan rows")
        return np.asarray(rows, dtype=float), np.asarray(labels)

    @staticmethod
    def _normalize_header(value):
        return _normalize_friendly_name(value)

    def _save_model(self):
        payload = {
            "model": self.model,
            "features": list(self.model_features),
            "classes": list(CLASS_NAMES),
            "training_rows": self.training_rows,
        }
        with self.model_path.open("wb") as handle:
            pickle.dump(payload, handle)

    def _load_model(self):
        if not self.model_path.exists():
            return False
        try:
            with self.model_path.open("rb") as handle:
                payload = pickle.load(handle)
            if not isinstance(payload, dict):
                return False
            model = payload.get("model")
            features = payload.get("features") or list(FEATURE_NAMES)
            if model is None:
                return False
            self.model = model
            self.model_features = list(features)
            self.training_status = "loaded"
            return True
        except Exception:
            return False

    def _load_or_train_model(self):
        if self._load_model():
            return self.model
        x, y = self._read_rows()
        if x.size == 0:
            raise RuntimeError("No dataset rows were available for model training")
        x = np.nan_to_num(np.asarray(x, dtype=float), nan=0.0, posinf=1e12, neginf=0.0)
        self.model.fit(np.clip(x, 0, 1e12), y)
        self.training_rows = len(y)
        self.training_status = "trained"
        self._save_model()
        return self.model

    def build_feature_vector(self, features):
        normalized = {}
        for key, value in (features or {}).items():
            normalized[str(key).strip()] = value
        vector = {}
        for name in FEATURE_NAMES:
            value = None
            alias_candidates = {name, *LEGACY_FEATURE_ALIASES.get(name, ())}
            for candidate in alias_candidates:
                if candidate in normalized and normalized[candidate] is not None:
                    value = normalized[candidate]
                    break
            if value is None:
                for key, entry in normalized.items():
                    normalized_key = _normalize_friendly_name(key)
                    if normalized_key == name or normalized_key in alias_candidates:
                        value = entry
                        break
            vector[name] = float(value if value is not None else 0.0)
        return vector

    def _vector(self, features):
        if isinstance(features, dict):
            mapping = self.build_feature_vector(features)
            return [float(mapping.get(name, 0.0)) for name in FEATURE_NAMES]
        if isinstance(features, (list, tuple, np.ndarray)):
            values = [float(value) for value in list(features)]
            if len(values) < len(FEATURE_NAMES):
                values = values + [0.0] * (len(FEATURE_NAMES) - len(values))
            return values[: len(FEATURE_NAMES)]
        return [0.0] * len(FEATURE_NAMES)

    def predict(self, features):
        x = np.nan_to_num(np.asarray([self._vector(features)], dtype=float), nan=0.0)
        x = np.clip(x, 0, 1e12)
        probabilities = self.model.predict_proba(x)[0]
        index = int(np.argmax(probabilities))
        label = str(self.model.classes_[index])
        shap_values = []
        if self.explainer is not None:
            try:
                raw = np.asarray(self.explainer.shap_values(x))
                contribution = raw[0, :, index] if raw.ndim == 3 else raw[index][0]
                ranked = sorted(
                    zip(FEATURE_NAMES, contribution.tolist()),
                    key=lambda item: abs(item[1]),
                    reverse=True,
                )
                shap_values = [
                    {"feature": name, "value": round(float(value), 4)}
                    for name, value in ranked[:10]
                ]
            except Exception:
                shap_values = []
        return label, float(probabilities[index]), shap_values

    def classify_live(self, features, distinct_ports=0, source_syn_count=0):
        """Combine the trained CICIDS model with conservative live-flow safeguards."""
        payload = self.build_feature_vector(features)
        label, probability, shap_values = self.predict(payload)

        packet_rate = 0.0
        for key in ("flow_packets_per_s", "flow_packets_s", "flow_packets_per_sec"):
            value = payload.get(key)
            if value is not None:
                packet_rate = float(value)
                break

        total_fwd_packets = 0.0
        for key in ("total_fwd_packets", "total_forward_packets", "fwd_packets"):
            value = payload.get(key)
            if value is not None:
                total_fwd_packets = float(value)
                break

        strong_dos_evidence = (
            label == "DoS"
            or source_syn_count >= 8
            or (packet_rate >= 12 and total_fwd_packets >= 10)
            or (packet_rate >= 5 and total_fwd_packets >= 20 and distinct_ports <= 2)
        )
        if strong_dos_evidence:
            return "DoS", max(probability, 0.85), shap_values
        if distinct_ports >= 4:
            return "PortScan", max(probability, 0.85), shap_values
        return label, probability, shap_values

    def evaluate_model(self, save_dir=None):
        if not self.model:
            raise RuntimeError("Random Forest model is not available")
        x, y = self._read_rows()
        x = np.nan_to_num(np.asarray(x, dtype=float), nan=0.0, posinf=1e12, neginf=0.0)
        y_pred = self.model.predict(np.clip(x, 0, 1e12))
        labels = list(CLASS_NAMES)
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred, average="weighted", zero_division=0)
        recall = recall_score(y, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y, y_pred, average="weighted", zero_division=0)
        matrix = confusion_matrix(y, y_pred, labels=labels)
        report = classification_report(y, y_pred, labels=labels, output_dict=True, zero_division=0)
        metrics = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "labels": labels,
            "confusion_matrix": matrix.tolist(),
            "class_metrics": {
                class_name: {
                    "precision": float(report.get(class_name, {}).get("precision", 0.0)),
                    "recall": float(report.get(class_name, {}).get("recall", 0.0)),
                    "f1_score": float(report.get(class_name, {}).get("f1-score", 0.0)),
                    "support": int(report.get(class_name, {}).get("support", 0)),
                }
                for class_name in labels
            },
        }
        output_dir = Path(save_dir) if save_dir else RESULTS_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        with (output_dir / "evaluation.json").open("w", encoding="utf-8") as handle:
            json.dump(metrics, handle, indent=2, sort_keys=True)
        with (output_dir / "classification_report.txt").open("w", encoding="utf-8") as handle:
            handle.write(classification_report(y, y_pred, labels=labels, zero_division=0))
        if plt is not None:
            fig, axes = plt.subplots(figsize=(6, 5))
            axes.imshow(matrix, interpolation="nearest", cmap=plt.cm.Blues)
            axes.set_title("Confusion Matrix")
            axes.set_xticks(range(len(labels)))
            axes.set_xticklabels(labels)
            axes.set_yticks(range(len(labels)))
            axes.set_yticklabels(labels)
            for i in range(matrix.shape[0]):
                for j in range(matrix.shape[1]):
                    axes.text(j, i, format(matrix[i, j], "d"), ha="center", va="center", color="white" if matrix[i, j] > matrix.max() / 2 else "black")
            fig.tight_layout()
            fig.savefig(output_dir / "confusion_matrix.png", dpi=150)
            plt.close(fig)
        return metrics
