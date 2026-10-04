"""DNS tunneling detector.

A dedicated model trained on CIC-Bell-DNS-EXF-2021 stateless DNS query
features (see ml/train_dns_model.py and dns/FEATURE_MAPPING.md), completely
independent of the CICIDS-2017 Random Forest used for DoS/PortScan -- a
different feature schema, a different artifact, a different explanation
call. Explainability uses SHAP's TreeExplainer, the same library already
used for the network model, since this is also a tree ensemble; it is never
labeled SHAP in the UI unless it was actually produced by SHAP (see
explanation.py's equivalent rule for the network model).
"""
import json
import os
import pickle

import numpy as np
import pandas as pd

from dns_features import STATELESS_FEATURES

_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_HERE, "models", "dns_tunnel_rf.pkl")
METADATA_PATH = os.path.join(_HERE, "models", "dns_tunnel_rf.metadata.json")

try:
    import shap
except Exception:
    shap = None


class DNSTunnelDetector:
    def __init__(self, model_path=MODEL_PATH, metadata_path=METADATA_PATH):
        self.model = None
        self.metadata = {}
        self.status = "not loaded"
        self._explainer = None
        self._load(model_path, metadata_path)

    def _load(self, model_path, metadata_path):
        try:
            with open(model_path, "rb") as fh:
                self.model = pickle.load(fh)
            if os.path.exists(metadata_path):
                with open(metadata_path) as fh:
                    self.metadata = json.load(fh)
            self.status = "loaded"
            if shap is not None:
                try:
                    self._explainer = shap.TreeExplainer(self.model)
                except Exception:
                    self._explainer = None
        except FileNotFoundError:
            self.status = "unavailable: model not trained (run `python ml/train_dns_model.py`)"
        except Exception as exc:
            self.status = f"unavailable: {type(exc).__name__}: {exc}"

    @property
    def feature_order(self):
        return self.metadata.get("features") or list(STATELESS_FEATURES)

    def classify(self, feature_dict):
        """Returns (label, confidence[0-100], shap_contributions|None).
        Fails safe to BENIGN/0 confidence if the model isn't loaded."""
        if self.model is None:
            return "BENIGN", 0.0, None
        row = {name: [float(feature_dict.get(name, 0) or 0)] for name in self.feature_order}
        x = pd.DataFrame(row, columns=self.feature_order)
        proba = self.model.predict_proba(x)[0]
        classes = list(self.model.classes_)
        idx = int(np.argmax(proba))
        label = str(classes[idx])
        confidence = float(proba[idx]) * 100.0
        shap_values = self._explain(x, idx)
        return label, confidence, shap_values

    def _explain(self, x, class_idx):
        if self._explainer is None:
            return None
        try:
            raw = self._explainer.shap_values(x)
            values = raw[class_idx] if isinstance(raw, list) else raw
            contributions = [
                {"feature": name, "value": round(float(values[0][i]), 5)}
                for i, name in enumerate(self.feature_order)
            ]
            contributions.sort(key=lambda d: abs(d["value"]), reverse=True)
            return contributions
        except Exception:
            return None
