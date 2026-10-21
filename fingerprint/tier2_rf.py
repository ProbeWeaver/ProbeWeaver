"""Tier-2 RandomForest training over the frozen phase-aware rule corpus.

Tier-1 code rules remain the outer gate.  This model is trained on every
currently retained response observation and is invoked only when Tier-1 has
no reliable match.  Internal probe-family group diagnostics are used to audit
the model and confidence threshold; the deployable model is then refit on all
construction atoms.  Those diagnostics are not a substitute for the E0 fresh
probe-family validation round.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, top_k_accuracy_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import LabelEncoder

from core.rule_corpus import canonical_sha256, load_rule_corpus
from fingerprint.feature_extractor import ResponseFeatureExtractor

SCHEMA_VERSION = 1
ARTIFACT_TYPE = "tier2_random_forest_training"
CONFIDENCE_GRID = (0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95)

class Tier2TrainingError(ValueError):
    pass

def load_tier2_rf_artifact(manifest_path: str) -> tuple[dict, Any, LabelEncoder]:
    """Load and fully rebind a trained Tier-2 model artifact."""
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("schema_version") != SCHEMA_VERSION \
            or manifest.get("artifact_type") != ARTIFACT_TYPE:
        raise Tier2TrainingError("unsupported Tier-2 RF manifest")
    core = {key: value for key, value in manifest.items()
            if key not in ("artifact_hash", "created_at")}
    if manifest.get("artifact_hash") != canonical_sha256(core):
        raise Tier2TrainingError("Tier-2 RF artifact_hash mismatch")
    files = manifest.get("files") or {}
    for name in ("model", "label_encoder"):
        record = files.get(name) or {}
        path = record.get("path")
        if not path or not os.path.isfile(path):
            raise Tier2TrainingError(f"Tier-2 RF {name} file is missing")
        if _sha256_file(path) != record.get("sha256"):
            raise Tier2TrainingError(f"Tier-2 RF {name} sha256 mismatch")
    model = joblib.load(files["model"]["path"])
    encoder = joblib.load(files["label_encoder"]["path"])
    if list(encoder.classes_) != manifest["data"]["classes"]:
        raise Tier2TrainingError("Tier-2 RF label encoder classes mismatch")
    return manifest, model, encoder

def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _atomic_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False,
                      sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise

def _atomic_joblib(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    try:
        joblib.dump(value, temp)
        with temp.open("rb+") as handle:
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise

def samples_from_atoms(atoms: Sequence[Mapping]) -> list[dict]:
    samples = []
    for atom in atoms:
        response_hex = str(atom.get("response_hex") or "")
        packet_hex = str(atom.get("packet_hex") or "")
        label = str(atom.get("id_cluster") or "")
        if not response_hex or not packet_hex or not label:
            raise Tier2TrainingError(
                "rule corpus atom lacks response/request/id_cluster")
        samples.append({
            "cluster": label,
            "member": str(atom.get("member") or ""),
            "response_hex": response_hex,
            "request_hex": packet_hex,
            "response_identity": str(atom.get("response_identity") or ""),
            "probe_family_identity": str(
                atom.get("probe_family_identity") or ""),
            "probe_family_basis": str(atom.get("probe_family_basis") or ""),
            "phase": str(atom.get("phase") or ""),
            "transport": str(atom.get("transport") or ""),
        })
    if not samples:
        raise Tier2TrainingError("rule corpus produced no RF samples")
    return samples

def _make_model(*, n_estimators: int, max_depth: Optional[int],
                min_samples_leaf: int, random_state: int,
                n_jobs: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=n_jobs,
    )

def _best_group_split(y: np.ndarray, groups: np.ndarray, *,
                      test_size: float, random_state: int) -> Optional[tuple]:
    unique_groups = np.unique(groups)
    if len(unique_groups) < 2:
        return None
    all_classes = set(y.tolist())
    splitter = GroupShuffleSplit(
        n_splits=min(128, max(16, len(unique_groups))),
        test_size=test_size,
        random_state=random_state,
    )
    best = None
    best_score = None
    dummy = np.zeros(len(y), dtype=np.uint8)
    for train_idx, test_idx in splitter.split(dummy, y, groups):
        train_classes = set(y[train_idx].tolist())
        if train_classes != all_classes:
            continue
        test_classes = set(y[test_idx].tolist())
        score = (
            len(test_classes),
            -abs(len(test_idx) / len(y) - test_size),
            len(test_idx),
        )
        if best_score is None or score > best_score:
            best = (train_idx, test_idx)
            best_score = score
    return best

def _confidence_table(y_true: np.ndarray, y_pred: np.ndarray,
                      proba: np.ndarray) -> list[dict]:
    confidence = proba.max(axis=1)
    rows = []
    for threshold in CONFIDENCE_GRID:
        accepted = confidence >= threshold
        count = int(accepted.sum())
        rows.append({
            "threshold": threshold,
            "accepted": count,
            "coverage": float(count / len(y_true)) if len(y_true) else 0.0,
            "accuracy_when_accepted": (
                float(np.mean(y_pred[accepted] == y_true[accepted]))
                if count else None),
        })
    return rows

def _group_diagnostic(
    X: np.ndarray,
    y: np.ndarray,
    samples: Sequence[Mapping],
    classes: Sequence[str],
    *,
    n_estimators: int,
    max_depth: Optional[int],
    min_samples_leaf: int,
    test_size: float,
    random_state: int,
    n_jobs: int,
) -> dict:
    lineage_idx = np.array([
        index for index, sample in enumerate(samples)
        if sample["probe_family_basis"] == "lineage"
        and sample["probe_family_identity"]
    ], dtype=int)
    if not len(lineage_idx):
        return {"status": "unavailable", "reason": "no lineage-backed atoms"}
    X_lineage = X[lineage_idx]
    y_lineage = y[lineage_idx]
    groups = np.array([
        samples[index]["probe_family_identity"] for index in lineage_idx
    ])
    split = _best_group_split(
        y_lineage, groups, test_size=test_size,
        random_state=random_state)
    if split is None:
        return {"status": "unavailable", "reason": "fewer than two usable probe families"}
    train_idx, test_idx = split
    model = _make_model(
        n_estimators=n_estimators, max_depth=max_depth,
        min_samples_leaf=min_samples_leaf, random_state=random_state,
        n_jobs=n_jobs)
    model.fit(X_lineage[train_idx], y_lineage[train_idx])
    pred = model.predict(X_lineage[test_idx])
    proba = model.predict_proba(X_lineage[test_idx])
    labels = np.arange(len(classes))
    report = classification_report(
        y_lineage[test_idx], pred, labels=labels, target_names=list(classes),
        output_dict=True, zero_division=0)
    top2 = (
        float(top_k_accuracy_score(
            y_lineage[test_idx], proba, k=2, labels=labels))
        if len(classes) > 2 else 1.0)
    return {
        "status": "available",
        "meaning": "internal probe-family group diagnostic; not E0 held-out evidence",
        "lineage_atoms": int(len(lineage_idx)),
        "train_atoms": int(len(train_idx)),
        "validation_atoms": int(len(test_idx)),
        "train_probe_families": int(len(set(groups[train_idx]))),
        "validation_probe_families": int(len(set(groups[test_idx]))),
        "probe_family_overlap": int(len(
            set(groups[train_idx]) & set(groups[test_idx]))),
        "validation_classes": sorted({classes[index]
                                      for index in set(y_lineage[test_idx])}),
        "accuracy": float(np.mean(pred == y_lineage[test_idx])),
        "top2_accuracy": top2,
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "per_class": {
            name: report[name] for name in classes
        },
        "confidence": _confidence_table(y_lineage[test_idx], pred, proba),
    }

def train_tier2_rf(
    *,
    corpus_path: str,
    output_dir: str,
    provenance_path: Optional[str] = None,
    n_estimators: int = 100,
    max_depth: Optional[int] = 20,
    min_samples_leaf: int = 2,
    group_test_size: float = 0.2,
    random_state: int = 42,
    n_jobs: int = -1,
    deployment_threshold: float = 0.7,
    created_at: Optional[str] = None,
) -> dict:
    if n_estimators < 1 or min_samples_leaf < 1:
        raise Tier2TrainingError("RF tree/leaf parameters must be positive")
    if not 0.0 < group_test_size < 1.0:
        raise Tier2TrainingError("group_test_size must be in (0,1)")
    if not 0.0 <= deployment_threshold <= 1.0:
        raise Tier2TrainingError("deployment_threshold must be in [0,1]")

    atoms, provenance = load_rule_corpus(corpus_path, provenance_path)
    samples = samples_from_atoms(atoms)
    extractor = ResponseFeatureExtractor()
    X_rows, labels, feature_names = extractor.extract_batch(
        samples, label_key="cluster")
    X = np.asarray(X_rows, dtype=np.float64)
    encoder = LabelEncoder()
    y = encoder.fit_transform(np.asarray(labels))
    classes = list(encoder.classes_)

    diagnostic = _group_diagnostic(
        X, y, samples, classes,
        n_estimators=n_estimators, max_depth=max_depth,
        min_samples_leaf=min_samples_leaf, test_size=group_test_size,
        random_state=random_state, n_jobs=n_jobs)

    model = _make_model(
        n_estimators=n_estimators, max_depth=max_depth,
        min_samples_leaf=min_samples_leaf, random_state=random_state,
        n_jobs=n_jobs)
    model.fit(X, y)
    in_sample_accuracy = float(model.score(X, y))

    output = Path(output_dir)
    model_path = output / "fingerprint_model.joblib"
    encoder_path = output / "label_encoder.joblib"
    _atomic_joblib(model_path, model)
    _atomic_joblib(encoder_path, encoder)

    class_distribution = dict(sorted(Counter(labels).items()))
    phase_distribution = dict(sorted(Counter(
        sample["phase"] for sample in samples).items()))
    transport_distribution = dict(sorted(Counter(
        sample["transport"] for sample in samples).items()))
    feature_importance = sorted(
        ((name, float(value)) for name, value in zip(
            feature_names, model.feature_importances_)),
        key=lambda item: (-item[1], item[0]))

    core = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "training_contract": {
            "tier": 2,
            "runtime_position": "after_tier1_code_rule_miss",
            "final_fit": "all_current_rule_corpus_response_observations",
            "internal_diagnostic_axis": "probe_family_group_disjoint",
            "formal_external_validation": "E0_fresh_probe_family_round",
            "deployment_threshold": deployment_threshold,
        },
        "corpus": {
            "path": os.path.abspath(corpus_path),
            "provenance_path": os.path.abspath(
                provenance_path or f"{corpus_path}.provenance.json"),
            "corpus_digest": provenance["corpus_digest"],
            "corpus_file_sha256": provenance["corpus_file_sha256"],
            "source_candidates_digest": provenance["source_candidates_digest"],
            "construction": provenance["construction"],
        },
        "data": {
            "n_samples": len(samples),
            "n_classes": len(classes),
            "classes": classes,
            "class_distribution": class_distribution,
            "phase_distribution": phase_distribution,
            "transport_distribution": transport_distribution,
            "unique_response_identities": len({
                sample["response_identity"] for sample in samples}),
            "unique_probe_families": len({
                sample["probe_family_identity"] for sample in samples}),
            "lineage_backed_samples": sum(
                sample["probe_family_basis"] == "lineage"
                for sample in samples),
        },
        "feature_names": list(feature_names),
        "feature_schema_digest": canonical_sha256(list(feature_names)),
        "feature_importance": feature_importance,
        "params": {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_leaf": min_samples_leaf,
            "class_weight": "balanced_subsample",
            "random_state": random_state,
            "n_jobs": n_jobs,
        },
        "diagnostic": diagnostic,
        "final_fit": {
            "in_sample_accuracy": in_sample_accuracy,
            "meaning": "construction fit check only; not a generalization metric",
        },
        "runtime": {
            "python": os.sys.version.split()[0],
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "files": {
            "model": {
                "path": str(model_path.resolve()),
                "sha256": _sha256_file(model_path),
            },
            "label_encoder": {
                "path": str(encoder_path.resolve()),
                "sha256": _sha256_file(encoder_path),
            },
        },
    }
    manifest = dict(core)
    manifest["artifact_hash"] = canonical_sha256(core)
    manifest["created_at"] = created_at or datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    _atomic_json(output / "training_meta.json", manifest)
    return manifest
