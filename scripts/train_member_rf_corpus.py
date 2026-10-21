"""Train member refinement RFs from the same frozen phase-aware rule corpus.

Unlike the legacy row-random trainer, admission uses a lineage-backed
probe-family diagnostic. Final admitted models are refit on all eligible
current-corpus samples. This is not an independent fresh-round evaluation.
"""
import argparse
from collections import Counter, defaultdict
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
from sklearn.preprocessing import LabelEncoder
import config
from core.rule_corpus import load_rule_corpus
from fingerprint.feature_extractor import ResponseFeatureExtractor
from fingerprint.tier2_rf import (
    samples_from_atoms, _group_diagnostic, _make_model, _atomic_json,
    _atomic_joblib, _sha256_file,
)

def train(corpus, output, n_jobs=4):
    atoms, provenance = load_rule_corpus(corpus)
    samples = samples_from_atoms(atoms)
    grouped = defaultdict(list)
    for sample in samples:
        grouped[sample['cluster']].append(sample)
    out = Path(output)
    extractor = ResponseFeatureExtractor()
    manifest = {}
    for cluster, rows in sorted(grouped.items()):
        counts = Counter(r['member'] for r in rows)
        eligible = sorted(m for m, n in counts.items()
                          if n >= config.MEMBER_RF_MIN_SAMPLES_PER_MEMBER)
        meta = {'cluster': cluster, 'members': eligible,
                'all_member_counts': dict(counts),
                'corpus_digest': provenance['corpus_digest'],
                'diagnostic_axis': 'probe_family_group_disjoint',
                'formal_external_validation': 'not_evaluated',
                'final_fit': 'all_eligible_current_corpus_observations'}
        if len(eligible) < config.MEMBER_RF_MIN_SEPARABLE_MEMBERS:
            meta.update(status='trivial', reason='Fewer than two sufficiently sampled members')
        else:
            fit_rows = [r for r in rows if r['member'] in eligible]
            X, labels, names = extractor.extract_batch(fit_rows, label_key='member', show_progress=False)
            X = np.asarray(X, dtype=np.float64)
            le = LabelEncoder()
            y = le.fit_transform(labels)
            classes = list(le.classes_)
            diag = _group_diagnostic(X, y, fit_rows, classes, n_estimators=100,
                max_depth=20, min_samples_leaf=5, test_size=0.2,
                random_state=42, n_jobs=n_jobs)
            meta.update(n_samples=len(fit_rows), feature_names=names, diagnostic=diag)
            admitted = (diag.get('status') == 'available'
                        and diag.get('probe_family_overlap') == 0
                        and set(diag.get('validation_classes', [])) == set(classes)
                        and diag['accuracy'] >= config.MEMBER_RF_MIN_ACCURACY)
            if not admitted:
                meta.update(status='member_undetermined',
                            reason='Probe-family diagnostic unavailable, incomplete member coverage, or below configured accuracy gate')
            else:
                model = _make_model(n_estimators=100, max_depth=20,
                    min_samples_leaf=5, random_state=42, n_jobs=n_jobs)
                model.fit(X, y)
                cdir = out/cluster
                _atomic_joblib(cdir/'model.joblib', model)
                _atomic_joblib(cdir/'label_encoder.joblib', le)
                meta.update(status='ok', members=classes,
                    test_accuracy=diag['accuracy'], in_sample_accuracy=float(model.score(X, y)),
                    model_sha256=_sha256_file(cdir/'model.joblib'),
                    encoder_sha256=_sha256_file(cdir/'label_encoder.joblib'))
                _atomic_json(cdir/'training_meta.json', meta)
        manifest[cluster] = meta
        _atomic_json(out/'manifest.json', manifest)
        print(cluster, meta['status'], meta.get('diagnostic', {}).get('accuracy'), flush=True)
    return manifest

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--corpus', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--n-jobs', type=int, default=4)
    args = p.parse_args()
    train(args.corpus, args.output, args.n_jobs)
