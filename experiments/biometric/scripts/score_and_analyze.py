"""Score LFW View 2 pairs from extracted embeddings, under several quantizations.

For each variant this writes results/scores_<variant>.csv (pair_id,squared_distance),
runs the fixed-fold protocol evaluator (evaluate_pair_scores.evaluate), and adds
descriptive all-pair statistics (ROC AUC, EER) that are NOT used for any threshold.

Quantization (frozen before scoring): L2-normalize, multiply by Gamma, round half
away from zero (as BioZKFHE / scmv-model.mjs); Gamma = 2**(b-1) - 1 for a signed
b-bit coordinate, plus the BioZKFHE rule Gamma = L = 512. Squared integer distance
is offset-invariant, so it equals the circuit's distance on u16-offset coordinates.
The float reference uses round(1e9 * squared float distance) to fit the integer CSV.

Usage: python -I scripts/score_and_analyze.py C:\\biobind-data\\embeddings\\inception_vggface2_512.npz
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate_pair_scores import evaluate, load_protocol  # noqa: E402

PAIRS = ROOT / "data" / "lfw" / "view2_pairs.csv"
RESULTS = ROOT / "results"
CIRCUIT_DISTANCE_BITS = 48


def quantize(x: np.ndarray, gamma: int) -> np.ndarray:
    unit = x / np.linalg.norm(x, axis=1, keepdims=True)
    y = unit * gamma
    return (np.sign(y) * np.floor(np.abs(y) + 0.5)).astype(np.int64)


def roc_stats(distances: np.ndarray, labels: np.ndarray) -> dict:
    # Accept when distance <= t; sweep all distinct thresholds.
    order = np.argsort(distances, kind="stable")
    d, y = distances[order], labels[order]
    pos, neg = y.sum(), (1 - y).sum()
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    last = np.r_[d[1:] != d[:-1], True]
    tpr, fpr = tp[last] / pos, fp[last] / neg
    tpr, fpr = np.r_[0.0, tpr], np.r_[0.0, fpr]
    auc = float(np.trapz(tpr, fpr))
    fnr = 1 - tpr
    i = int(np.argmin(np.abs(fnr - fpr)))
    return {"auc": round(auc, 6), "eer": round(float((fnr[i] + fpr[i]) / 2), 5)}


def main() -> None:
    data = np.load(sys.argv[1])
    index = {n: i for i, n in enumerate(data["names"].tolist())}
    emb = data["embeddings"].astype(np.float64)
    with PAIRS.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    left = np.array([index[r["image_left"]] for r in rows])
    right = np.array([index[r["image_right"]] for r in rows])
    labels = np.array([int(r["same_person"]) for r in rows])
    pair_ids = [r["pair_id"] for r in rows]
    protocol = load_protocol()

    variants = {"float": None, **{f"int{b}": 2 ** (b - 1) - 1 for b in (4, 6, 8, 10, 12, 16)}, "biozkfhe_gamma512": 512}
    summary = {"embeddings": sys.argv[1], "pairs": len(rows), "variants": {}}
    RESULTS.mkdir(exist_ok=True)
    for name, gamma in variants.items():
        if gamma is None:
            unit = emb / np.linalg.norm(emb, axis=1, keepdims=True)
            diff = unit[left] - unit[right]
            dist = np.rint((diff * diff).sum(axis=1) * 1e9).astype(np.int64)
            max_coord = None
        else:
            q = quantize(emb, gamma)
            diff = q[left] - q[right]
            dist = (diff * diff).sum(axis=1)
            max_coord = int(np.abs(q).max())
        assert int(dist.max()) < 2 ** CIRCUIT_DISTANCE_BITS
        path = RESULTS / f"scores_{name}.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["pair_id", "squared_distance"])
            w.writerows(zip(pair_ids, dist.tolist()))
        report = evaluate(protocol, {p: int(v) for p, v in zip(pair_ids, dist.tolist())})
        acc = [(f["tp"] + f["tn"]) / 600 for f in report["folds"]]
        summary["variants"][name] = {
            "gamma": gamma, "maxAbsCoordinate": max_coord,
            "heldOutAccuracyMean": round(float(np.mean(acc)), 5), "heldOutAccuracyStd": round(float(np.std(acc)), 5),
            "pooledTar": round(report["pooledTar"], 5), "pooledFar": round(report["pooledFar"], 5),
            "pooledFalseAccepts": report["pooledHeldOutCounts"].get("fp", 0),
            "pooledFalseRejects": report["pooledHeldOutCounts"].get("fn", 0),
            "thresholds": [f["threshold"] for f in report["folds"]],
            **roc_stats(dist.astype(np.float64), labels),
        }
        (RESULTS / f"lfw_view2_{name}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary["note"] = ("heldOut* and pooled* follow the fixed-fold protocol (threshold from the other nine folds); "
                       "auc and eer are descriptive over all 6,000 pairs and select nothing. LFW has 3,000 impostor "
                       "pairs, so no low-FAR claim follows.")
    (RESULTS / "lfw_view2_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
