"""Evaluate integer squared distances on the fixed LFW View 2 folds.

Input CSV: pair_id,squared_distance. All 6,000 official pair IDs are required.
The threshold is selected from the other nine folds by balanced accuracy;
ties choose the smaller threshold. No held-out score enters selection.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from itertools import groupby
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAIRS = ROOT / "data" / "lfw" / "view2_pairs.csv"


def choose_threshold(train: list[tuple[int, int]]) -> int:
    positives = sum(label for _, label in train)
    negatives = len(train) - positives
    if not positives or not negatives:
        raise ValueError("training folds need both labels")
    best_threshold = -1
    best_score_num = negatives * positives  # all-reject balanced accuracy numerator
    tp = fp = 0
    for distance, rows in groupby(sorted(train), key=lambda item: item[0]):
        group = [label for _, label in rows]
        tp += sum(group)
        fp += len(group) - sum(group)
        score_num = tp * negatives + (negatives - fp) * positives
        if score_num > best_score_num:
            best_score_num = score_num
            best_threshold = distance
    return best_threshold


def load_protocol() -> dict[str, tuple[int, int]]:
    with PAIRS.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    protocol = {row["pair_id"]: (int(row["fold"]), int(row["same_person"])) for row in rows}
    if len(rows) != 6000 or len(protocol) != 6000:
        raise ValueError("protocol file is not the validated 6,000-pair View 2 set")
    return protocol


def load_scores(path: Path, protocol: dict[str, tuple[int, int]]) -> dict[str, int]:
    result = {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != ["pair_id", "squared_distance"]:
            raise ValueError("score CSV must have exactly pair_id,squared_distance")
        for row in reader:
            pair_id = row["pair_id"]
            if pair_id not in protocol or pair_id in result:
                raise ValueError(f"unknown or duplicate pair_id: {pair_id}")
            value = int(row["squared_distance"])
            if value < 0 or value >= 2**48:
                raise ValueError(f"out-of-range squared distance: {pair_id}")
            result[pair_id] = value
    if result.keys() != protocol.keys():
        raise ValueError(f"missing {len(protocol.keys() - result.keys())} official pairs")
    return result


def evaluate(protocol: dict[str, tuple[int, int]], scores: dict[str, int]) -> dict:
    folds = []
    totals = Counter()
    for held_out in range(10):
        train = [(scores[key], label) for key, (fold, label) in protocol.items() if fold != held_out]
        threshold = choose_threshold(train)
        counts = Counter()
        for key, (fold, label) in protocol.items():
            if fold != held_out:
                continue
            accepted = scores[key] <= threshold
            counts["tp" if label and accepted else "fn" if label else "fp" if accepted else "tn"] += 1
        if counts["tp"] + counts["fn"] != 300 or counts["fp"] + counts["tn"] != 300:
            raise ValueError(f"invalid held-out fold {held_out}")
        totals.update(counts)
        folds.append({"fold": held_out, "threshold": threshold, **dict(counts),
                      "tar": counts["tp"] / 300, "far": counts["fp"] / 300})
    return {"thresholdRule": "max training balanced accuracy; smaller threshold on ties",
            "acceptRule": "squared_distance <= threshold",
            "folds": folds, "pooledHeldOutCounts": dict(totals),
            "pooledTar": totals["tp"] / 3000, "pooledFar": totals["fp"] / 3000,
            "warning": "Descriptive View 2 cross-validation only; paired images/identities are dependent. No low-FAR extrapolation."}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scores_csv", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    protocol = load_protocol()
    scores = load_scores(args.scores_csv, protocol)
    report = evaluate(protocol, scores)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
