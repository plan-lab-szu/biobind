"""Validate LFW View 2 fold structure and export pair records for evaluation."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "lfw" / "pairs.txt"
OUTPUT = ROOT / "data" / "lfw" / "view2_pairs.csv"
SUMMARY = ROOT / "data" / "lfw" / "protocol_summary.json"


def image_id(person: str, index: str) -> str:
    n = int(index)
    if n < 1:
        raise ValueError(f"invalid image index: {index}")
    return f"{person}/{person}_{n:04d}.jpg"


def main() -> None:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("empty pairs file")
    header = lines[0].split()
    if len(header) != 2:
        raise ValueError(f"invalid View 2 header: {header}")
    folds, pairs_per_class = map(int, header)
    if (folds, pairs_per_class) != (10, 300):
        raise ValueError(f"unexpected official fold shape: {header}")
    records = []
    expected = folds * pairs_per_class * 2
    if len(lines) - 1 != expected:
        raise ValueError(f"expected {expected} pairs, found {len(lines) - 1}")
    for fold in range(folds):
        for offset in range(pairs_per_class * 2):
            fields = lines[1 + fold * pairs_per_class * 2 + offset].split()
            same = offset < pairs_per_class
            if same and len(fields) == 3:
                left = image_id(fields[0], fields[1])
                right = image_id(fields[0], fields[2])
            elif not same and len(fields) == 4:
                left = image_id(fields[0], fields[1])
                right = image_id(fields[2], fields[3])
                if fields[0] == fields[2]:
                    raise ValueError(f"negative pair has same identity at fold {fold}")
            else:
                raise ValueError(f"bad pair at fold {fold}, position {offset}: {fields}")
            records.append((fold, f"lfw-v2-f{fold:02d}-p{offset:03d}", left, right, int(same)))
    with OUTPUT.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(("fold", "pair_id", "image_left", "image_right", "same_person"))
        writer.writerows(records)
    summary = {
        "source": str(SOURCE),
        "sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "folds": folds,
        "pairsPerFold": pairs_per_class * 2,
        "genuinePerFold": pairs_per_class,
        "impostorPerFold": pairs_per_class,
        "totalPairs": len(records),
        "imagesAvailable": False,
        "scoresAvailable": False,
    }
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
