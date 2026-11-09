"""Calibrate the SCMV 1:N deduplication threshold (inner product) on LFW and
estimate false-duplicate and missed-duplicate rates versus gallery size.

Protocol (fixed before running):
  * Score: integer inner product of 12-bit quantized vectors (Gamma = 2047, the
    recommended circuit setting); SCMV computes the same inner product on
    plaintext slots. A probe is a duplicate if its maximum score over the
    gallery is >= tau.
  * Identity split by SHA-256 of the identity name: even -> calibration half,
    odd -> test half. Thresholds are chosen on the calibration half only.
    Further splits use independently salted hashes.
  * Thresholds: smallest tau with calibration per-comparison FMR <= target, for
    targets 1e-3 .. 1e-6; plus the model's current tau = Gamma^2 / 2 (cosine 0.5).
  * Test half per-comparison FMR (impostor image pairs) and FNMR (genuine image
    pairs), with exact Clopper-Pearson 95% intervals (rule-of-three style upper
    bound when zero errors).
  * Open-set simulation on the test half: identities split again by hash into a
    gallery pool (3/4) and newcomers (1/4). Gallery = first image per identity.
    False duplicate: a newcomer image whose max score >= tau. Missed duplicate:
    a second image of a gallery identity whose max score < tau.
  * Extrapolation to larger galleries: FD(N) = 1 - (1 - FMR)^N, assuming
    independent comparisons; reported with the FMR point estimate and its
    upper 95% bound.

Usage: python -I scripts/dedup_calibration.py <embeddings.npz>
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import beta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from score_and_analyze import quantize  # noqa: E402

GAMMA = 2047
TARGETS = [1e-3, 1e-4, 1e-5, 1e-6]
SIZES = [100, 250, 500, 1000]
EXTRAPOLATE = [10_000, 100_000, 1_000_000]


def bucket(name: str, mod: int, salt: str = "") -> int:
    return int(hashlib.sha256(f"{salt}{name}".encode()).hexdigest(), 16) % mod


def ci(k: int, n: int) -> tuple[float, float]:
    lo = 0.0 if k == 0 else float(beta.ppf(0.025, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(0.975, k + 1, n - k))
    return lo, hi


def pair_scores(q: np.ndarray, ids: np.ndarray, rows: np.ndarray):
    """Genuine and impostor inner products among `rows` (each unordered pair once)."""
    sub = q[rows].astype(np.float64)
    lab = ids[rows]
    genuine, impostor = [], []
    for start in range(0, len(rows), 1024):
        block = sub[start:start + 1024] @ sub.T  # exact: integers below 2^53
        for k in range(block.shape[0]):
            i = start + k
            s = block[k, i + 1:]
            same = lab[i + 1:] == lab[i]
            genuine.append(s[same])
            impostor.append(s[~same])
    return np.concatenate(genuine).astype(np.int64), np.concatenate(impostor).astype(np.int64)


def threshold_for(impostor_sorted: np.ndarray, target: float) -> int:
    # smallest tau with fraction(impostor >= tau) <= target
    n = len(impostor_sorted)
    allowed = int(np.floor(target * n))
    if allowed >= n:
        return int(impostor_sorted[0])
    return int(impostor_sorted[n - allowed - 1]) + 1


def main() -> None:
    data = np.load(sys.argv[1])
    names = data["names"].tolist()
    q = quantize(data["embeddings"].astype(np.float64), GAMMA)
    person = np.array([n.split("/")[0] for n in names])
    half = np.array([bucket(p, 2) for p in person])
    calib_rows = np.where(half == 0)[0]
    test_rows = np.where(half == 1)[0]

    g_cal, i_cal = pair_scores(q, person, calib_rows)
    g_test, i_test = pair_scores(q, person, test_rows)
    i_cal_sorted = np.sort(i_cal)

    thresholds = {f"FMR<={t:g}": threshold_for(i_cal_sorted, t) for t in TARGETS}
    thresholds["current Gamma^2/2"] = GAMMA * GAMMA // 2

    # Open-set split of the test half.
    by_person = defaultdict(list)
    for r in test_rows:
        by_person[person[r]].append(r)
    for p in by_person:
        by_person[p].sort(key=lambda r: names[r])
    # Independent salts: the half split already fixes the low bits of the unsalted hash.
    gallery_pool = sorted((p for p in by_person if bucket(p, 4, "open|") != 0), key=lambda p: bucket(p, 1 << 30, "order|"))
    newcomers = [p for p in by_person if bucket(p, 4, "open|") == 0]
    newcomer_rows = np.array([r for p in newcomers for r in by_person[p]])

    report = {
        "gamma": GAMMA,
        "identities": {"calibration": int(len(set(person[calib_rows]))), "test": len(by_person),
                       "testGalleryPool": len(gallery_pool), "testNewcomers": len(newcomers)},
        "pairs": {"calibrationGenuine": len(g_cal), "calibrationImpostor": len(i_cal),
                  "testGenuine": len(g_test), "testImpostor": len(i_test)},
        "thresholds": {},
    }
    for label, tau in thresholds.items():
        fm = int((i_test >= tau).sum())
        fn = int((g_test < tau).sum())
        fmr, fnmr = fm / len(i_test), fn / len(g_test)
        fmr_hi = ci(fm, len(i_test))[1]
        entry = {"tau": tau, "cosineEquivalent": round(tau / GAMMA ** 2, 4),
                 "testFMR": fmr, "testFMR95": ci(fm, len(i_test)), "testFalseMatches": fm,
                 "testFNMR": round(fnmr, 5), "testFNMR95": [round(x, 5) for x in ci(fn, len(g_test))],
                 "openSet": [], "extrapolatedFalseDuplicate": {}}
        for size in SIZES + [len(gallery_pool)]:
            gal_people = gallery_pool[:size]
            gal_rows = np.array([by_person[p][0] for p in gal_people])
            G = q[gal_rows].astype(np.float64)
            fd = int(((q[newcomer_rows].astype(np.float64) @ G.T).max(axis=1) >= tau).sum())
            mated = np.array([by_person[p][1] for p in gal_people if len(by_person[p]) >= 2])
            md = int(((q[mated].astype(np.float64) @ G.T).max(axis=1) < tau).sum()) if len(mated) else 0
            entry["openSet"].append({"gallerySize": size,
                                     "falseDuplicateRate": round(fd / len(newcomer_rows), 5), "falseDuplicates": fd,
                                     "newcomerProbes": int(len(newcomer_rows)),
                                     "missedDuplicateRate": round(md / len(mated), 5) if len(mated) else None,
                                     "missedDuplicates": md, "matedProbes": int(len(mated))})
        for n in EXTRAPOLATE:
            entry["extrapolatedFalseDuplicate"][str(n)] = {
                "pointEstimate": round(1 - (1 - fmr) ** n, 5), "upper95": round(1 - (1 - fmr_hi) ** n, 5)}
        report["thresholds"][label] = entry
    report["notes"] = ("Extrapolation assumes independent comparisons and an LFW-like population; LFW identities are "
                       "celebrities with dependent images. Per-comparison FMR below about 3/testImpostor pairs cannot "
                       "be resolved on this data. Missed-duplicate rates are non-adversarial; they are not the "
                       "adversarial-presentation miss rate f_nm of the security model.")
    out = ROOT / "results" / "dedup_calibration.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
