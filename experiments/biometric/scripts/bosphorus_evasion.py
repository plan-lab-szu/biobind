"""Evasive re-enrollment on Bosphorus (run R-BOSPHORUS-20261109).

Frozen protocol (notes/bosphorus-protocol-draft-20261109.md):
  * Gallery: for every subject, the N_N sample 0 image. A subject whose gallery image
    has no detected face is left out of the gallery and listed.
  * Probes: every other image of a gallery subject, grouped by pose category.
    Same-person neutral repeats (N_N, sample >= 1) are the "normal recapture" control.
  * Score: integer inner product of 12-bit quantized vectors (Gamma = 2047), exactly as
    in dedup_calibration.py; thresholds tau are read from results/dedup_calibration.json
    (calibrated on LFW only, never tuned on Bosphorus). Match means score >= tau.
  * Missed duplicate (open set, the definition of dedup_calibration.py): the maximum
    score of the probe over the whole gallery is below tau, so deduplication would not
    flag the person. Reported with Clopper-Pearson 95% intervals.
  * Pairwise miss: the probe's score against the person's own gallery entry is below tau.
  * Detection failures: a probe with no detected face is a successful evasion. Every
    figure is given as "including detection failures" (failures count as misses) and
    "detected only".
  * False-duplicate control: N_N repeats of person i against the gallery without i,
    fraction with max score >= tau.

Per-probe scores contain subject ids and stay outside the repository (--scores-out).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import beta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from score_and_analyze import quantize  # noqa: E402

GAMMA = 2047
GROUPS = {
    "O_EYE": ["O_EYE"], "O_MOUTH": ["O_MOUTH"], "O_GLASSES": ["O_GLASSES"], "O_HAIR": ["O_HAIR"],
    "E_all": ["E_HAPPY", "E_SURPRISE", "E_FEAR", "E_SADNESS", "E_ANGER", "E_DISGUST"],
    "LFAU_all": None, "UFAU_all": None, "CAU_all": None,       # prefix groups
    "YR_le30": ["YR_R10", "YR_R20", "YR_R30"], "YR_45": ["YR_R45", "YR_L45"], "YR_90": ["YR_R90", "YR_L90"],
    "PR_slight": ["PR_SU", "PR_SD"], "PR_full": ["PR_U", "PR_D"],
    "CR_all": ["CR_RD", "CR_RU"],
}
PREFIX = {"LFAU_all": "LFAU_", "UFAU_all": "UFAU_", "CAU_all": "CAU_"}
# Groups that an attended enrollment station would plausibly accept.
ATTENDED = ["O_EYE", "O_MOUTH", "O_GLASSES", "O_HAIR", "E_all", "LFAU_all", "UFAU_all", "CAU_all",
            "YR_le30", "PR_slight"]


def cp(k: int, n: int) -> list[float]:
    if n == 0:
        return [None, None]
    lo = 0.0 if k == 0 else beta.ppf(0.025, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(0.975, k + 1, n - k)
    return [round(float(lo), 4), round(float(hi), 4)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--embeddings", type=Path, required=True)
    parser.add_argument("--extraction", type=Path, default=ROOT / "results" / "extraction_bosphorus.json")
    parser.add_argument("--failures", type=Path, default=None,
                        help="failures JSON written by extract_bosphorus.py (default: next to --embeddings)")
    parser.add_argument("--scores-out", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "bosphorus_evasion.json")
    args = parser.parse_args()

    data = np.load(args.embeddings)
    names, subj, cats, samp = data["names"], data["subjects"], data["categories"], data["samples"]
    q = quantize(data["embeddings"].astype(np.float64), GAMMA).astype(np.float64)
    extraction = json.loads(args.extraction.read_text())
    failures_path = args.failures or args.embeddings.with_suffix(".failures.json")
    failed = json.loads(failures_path.read_text())["failedImages"]
    calib = json.loads((ROOT / "results" / "dedup_calibration.json").read_text())
    taus = {k: v["tau"] for k, v in calib["thresholds"].items()}

    import re
    pat = re.compile(r"^(bs\d{3})_(.+)_(\d+)\.png$")
    failed_probe = []  # (subject, category)
    failed_gallery = []
    for f in failed:
        s, c, k = pat.match(f).groups()
        (failed_gallery if (c == "N_N" and int(k) == 0) else failed_probe).append((s, c))

    gal_idx = {}
    for i, (s, c, k) in enumerate(zip(subj, cats, samp)):
        if c == "N_N" and k == 0:
            gal_idx[str(s)] = i
    people = sorted(gal_idx)
    G = q[[gal_idx[p] for p in people]]
    pos = {p: j for j, p in enumerate(people)}
    all_subjects = sorted({str(s) for s in subj} | {s for s, _ in failed_probe} | {s for s, _ in failed_gallery})

    # Probe table: (subject, category, own score, max score over gallery) for detected probes.
    probes = []
    for i in range(len(names)):
        s, c, k = str(subj[i]), str(cats[i]), int(samp[i])
        if s not in pos or (c == "N_N" and k == 0):
            continue
        sc = G @ q[i]
        probes.append((s, c, k, sc[pos[s]], sc.max(), float(np.max(np.delete(sc, pos[s])))))
    args.scores_out.parent.mkdir(parents=True, exist_ok=True)
    with args.scores_out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["subject", "category", "sample", "own_score", "max_score_all", "max_score_others"])
        w.writerows(probes)

    def members(g):
        return set(GROUPS[g]) if GROUPS[g] is not None else None

    def select(g, rows):
        if g in PREFIX:
            return [r for r in rows if r[1].startswith(PREFIX[g])]
        return [r for r in rows if r[1] in members(g)]

    def select_failed(g):
        if g in PREFIX:
            return [x for x in failed_probe if x[1].startswith(PREFIX[g]) and x[0] in pos]
        return [x for x in failed_probe if x[1] in members(g) and x[0] in pos]

    result = {
        "run": "R-BOSPHORUS-20261109", "gamma": GAMMA,
        "subjectsInGallery": len(people), "galleryFailures": failed_gallery,
        "excludedUnpublishableSubjects": extraction["excludedUnpublishableSubjects"],
        "detectionFailuresTotal": len(failed), "thresholdsSource": "results/dedup_calibration.json (LFW)",
        "attendedGroups": ATTENDED, "tables": {},
    }
    for tname, tau in taus.items():
        rows_out = {}
        for g in list(GROUPS) + ["N_repeat_control"]:
            if g == "N_repeat_control":
                sel = [r for r in probes if r[1] == "N_N"]; fl = [x for x in failed_probe if x[1] == "N_N" and x[0] in pos]
            else:
                sel, fl = select(g, probes), select_failed(g)
            n_det = len(sel)
            open_miss = sum(1 for r in sel if r[4] < tau)
            own_miss = sum(1 for r in sel if r[3] < tau)
            n_all = n_det + len(fl)
            rows_out[g] = {
                "detected": n_det, "detectionFailures": len(fl),
                "openMissDetectedOnly": {"k": open_miss, "n": n_det, "rate": round(open_miss / n_det, 4) if n_det else None,
                                         "ci95": cp(open_miss, n_det)},
                "openMissIncludingFailures": {"k": open_miss + len(fl), "n": n_all,
                                              "rate": round((open_miss + len(fl)) / n_all, 4) if n_all else None,
                                              "ci95": cp(open_miss + len(fl), n_all)},
                "pairwiseMissDetectedOnly": {"k": own_miss, "n": n_det, "rate": round(own_miss / n_det, 4) if n_det else None,
                                             "ci95": cp(own_miss, n_det)},
            }
        # Pooled attended groups.
        sel = [r for g in ATTENDED for r in select(g, probes)]
        fl = [x for g in ATTENDED for x in select_failed(g)]
        om = sum(1 for r in sel if r[4] < tau)
        rows_out["ATTENDED_pooled"] = {
            "detected": len(sel), "detectionFailures": len(fl),
            "openMissIncludingFailures": {"k": om + len(fl), "n": len(sel) + len(fl),
                                          "rate": round((om + len(fl)) / (len(sel) + len(fl)), 4),
                                          "ci95": cp(om + len(fl), len(sel) + len(fl))}}
        # False-duplicate control: N_N repeats against the gallery without the person.
        ctrl = [r for r in probes if r[1] == "N_N"]
        fd = sum(1 for r in ctrl if r[5] >= tau)
        result["tables"][tname] = {"tau": tau, "cosineEquivalent": round(tau / GAMMA ** 2, 4), "groups": rows_out,
                                   "falseDuplicateControl": {"k": fd, "n": len(ctrl), "rate": round(fd / len(ctrl), 4),
                                                             "ci95": cp(fd, len(ctrl)),
                                                             "gallerySize": len(people) - 1}}
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"gallery {len(people)} subjects, {len(probes)} detected probes, {len(failed)} detection failures")
    for tname in ("FMR<=0.001", "FMR<=0.0001", "FMR<=1e-05"):
        t = result["tables"][tname]
        print(f"\n{tname}  tau={t['tau']} cos~{t['cosineEquivalent']}  FD control {t['falseDuplicateControl']['rate']}")
        for g, v in t["groups"].items():
            r = v["openMissIncludingFailures"]
            print(f"  {g:18s} n={r['n']:4d} miss={r['rate']} ci={r['ci95']} (detFail {v['detectionFailures']})")


if __name__ == "__main__":
    main()
