"""Separate detector failures from matching misses in the archived aggregates.

No images, embeddings, thresholds or historical outputs are changed. Use
--scores and --failures for subject-cluster intervals from private per-probe
records. Without them, only aggregate counts and rates can be produced.
"""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

GROUPS = {
    "O_EYE": ["O_EYE"], "O_MOUTH": ["O_MOUTH"], "O_GLASSES": ["O_GLASSES"], "O_HAIR": ["O_HAIR"],
    "E_all": ["E_HAPPY", "E_SURPRISE", "E_FEAR", "E_SADNESS", "E_ANGER", "E_DISGUST"],
    "YR_le30": ["YR_R10", "YR_R20", "YR_R30"], "YR_45": ["YR_R45", "YR_L45"],
    "YR_90": ["YR_R90", "YR_L90"], "PR_slight": ["PR_SU", "PR_SD"],
    "PR_full": ["PR_U", "PR_D"], "CR_all": ["CR_RD", "CR_RU"], "N_repeat_control": ["N_N"],
}
PREFIXES = {"LFAU_all": "LFAU_", "UFAU_all": "UFAU_", "CAU_all": "CAU_"}


def fraction(k, n):
    assert isinstance(k, int) and isinstance(n, int) and 0 <= k <= n
    return {"k": k, "n": n, "rate": k / n if n else None}


def decompose(group):
    old = group["openMissIncludingFailures"]
    failures, detected = group["detectionFailures"], group["detected"]
    assert old["n"] == failures + detected
    misses = old["k"] - failures
    detected_rate = fraction(misses, detected)
    if "openMissDetectedOnly" in group:
        reported = group["openMissDetectedOnly"]
        assert (reported["k"], reported["n"]) == (misses, detected)
        assert abs(reported["rate"] - detected_rate["rate"]) <= 0.000051
    return {
        "submitted": old["n"],
        "detected": detected,
        "detectionFailure": fraction(failures, old["n"]),
        "matchingMissDetected": detected_rate,
        "candidateAcceptanceFailClosed": fraction(misses, old["n"]),
        "historicalCombined": fraction(old["k"], old["n"]),
    }


def analyze(source, extraction):
    result = {
        "run": "R-BOSPHORUS-REANALYSIS-20261114",
        "sourceRun": source["run"],
        "subjectsInGallery": source["subjectsInGallery"],
        "images": extraction["images"],
        "detectionFailuresTotal": extraction["detectionFailures"],
        "attendedGroups": source["attendedGroups"],
        "interpretation": {
            "grouping": "Original protocol grouping retained; no operational acceptance gate was run.",
            "matchingMissDetected": "Maximum score over the fixed gallery below the unchanged LFW threshold, conditional on detection.",
            "candidateAcceptanceFailClosed": "Matching misses / all submitted probes, assuming every detection failure rejects; offline candidates, not issued credentials.",
            "historicalCombined": "Historical detection failures plus matching misses; not an issuance-risk estimate.",
            "weighting": "Pooled attempt-weighted descriptive rates; subjects have unequal probe counts.",
            "uncertainty": "No independence-based intervals. Per-subject scores unavailable at reanalysis; subject-cluster intervals and subject-level any-miss rates not estimated.",
        },
        "tables": {},
    }
    assert source["galleryFailures"] == []
    assert extraction["embedded"] + extraction["detectionFailures"] == extraction["images"]
    for name, table in source["tables"].items():
        groups = {g: decompose(row) for g, row in table["groups"].items()}
        pooled = groups["ATTENDED_pooled"]
        for field in ["submitted", "detected"]:
            assert pooled[field] == sum(groups[g][field] for g in source["attendedGroups"])
        for field in ["detectionFailure", "matchingMissDetected", "historicalCombined"]:
            assert pooled[field]["k"] == sum(groups[g][field]["k"] for g in source["attendedGroups"])
        singles = [v for g, v in groups.items() if g != "ATTENDED_pooled"]
        assert sum(v["submitted"] for v in singles) + source["subjectsInGallery"] == extraction["images"]
        assert sum(v["detectionFailure"]["k"] for v in singles) == extraction["detectionFailures"]
        assert sum(v["detected"] for v in singles) + source["subjectsInGallery"] == extraction["embedded"]
        control = table["falseDuplicateControl"]
        assert control["n"] == groups["N_repeat_control"]["detected"]
        result["tables"][name] = {
            "tau": table["tau"], "cosineEquivalent": table["cosineEquivalent"],
            "groups": groups,
            "falseDuplicateControl": fraction(control["k"], control["n"]),
        }
    return result


def cluster_analysis(result, source, scores_path, failures_path, seed, repetitions):
    """Resample subjects with their full probe sets, holding the gallery fixed."""
    import numpy as np

    with scores_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    failed_names = json.loads(failures_path.read_text())["failedImages"]
    failed = []
    for name in failed_names:
        match = re.fullmatch(r"(bs\d{3})_(.+)_(\d+)\.png", name)
        assert match, "Unexpected failure filename"
        subject, category, sample = match.groups()
        assert (category, int(sample)) != ("N_N", 0), "Gallery detection failure"
        failed.append((subject, category))
    people = sorted({row["subject"] for row in rows} | {s for s, _ in failed})
    assert len(people) == result["subjectsInGallery"]
    assert len(rows) + len(failed) + len(people) == result["images"]
    assert len({(r["subject"], r["category"], r["sample"]) for r in rows}) == len(rows)
    assert not (set(people) & set(source["excludedUnpublishableSubjects"]))
    pos = {p: i for i, p in enumerate(people)}
    rng = np.random.Generator(np.random.PCG64(seed))
    # Each multinomial row is equivalent to drawing 98 complete subjects
    # with replacement. The same draws are used for all thresholds/groups.
    weights = rng.multinomial(len(people), np.full(len(people), 1 / len(people)), size=repetitions)

    def belongs(group, category):
        if group == "ATTENDED_pooled":
            return any(belongs(g, category) for g in result["attendedGroups"])
        if group in PREFIXES:
            return category.startswith(PREFIXES[group])
        return category in GROUPS[group]

    def counts(selected):
        out = np.zeros(len(people), dtype=np.int64)
        for p in selected:
            out[pos[p]] += 1
        return out

    def add_interval(stat, numerator, denominator):
        assert (int(numerator.sum()), int(denominator.sum())) == (stat["k"], stat["n"])
        # An empirical zero-event bootstrap cannot supply a useful upper bound.
        if stat["k"] in (0, stat["n"]):
            stat["clusterCi95"] = None
            stat["intervalStatus"] = "omitted_at_empirical_boundary"
            return
        den = weights @ denominator
        assert np.all(den > 0), "Zero bootstrap denominator"
        rates = (weights @ numerator) / den
        stat["clusterCi95"] = np.quantile(rates, [0.025, 0.975], method="linear").tolist()

    for name, table in result["tables"].items():
        tau = table["tau"]
        for group, values in table["groups"].items():
            probes = [r for r in rows if belongs(group, r["category"])]
            det = counts(r["subject"] for r in probes)
            failure = counts(s for s, c in failed if belongs(group, c))
            miss = counts(r["subject"] for r in probes if float(r["max_score_all"]) < tau)
            assert int(det.sum()) == values["detected"]
            assert int(failure.sum()) == values["detectionFailure"]["k"]
            assert int(miss.sum()) == values["matchingMissDetected"]["k"]
            if group != "ATTENDED_pooled":
                own = sum(float(r["own_score"]) < tau for r in probes)
                assert own == source["tables"][name]["groups"][group]["pairwiseMissDetectedOnly"]["k"]
            add_interval(values["matchingMissDetected"], miss, det)
            add_interval(values["candidateAcceptanceFailClosed"], miss, det + failure)
            add_interval(values["detectionFailure"], failure, det + failure)
            values["subjectsWithSubmittedProbes"] = int(np.count_nonzero(det + failure))
            values["subjectsWithDetectedProbes"] = int(np.count_nonzero(det))
            values["subjectsWithAnyMatchingMiss"] = fraction(int(np.count_nonzero(miss)), int(np.count_nonzero(det)))
        neutral = [r for r in rows if r["category"] == "N_N"]
        den = counts(r["subject"] for r in neutral)
        num = counts(r["subject"] for r in neutral if float(r["max_score_others"]) >= tau)
        add_interval(table["falseDuplicateControl"], num, den)
    result["interpretation"]["uncertainty"] = "95% percentile subject-cluster bootstrap intervals conditional on the observed gallery and thresholds; whole subject probe sets resampled. Not a worst-case adversarial bound. Intervals omitted at empirical 0/1 boundaries."
    result["bootstrap"] = {
        "seed": seed, "repetitions": repetitions, "rng": "numpy.PCG64",
        "numpyVersion": np.__version__, "subjectsPerDraw": len(people),
        "quantileMethod": "linear", "weighting": "ratio of pooled counts per draw",
        "gallery": "held fixed; gallery-selection uncertainty not estimated",
        "anyMissInterpretation": "descriptive fraction of subjects with a miss in their available finite probe sets; unequal probe counts; not an adaptive attack probability",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "results/bosphorus_evasion.json")
    parser.add_argument("--extraction", type=Path, default=ROOT / "results/extraction_bosphorus.json")
    parser.add_argument("--out", type=Path, default=ROOT / "results/bosphorus_reanalysis_20261114.json")
    parser.add_argument("--scores", type=Path, help="Private per-probe CSV; stays outside repository")
    parser.add_argument("--failures", type=Path, help="Private failed-image JSON")
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--repetitions", type=int, default=20000)
    args = parser.parse_args()
    source = json.loads(args.source.read_text())
    result = analyze(source, json.loads(args.extraction.read_text()))
    assert bool(args.scores) == bool(args.failures), "Provide both --scores and --failures"
    inputs = [args.source, args.extraction]
    if args.scores:
        cluster_analysis(result, source, args.scores, args.failures, args.seed, args.repetitions)
        inputs += [args.scores, args.failures]
    result["inputs"] = [
        {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in inputs
    ]
    result["scriptSha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for name, table in result["tables"].items():
        pooled = table["groups"]["ATTENDED_pooled"]
        print(name, json.dumps(pooled))


if __name__ == "__main__":
    main()
