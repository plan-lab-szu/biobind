"""Summarize immutable BGV runs and verify the C1 arithmetic preconditions."""
import csv
import json
from decimal import Decimal, getcontext
from pathlib import Path
getcontext().prec = 60
RESULTS = Path(__file__).resolve().parent.parent / "results"
OUT = RESULTS / "bgv-analysis-20261030-r2"
OUT.mkdir(exist_ok=False)
measurement = json.loads((RESULTS / "bgv-measure-20261030/summary.json").read_text())
rows = []
for run in measurement["profiles"]:
    p = json.loads((RESULTS / "bgv-measure-20261030" / run["profile"] / "parameters.json").read_text())
    d_bound = (Decimal(p["Gamma"]) + Decimal(p["L"]).sqrt()/2)**2
    packed_bound = 2*d_bound*sum(Decimal(p["T"])**k for k in range(p["n"]))
    assert Decimal(p["T"]) > 2*d_bound
    assert Decimal(p["plain_modulus"]) > packed_bound
    m = run["medians"]
    rows.append({"profile": run["profile"], "raw_bytes": m["none_bytes"], "raw_MiB": m["none_bytes"]/2**20,
                 "compressed_MiB": m["default_bytes"]/2**20, "enroll_median_ms": m["enroll_total_ms"],
                 "add_median_ms": m["add_ms"], "load_two_median_ms": m["load_two_ms"],
                 "save_merge_median_ms": m["save_merge_ms"],
                 "sum_three_keccak_medians_ms": sum(h["median_keccak_ms"] for h in run["binaryEvidence"]),
                 "single_merge_checks_pass": run["allChecksPass"], "single_merge_query_noise_min": run["minimumQueryNoiseBits"],
                 "C1_T_gt_2D": True, "C1_plain_gt_2D_sum_Tk": True,
                 "D_upper": str(d_bound), "packed_bound": str(packed_bound),
                 "coordinate_only_counterexample_dot": p["L"]*p["Gamma"]**2})
stress = []
for name in ["bgv-stress-f3-20261030", "bgv-stress-f3-v1-20261030-r2", "bgv-stress-f3-v1-20261030-r3",
             "bgv-stress-m2-20261030", "bgv-stress-m2-v1-20261030-r2", "bgv-stress-m2-v1-20261030-r3"]:
    result = json.loads((RESULTS / name / "summary.json").read_text())["profiles"][0]
    stress.append({"run": name, "profile": result["profile"], **result["last"]})
assert len(rows) == 5 and len(stress) == 6
assert all(r["single_merge_checks_pass"] for r in rows)
assert all(r["wrong_slots"] > 0 for r in stress)
for name,data in [("measurements.csv",rows),("stress.csv",stress)]:
    with (OUT/name).open("x",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(data[0]),quoting=csv.QUOTE_ALL); w.writeheader();w.writerows(data)
report={"measurements":rows,"stress":stress,
        "conclusion":"C1 arithmetic holds on the normalized/rounded domain; C2 does not hold for all tested incremental histories in two original E3 parameter profiles.",
        "adjustedParameters":"Not executed: Windows Code Integrity rejected the diagnostic v2 binary; no mitigation result.",
        "limits":"Three fresh-key stress runs per failing profile, one fixed synthetic plaintext seed, powers-of-two checkpoints. Other profiles were not exhaustively stress-tested to capacity. No full encrypted protocol integration."}
(OUT/"summary.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"profiles":len(rows),"singleMergeRounds":30,"stressFailures":len(stress),
                  "C1ParameterChecks":10,"output":str(OUT)}))
