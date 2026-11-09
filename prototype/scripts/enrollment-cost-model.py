"""End-to-end enrollment cost: BioZKFHE (published E2/E3 measurements) composed
with the BioBind enrollment source (compact, calldata record) and gateway issuance.

On-chain: BioZKFHE's E2 session = createSession + M x submitOpenedProofWithQAP
+ t confirmations + finalizeSession. In the composition, the BioBind source
replaces session creation, the t confirmation transactions, and finalization
(one batched finalize with t signatures); the M per-block proof submissions are
kept as measured. The integrated contract would also need a coverage counter in
finalize; that cost is not measured and is noted as a caveat.

Committee: per merge, a member needs C_M and C_enroll and hashes C_M, C_enroll,
and C_M + C_enroll. Block sizes come from E3. Hash and addition throughput are
measured here only as proxies (hashlib SHA3-256 and numpy uint64 addition over
buffers of the same size), not as SEAL measurements.

Usage (from prototype/): python -I scripts/enrollment-cost-model.py <BioZKFHE pack root>
"""
import csv
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone

import numpy as np

pack = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
e2 = os.path.join(pack, "source", "TDSC_R1", "experiments", "E2_contract_cost", "processed")
e3 = os.path.join(pack, "source", "TDSC_R1", "experiments", "E3_security_tradeoff", "processed")

fn = {r["function"]: int(r["gas_used"]) for r in csv.DictReader(open(os.path.join(e2, "E2_contract_function_cost.csv"), encoding="utf-8"))}
sessions = list(csv.DictReader(open(os.path.join(e2, "E2_contract_session_cost.csv"), encoding="utf-8")))
seal = [r for r in csv.DictReader(open(os.path.join(e3, "E3_seal_security_performance_raw_derived.csv"), encoding="utf-8")) if r["method"] == "scmv"]
ours = json.load(open(os.path.join(root, "build", "enrollment-source", "result.json"), encoding="utf-8"))["summary"]["compact"]
med = ours["medians"]
issuance_merge = next(r["issuance"] for r in ours["endToEnd"] if not r["append"])

block_bytes = {}
for r in seal:
    key = f'{r["model"]}_n{r["n"]}'
    block_bytes.setdefault(key, int(r["storage_bytes"]) / int(r["M"]))

T = 3  # committee threshold in E2 and in our measurements
rows = []
for s in sessions:
    q = int(s["query_count"])
    M = int(s["M"])
    proof = fn[f"submitOpenedProofWithQAP:q{q}"]
    create, confirm_first, confirm_more, final = (fn["createSession"], fn["submitCommitteeConfirmation:first"],
                                                   fn["submitCommitteeConfirmation:additional"], fn["finalizeSession"])
    biozkfhe = create + M * proof + confirm_first + (T - 1) * confirm_more + final
    assert biozkfhe == int(s["total_gas"]), (s["profile"], s["N"], biozkfhe, s["total_gas"])
    composed_source = med["createSession"] + med["bindRequest"] + M * proof + med["finalizeMerge"]
    rows.append({
        "profile": s["profile"], "N": int(s["N"]), "M": M, "queryCount": q,
        "biozkfheSessionGas": biozkfhe,
        "biozkfheReplacedPart": create + confirm_first + (T - 1) * confirm_more + final,
        "blockProofsGas": M * proof,
        "biobindSourceReplacement": med["createSession"] + med["bindRequest"] + med["finalizeMerge"],
        "composedSourceGas": composed_source,
        "gatewayIssuanceGas": issuance_merge,
        "composedEnrollmentGas": composed_source + issuance_merge,
        "issuanceShare": round(issuance_merge / (composed_source + issuance_merge), 3),
    })

# Throughput proxies on this machine.
def throughput_sha3(nbytes, reps=3):
    buf = os.urandom(nbytes)
    best = min((lambda t0: (hashlib.sha3_256(buf).digest(), time.perf_counter() - t0)[1])(time.perf_counter()) for _ in range(reps))
    return nbytes / best

def throughput_add(nbytes, reps=3):
    a = np.frombuffer(os.urandom(nbytes), dtype=np.uint64).copy()
    b = np.frombuffer(os.urandom(nbytes), dtype=np.uint64).copy()
    q = np.uint64((1 << 60) - 93)
    a %= q
    b %= q
    best = 1e9
    for _ in range(reps):
        t0 = time.perf_counter()
        c = a + b
        np.subtract(c, q, out=c, where=c >= q)
        best = min(best, time.perf_counter() - t0)
    return nbytes / best

probe = 64 * 2**20
sha3_bps = throughput_sha3(probe)
add_bps = throughput_add(probe)

committee = []
for key, bb in block_bytes.items():
    download_no_replica = 2 * bb  # C_M and C_enroll
    download_replica = bb  # C_enroll only, if the member keeps its own gallery replica
    hashed = 3 * bb  # C_M, C_enroll, C_M + C_enroll
    committee.append({
        "profile": key, "blockMiB": round(bb / 2**20, 2), "templatesPerBlock": int(next(r["templates_per_block"] for r in seal if f'{r["model"]}_n{r["n"]}' == key)),
        "downloadPerMergeMiB_noReplica": round(download_no_replica / 2**20, 1),
        "downloadPerMergeMiB_withReplica": round(download_replica / 2**20, 1),
        "hashedPerMergeMiB": round(hashed / 2**20, 1),
        "proxyHashSeconds": round(hashed / sha3_bps, 3),
        "proxyAddSeconds": round(bb / add_bps, 3),
    })

record = {
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "scope": "Composition cost model; BioZKFHE E2 function gas and E3 block sizes (published pack) + BioBind compact source and gateway issuance medians (build/enrollment-source/result.json, t=3).",
    "caveats": [
        "E2 session totals are BioZKFHE's own per-block-extrapolated values (classification MeasuredReceiptPerBlockExtrapolatedSession).",
        "Composed source assumes block-proof submissions are kept unchanged; a coverage counter in the integrated finalize is not measured.",
        "C_enroll is assumed to be one full block in size (pending confirmation, BIOZKFHE_QUESTIONS.md item 10).",
        "Hash and addition times are throughput proxies on this machine, not SEAL measurements; hash function is SHA3-256 via hashlib.",
    ],
    "machine": {"platform": platform.platform(), "python": sys.version.split()[0], "numpy": np.__version__},
    "proxies": {"sha3_256_MiBps": round(sha3_bps / 2**20, 1), "uint64_modadd_MiBps": round(add_bps / 2**20, 1)},
    "inputs": {"biozkfheFunctionGas": fn, "biobindCompactMedians": med, "gatewayIssuanceMerge": issuance_merge},
    "onChain": rows,
    "committee": committee,
}
out = os.path.join(root, "build", "enrollment-cost")
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "result.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(record, f, indent=2)
    f.write("\n")
print(json.dumps({"proxies": record["proxies"], "onChain": rows, "committee": committee}, indent=1))
