"""Run actual SEAL component measurements. Outputs are new directories, never overwritten."""
import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from Crypto.Hash import keccak

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROFILES = [("FaceNet", 1), ("FaceNet", 2), ("FaceNet", 3), ("MobileFaceNet", 1), ("MobileFaceNet", 2)]

def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--binary-dir", type=Path, required=True)
    ap.add_argument("--mode", choices=["measure", "stress"], default="measure")
    ap.add_argument("--profile", choices=[f"{m}-{n}" for m,n in PROFILES])
    ap.add_argument("--max-enrollments", type=int)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    args.binary_dir.mkdir(parents=True, exist_ok=False)
    files = [HERE / "bgv-measure.cpp", HERE / "CMakeLists.txt", HERE / "vendor/scmv_e3_benchmark.cpp", Path(__file__), args.exe]
    manifest = {"startedAt": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
                "python": platform.python_version(), "processor": platform.processor(),
                "logicalCPUs": os.cpu_count(), "mode": args.mode,
                "BioZKFHECommit": "76ffb9f1885a2cbdef3f34c73971fc262db1bd60",
                "SEAL": "official v4.1.2; not the unbuildable bundled fork", "compression": "zstd 1.5.7; zlib off",
                "inputs": [{"name": p.name, "sha256": sha(p), "bytes": p.stat().st_size} for p in files],
                "syntheticData": True, "cryptographicRandomness": "SEAL OS entropy; not fixed",
                "plaintextPRNGSeed": 20261030, "warmups": 1, "measuredRounds": 5 if args.mode == "measure" else None,
                "integration": "component only; no ES signing/PVSC/threshold decryption/chain"}
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    summaries = []
    for model,n in PROFILES:
        name = f"{model}-{n}"
        if args.profile and args.profile != name:
            continue
        binary = args.binary_dir / name
        dest = args.out / name
        dest.mkdir()
        cmd = [str(args.exe.resolve()), args.mode, model, str(n), str(binary.resolve())]
        if args.max_enrollments:
            cmd.append(str(args.max_enrollments))
        print("Running", name, args.mode, flush=True)
        with (dest / "run.log").open("w", encoding="utf-8") as log:
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
        for filename in ["parameters.json", "samples.jsonl", "stress.jsonl"]:
            if (binary / filename).exists():
                (dest / filename).write_bytes((binary / filename).read_bytes())
        raw_name = "samples.jsonl" if args.mode == "measure" else "stress.jsonl"
        samples = [json.loads(s) for s in (dest / raw_name).read_text().splitlines()]
        if args.mode == "stress":
            summary = {"profile": name, "last": samples[-1], "checkpoints": len(samples),
                       "correctAtAllCheckpoints": all(s["wrong_slots"] == 0 and s["wrong_packed_slots"] == 0 for s in samples)}
        else:
            measured = [s for s in samples if not s["warmup"]]
            summary = {"profile": name, "samples": len(measured), "allChecksPass": all(
                s["wrong_slots"] == 0 and s["wrong_packed_slots"] == 0 and s["independent_bytes_equal"] for s in samples)}
            summary["medians"] = {k: statistics.median(s[k] for s in measured) for k in measured[0]
                                  if k.endswith("_ms") or k.endswith("_bytes")}
            summary["medians"]["enroll_total_ms"] = statistics.median(
                sum(s[k] for k in ["enroll_construct_ms", "enroll_encode_ms", "enroll_encrypt_ms"]) for s in measured)
            summary["medians"]["query_encrypt_total_ms"] = statistics.median(
                sum(s[k] for k in ["query_construct_ms", "query_encode_ms", "query_encrypt_ms"]) for s in measured)
            summary["minimumQueryNoiseBits"] = min(s["query_noise"] for s in samples)
            hashes = []
            for filename in ["tail.bin", "enrollment.bin", "merged.bin"]:
                path = binary / filename
                data = path.read_bytes()  # Timed interval excludes disk read.
                times = []
                for i in range(6):
                    start = time.perf_counter()
                    h = keccak.new(digest_bits=256); h.update(data); digest = h.hexdigest()
                    times.append((time.perf_counter()-start)*1000)
                hashes.append({"file": filename, "bytes": len(data), "sha256": sha(path), "keccak256": digest,
                               "keccak_ms_with_warmup": times, "median_keccak_ms": statistics.median(times[1:])})
                del data
            summary["binaryEvidence"] = hashes
            summary["binaryRetention"] = "Full ciphertexts retained in local external binary-dir; hashes portable. No keys exported."
        (dest / "summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
        summaries.append(summary)
        print(json.dumps(summary), flush=True)
    (args.out / "summary.json").write_text(json.dumps({"completedAt": datetime.now(timezone.utc).isoformat(),
        "profiles": summaries}, indent=2)+"\n", encoding="utf-8")

if __name__ == "__main__":
    main()
