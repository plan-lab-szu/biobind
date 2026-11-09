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
PROFILES = [("Unified512", 2)]

def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", type=Path, required=True)
    ap.add_argument("--source-dir", type=Path, default=HERE, help="C++ source snapshot matching the executable")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--binary-dir", type=Path, required=True)
    ap.add_argument("--mode", choices=["measure", "stress"], default="measure")
    ap.add_argument("--profile", choices=[f"{m}-{n}" for m,n in PROFILES])
    ap.add_argument("--max-enrollments", type=int)
    ap.add_argument("--coeff-bits", help="Diagnostic override, e.g. 50,45,45,50; NOT original E3")
    ap.add_argument("--parameter-set", choices=["original", "incremental-candidate"], default="original")
    ap.add_argument("--seed", type=int, default=20261031)
    args = ap.parse_args()
    if args.parameter_set != "incremental-candidate":
        ap.error("Unified512 requires --parameter-set incremental-candidate")
    if args.parameter_set == "incremental-candidate":
        if args.coeff_bits:
            ap.error("choose --parameter-set or --coeff-bits, not both")
        # 210 key bits, 160 data bits at N=8192; SEAL tc128 remains mandatory.
        # This is a candidate, not a certified correctness bound.
        args.coeff_bits = "60,50,50,50"
    if args.max_enrollments is not None and args.max_enrollments <= 0:
        ap.error("--max-enrollments must be positive")
    args.out.mkdir(parents=True, exist_ok=False)
    args.binary_dir.mkdir(parents=True, exist_ok=False)
    files = [args.source_dir / "bgv-measure.cpp", args.source_dir / "CMakeLists.txt", HERE / "vendor/scmv_e3_benchmark.cpp", Path(__file__), args.exe]
    build_record = HERE / "runtime-build.json"
    if build_record.exists():
        files.append(build_record)
    manifest = {"startedAt": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
                "python": platform.python_version(), "processor": platform.processor(),
                "logicalCPUs": os.cpu_count(), "mode": args.mode,
                "BioZKFHECommit": "76ffb9f1885a2cbdef3f34c73971fc262db1bd60",
                "SEAL": "official v4.1.2; SEAL_USE_CXX17=OFF selects stock atomic locks", "compression": "zstd 1.5.7; zlib off",
                "inputs": [{"name": p.name, "sha256": sha(p), "bytes": p.stat().st_size} for p in files],
                "syntheticData": True, "cryptographicRandomness": "SEAL OS entropy; not fixed",
                "plaintextPRNGSeed": args.seed, "warmups": 1, "measuredRounds": 5 if args.mode == "measure" else None,
                "integration": "component only; no ES signing/PVSC/threshold decryption/chain",
                "coeffBitsOverride": args.coeff_bits, "parameterSet": args.parameter_set,
                "maxEnrollments": args.max_enrollments}
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    summaries = []
    correctness_failed = False
    for model,n in PROFILES:
        name = f"{model}-{n}"
        if args.profile and args.profile != name:
            continue
        binary = args.binary_dir / name
        dest = args.out / name
        dest.mkdir()
        cmd = [str(args.exe.resolve()), args.mode, model, str(n), str(binary.resolve())]
        if args.max_enrollments or args.coeff_bits:
            cmd.append(str(args.max_enrollments or n*8192))
        if args.coeff_bits:
            cmd.append(args.coeff_bits)
        cmd.append(str(args.seed))
        print("Running", name, args.mode, flush=True)
        watchdog_failed = False
        with (dest / "run.log").open("w", encoding="utf-8") as log:
            child = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
            last_size = 0
            last_progress = time.monotonic()
            while child.poll() is None:
                progress_file = binary / ("progress.jsonl" if args.mode == "stress" else "samples.jsonl")
                # Windows directory metadata may lag writes to an open stream.
                size = len(progress_file.read_bytes()) if progress_file.exists() else 0
                if size != last_size:
                    last_size = size
                    last_progress = time.monotonic()
                if time.monotonic() - last_progress > 900:
                    (dest / "watchdog.json").write_text(json.dumps({"reason": "no new progress for 900 seconds", "pid": child.pid})+"\n")
                    child.kill()
                    watchdog_failed = True
                    break
                time.sleep(5)
            returncode = child.wait()
        for filename in ["parameters.json", "samples.jsonl", "stress.jsonl", "progress.jsonl"]:
            if (binary / filename).exists():
                (dest / filename).write_bytes((binary / filename).read_bytes())
        if watchdog_failed:
            raise RuntimeError("runtime watchdog stopped a stalled child; raw evidence preserved")
        if returncode not in (0, 2):
            raise subprocess.CalledProcessError(returncode, cmd)
        correctness_failed |= returncode == 2
        raw_name = "samples.jsonl" if args.mode == "measure" else "stress.jsonl"
        samples = [json.loads(s) for s in (dest / raw_name).read_text().splitlines()]
        if args.mode == "stress":
            summary = {"profile": name, "last": samples[-1], "checkpoints": len(samples),
                       "correctAtAllCheckpoints": all(all(s.get(k,0) == 0 for k in
                           ["wrong_slots", "wrong_packed_slots", "wrong_row_slots", "fresh_wrong_slots", "fresh_wrong_packed_slots"])
                           for s in samples),
                       "completedCapacity": samples[-1]["enrollments"] == n*8192,
                       "processReturnCode": returncode}
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
    raise SystemExit(2 if correctness_failed or any(
        not s.get("correctAtAllCheckpoints", s.get("allChecksPass", False)) for s in summaries) else 0)

if __name__ == "__main__":
    main()
