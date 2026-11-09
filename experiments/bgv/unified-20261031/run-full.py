"""Reproducible unified-profile acceptance sequence; execute only in an allowed environment."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--exe', type=Path, required=True)
ap.add_argument('--out', type=Path, required=True)
ap.add_argument('--scratch', type=Path, required=True)
args = ap.parse_args()
args.out.mkdir(parents=True, exist_ok=False)
args.scratch.mkdir(parents=True, exist_ok=False)
status = {'state': 'running', 'completed': [], 'fullCapacityVerified': False}

def save():
    temp = args.out / 'status.tmp'
    temp.write_text(json.dumps(status, indent=2)+'\n')
    temp.replace(args.out / 'status.json')

def run(name, mode, seed, limit=None):
    cmd = [sys.executable, str(HERE/'run.py'), '--exe', str(args.exe.resolve()),
           '--mode', mode, '--profile', 'Unified512-2', '--parameter-set', 'incremental-candidate',
           '--seed', str(seed), '--out', str((args.out/name).resolve()),
           '--binary-dir', str((args.scratch/name).resolve())]
    if limit is not None:
        cmd += ['--max-enrollments', str(limit)]
    with (args.out/(name+'.log')).open('w') as log:
        subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
    report = json.loads((args.out/name/'summary.json').read_text())
    profile = report['profiles'][0]
    if mode == 'stress':
        assert profile['correctAtAllCheckpoints']
        if limit == 16384:
            assert profile['completedCapacity']
            raw = [json.loads(line) for line in (args.out/name/'Unified512-2/stress.jsonl').read_text().splitlines()]
            assert {8192,8193,16384}.issubset({r['enrollments'] for r in raw})
    else:
        assert profile['allChecksPass']
    return name

save()
try:
    status['completed'].append(run('smoke128', 'stress', 20261031, 128)); save()
    status['completed'].append(run('measure', 'measure', 20261031)); save()
    with ThreadPoolExecutor(max_workers=max(1, min(3, (os.cpu_count() or 4)//4))) as pool:
        pending = [pool.submit(run, f'full-r{i+1}', 'stress', 20261031+i, 16384) for i in range(3)]
        for result in as_completed(pending):
            status['completed'].append(result.result()); save()
    status.update(state='passed', fullCapacityVerified=True)
except BaseException as error:
    status.update(state='failed_or_blocked', error=repr(error))
    raise
finally:
    save()
