"""Record the local software budget controls with source fingerprints."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROUTE_ROOT = HERE.parent
OUTPUT = ROUTE_ROOT / "build" / "budget-reference" / "results.json"
SOURCES = (
    "attempt_budget.py", "budgeted_capture.py",
    "test_attempt_budget.py", "test_budgeted_capture.py",
)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        ("test_attempt_budget", "test_budgeted_capture")
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    record = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "scope": "local SQLite and HMAC software reference; no protected device or EVM signer",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "testsRun": result.testsRun,
        "failures": [str(test) for test, _ in result.failures],
        "errors": [str(test) for test, _ in result.errors],
        "passed": result.wasSuccessful(),
        "sourceSha256": {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in SOURCES
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
