"""Fetch the official LFW View 2 annotation mirror with a pinned digest."""

from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.request import urlopen


URL = "https://ndownloader.figshare.com/files/5976006"
SHA256 = "ea42330c62c92989f9d7c03237ed5d591365e89b3e649747777b70e692dc1592"
DEST = Path(__file__).resolve().parents[1] / "data" / "lfw" / "pairs.txt"


def main() -> None:
    if DEST.exists():
        data = DEST.read_bytes()
        source = "cached"
    else:
        with urlopen(URL, timeout=30) as response:
            data = response.read()
        source = URL
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError(f"SHA-256 mismatch for {source}: {digest}")
    if not DEST.exists():
        DEST.parent.mkdir(parents=True, exist_ok=True)
        DEST.write_bytes(data)
    print(f"{DEST}: {len(data)} bytes, sha256={digest}, source={source}")


if __name__ == "__main__":
    main()
