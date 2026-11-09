"""Extract face embeddings for the Bosphorus 2D images (run R-BOSPHORUS-20261109).

Protocol frozen before running (notes/bosphorus-protocol-draft-20261109.md):
  * Same detector and model as extract_embeddings.py: facenet-pytorch MTCNN
    (image_size=160, margin=0, post_process=True, select_largest=False,
    selection_method="center_weighted_size", CPU) and InceptionResnetV1 pretrained
    on VGGFace2, 512-D, L2-normalized.
  * No central-crop fallback: a failed detection is recorded as a detection failure
    and reported separately by bosphorus_evasion.py.
  * The seven subjects whose images may not be published (unallowed_subjects.txt) are
    excluded entirely: their images are not read. Category IGN_INV is skipped.

Inputs and outputs stay outside Dropbox:
  C:\\biobind-data\\venv\\Scripts\\python.exe -I scripts\\extract_bosphorus.py ^
      --root F:\\data-store\\bosphorus-2d\\BosphorusDB --out F:\\data-store\\bosphorus-results\\bosphorus_embeddings.npz
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"^(bs\d{3})_(.+)_(\d+)\.png$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--torch-home", type=Path, default=Path("C:/biobind-data/torch"))
    args = parser.parse_args()
    os.environ["TORCH_HOME"] = str(args.torch_home)

    import numpy as np
    import torch
    import facenet_pytorch
    from facenet_pytorch import MTCNN, InceptionResnetV1
    from PIL import Image

    unallowed = {ln.strip() for ln in (args.root / "unallowed_subjects.txt").read_text().splitlines()
                 if re.fullmatch(r"bs\d{3}", ln.strip())}
    if len(unallowed) != 7:
        raise SystemExit(f"expected 7 unallowed subjects, found {len(unallowed)}")

    items = []
    for sub in sorted(p.name for p in args.root.iterdir() if p.is_dir()):
        if sub in unallowed:
            continue
        for f in sorted((args.root / sub).glob("*.png")):
            m = NAME.match(f.name)
            if not m:
                raise SystemExit(f"unexpected file name {f.name}")
            if m.group(2) == "IGN_INV":
                continue
            items.append((f, m.group(1), m.group(2), int(m.group(3))))
    print(f"{len(items)} images from {len({i[1] for i in items})} subjects", flush=True)

    torch.set_num_threads(max(1, os.cpu_count() or 1))
    mtcnn = MTCNN(image_size=160, margin=0, post_process=True, select_largest=False,
                  selection_method="center_weighted_size", device="cpu")
    model = InceptionResnetV1(pretrained="vggface2").eval()
    weight_files = sorted(args.torch_home.rglob("*.pt"))

    names, subjects, cats, samples, vectors, failures = [], [], [], [], [], []
    batch, batch_meta = [], []
    t0 = time.perf_counter()

    def flush() -> None:
        if not batch:
            return
        with torch.no_grad():
            emb = model(torch.stack(batch)).numpy().astype("float32")
        for e, (n, s, c, k) in zip(emb, batch_meta):
            vectors.append(e); names.append(n); subjects.append(s); cats.append(c); samples.append(k)
        batch.clear(); batch_meta.clear()

    for i, (path, sub, cat, k) in enumerate(items):
        face = mtcnn(Image.open(path).convert("RGB"))
        if face is None:
            failures.append(path.name)
        else:
            batch.append(face)
            batch_meta.append((path.name, sub, cat, k))
        if len(batch) == 64:
            flush()
        if (i + 1) % 100 == 0:
            print(f"{i + 1}/{len(items)} images, {len(failures)} failures, {time.perf_counter() - t0:.0f}s", flush=True)
    flush()

    matrix = np.stack(vectors)
    norms = np.linalg.norm(matrix, axis=1)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    np.savez(args.out, names=np.array(names), subjects=np.array(subjects), categories=np.array(cats),
             samples=np.array(samples), embeddings=matrix)
    meta = {
        "images": len(items), "embedded": len(names), "detectionFailures": len(failures),
        "failedByCategory": dict(sorted(collections.Counter(re.match(r"^bs\d{3}_(.+)_\d+\.png$", f).group(1) for f in failures).items())),
        "subjects": len({i[1] for i in items}),
        "excludedUnpublishableSubjects": sorted(unallowed),
        "embeddingDimension": int(matrix.shape[1]), "normRange": [float(norms.min()), float(norms.max())],
        "seconds": round(time.perf_counter() - t0, 1),
        "pipeline": {"detector": "facenet_pytorch.MTCNN(image_size=160, margin=0, post_process=True, "
                                 "select_largest=False, selection_method='center_weighted_size')",
                     "fallback": "none; detection failures are recorded",
                     "model": "facenet_pytorch.InceptionResnetV1(pretrained='vggface2').eval()"},
        "weights": [{"file": str(p), "sha256": sha256(p), "bytes": p.stat().st_size} for p in weight_files],
        "versions": {"python": sys.version.split()[0], "torch": torch.__version__,
                     "facenet_pytorch": getattr(facenet_pytorch, "__version__", "2.6.0"),
                     "numpy": np.__version__},
        "embeddingsFile": str(args.out), "embeddingsSha256": sha256(args.out),
    }
    # Per-image failure names carry subject IDs: keep them next to the embeddings, outside the repository.
    failures_path = args.out.with_suffix(".failures.json")
    failures_path.write_text(json.dumps({"failedImages": failures}, indent=2) + "\n", encoding="utf-8")
    meta_path = ROOT / "results" / "extraction_bosphorus.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
