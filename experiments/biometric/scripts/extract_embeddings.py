"""Extract face embeddings for every image referenced by LFW View 2.

Pipeline (frozen before scoring):
  * MTCNN from facenet-pytorch 2.6.0, image_size=160, margin=0, post_process=True,
    select_largest=False with selection_method="center_weighted_size", CPU.
  * InceptionResnetV1(pretrained="vggface2"), eval mode, 512-D L2-normalized output.
  * If MTCNN finds no face, fall back to the central 160x160 crop of the 250x250
    LFW image with the same fixed standardization; every fallback is recorded.

Large inputs and outputs live outside Dropbox. Run with the dedicated venv:
  C:\\biobind-data\\venv\\Scripts\\python.exe -I scripts\\extract_embeddings.py ^
      --lfw-root C:\\biobind-data\\lfw\\lfw --out C:\\biobind-data\\embeddings\\inception_vggface2_512.npz
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = ROOT / "data" / "lfw" / "view2_pairs.csv"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lfw-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--torch-home", type=Path, default=Path.home() / ".cache" / "torch")
    args = parser.parse_args()
    os.environ["TORCH_HOME"] = str(args.torch_home)

    import numpy as np
    import torch
    import facenet_pytorch
    from facenet_pytorch import MTCNN, InceptionResnetV1, fixed_image_standardization
    from PIL import Image

    torch.set_num_threads(max(1, os.cpu_count() or 1))
    with PAIRS.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    images = sorted({r["image_left"] for r in rows} | {r["image_right"] for r in rows})

    mtcnn = MTCNN(image_size=160, margin=0, post_process=True, select_largest=False,
                  selection_method="center_weighted_size", device="cpu")
    model = InceptionResnetV1(pretrained="vggface2").eval()
    weight_files = sorted(args.torch_home.rglob("*.pt"))

    names, vectors, fallbacks, missing = [], [], [], []
    t0 = time.perf_counter()
    batch, batch_names = [], []

    def flush() -> None:
        if not batch:
            return
        with torch.no_grad():
            emb = model(torch.stack(batch)).numpy().astype("float32")
        vectors.extend(emb)
        names.extend(batch_names)
        batch.clear()
        batch_names.clear()

    for i, rel in enumerate(images):
        path = args.lfw_root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        img = Image.open(path).convert("RGB")
        face = mtcnn(img)
        if face is None:
            w, h = img.size
            left, top = (w - 160) // 2, (h - 160) // 2
            crop = img.crop((left, top, left + 160, top + 160))
            arr = torch.tensor(np.asarray(crop, dtype=np.float32)).permute(2, 0, 1)
            face = fixed_image_standardization(arr)
            fallbacks.append(rel)
        batch.append(face)
        batch_names.append(rel)
        if len(batch) == 64:
            flush()
        if (i + 1) % 1000 == 0:
            print(f"{i + 1}/{len(images)} images, {time.perf_counter() - t0:.0f}s", flush=True)
    flush()
    if missing:
        raise SystemExit(f"{len(missing)} referenced images are missing, e.g. {missing[:3]}")

    matrix = np.stack(vectors)
    norms = np.linalg.norm(matrix, axis=1)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    np.savez(args.out, names=np.array(names), embeddings=matrix)
    meta = {
        "images": len(names),
        "mtcnnFallbackCount": len(fallbacks),
        "fallbackImages": fallbacks,
        "embeddingDimension": int(matrix.shape[1]),
        "normRange": [float(norms.min()), float(norms.max())],
        "seconds": round(time.perf_counter() - t0, 1),
        "pipeline": {"detector": "facenet_pytorch.MTCNN(image_size=160, margin=0, post_process=True, "
                                 "select_largest=False, selection_method='center_weighted_size')",
                     "fallback": "central 160x160 crop + fixed_image_standardization",
                     "model": "facenet_pytorch.InceptionResnetV1(pretrained='vggface2').eval()"},
        "weights": [{"file": str(p), "sha256": sha256(p), "bytes": p.stat().st_size} for p in weight_files],
        "versions": {"python": sys.version.split()[0], "torch": torch.__version__,
                     "facenet_pytorch": getattr(facenet_pytorch, "__version__", "2.6.0"),
                     "numpy": np.__version__, "platform": platform.platform()},
        "embeddingsFile": str(args.out), "embeddingsSha256": sha256(args.out),
    }
    meta_path = ROOT / "results" / "extraction_inception_vggface2_512.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in meta.items() if k != "fallbackImages"}, indent=2))


if __name__ == "__main__":
    main()
