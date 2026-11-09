"""Export real LFW feature vectors for the 512-D private-circuit demos.

Selection rule (fixed, deterministic; this is a demonstration, not an accuracy
estimate -- accuracy comes from the View 2 protocol in score_and_analyze.py):
  * candidates are identities with >= 3 images among the extracted View 2 images;
  * person A: alphabetically first candidate whose three first images have all
    pairwise cosine similarities >= 0.6 (enrollment, probe, re-enrollment);
  * person B: next candidate with the same property and cosine < 0.2 to A's images.
Quantization reuses score_and_analyze.quantize (L2-normalize, x Gamma, round half
away from zero) and stores, per coordinate width, the offset unsigned values
expected by the circuit: 16-bit Gamma=512 (BioZKFHE rule) offset 32768,
12-bit Gamma=2047 offset 2048, 8-bit Gamma=127 offset 128.

Usage: python -I scripts/export_demo_vectors.py <embeddings.npz> <out.json>
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from score_and_analyze import quantize  # noqa: E402

PROFILES = {"b16": (512, 32768), "b12": (2047, 2048), "b8": (127, 128)}


def main() -> None:
    data = np.load(sys.argv[1])
    names = data["names"].tolist()
    emb = data["embeddings"].astype(np.float64)
    emb /= np.linalg.norm(emb, axis=1, keepdims=True)
    by_person = defaultdict(list)
    for i, n in enumerate(names):
        by_person[n.split("/")[0]].append(i)
    candidates = []
    for person in sorted(by_person):
        idx = sorted(by_person[person], key=lambda i: names[i])[:3]
        if len(idx) < 3:
            continue
        sims = emb[idx] @ emb[idx].T
        if sims[np.triu_indices(3, 1)].min() >= 0.6:
            candidates.append((person, idx))
    person_a, idx_a = candidates[0]
    person_b, idx_b = next((p, i) for p, i in candidates[1:] if (emb[i] @ emb[idx_a].T).max() < 0.2)

    roles = {"A_enroll": idx_a[0], "A_probe": idx_a[1], "A_reenroll": idx_a[2], "B_enroll": idx_b[0], "B_probe": idx_b[1]}
    out = {"selection": {"personA": person_a, "personB": person_b,
                         "images": {r: names[i] for r, i in roles.items()},
                         "cosine": {"A_enroll~A_probe": float(emb[idx_a[0]] @ emb[idx_a[1]]),
                                    "A_enroll~A_reenroll": float(emb[idx_a[0]] @ emb[idx_a[2]]),
                                    "A_enroll~B_probe": float(emb[idx_a[0]] @ emb[idx_b[1]]),
                                    "B_enroll~B_probe": float(emb[idx_b[0]] @ emb[idx_b[1]])},
                         "rule": __doc__.split("Quantization")[0].strip()},
           "profiles": {}}
    rows = np.array(list(roles.values()))
    for key, (gamma, offset) in PROFILES.items():
        q = quantize(emb[rows], gamma)
        out["profiles"][key] = {"gamma": gamma, "offset": offset,
                                "signed": {r: q[k].tolist() for k, r in enumerate(roles)},
                                "unsigned": {r: (q[k] + offset).tolist() for k, r in enumerate(roles)}}
    Path(sys.argv[2]).write_text(json.dumps(out) + "\n", encoding="utf-8")
    print(json.dumps(out["selection"], indent=1))


if __name__ == "__main__":
    main()
