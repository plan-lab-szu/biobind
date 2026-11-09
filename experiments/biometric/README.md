# Biometric experiments (LFW)

This folder reproduces the face-recognition numbers in the paper: LFW View 2
accuracy under quantization (paper Table XI and the ROC figure) and the 1:N
deduplication threshold calibration (paper Table XII and the deduplication
figure). Face images, model weights, embeddings and the exported demo vectors
are **not** included; the scripts regenerate them from public sources.

## Data and model

| Item | Source | Pinned value |
|---|---|---|
| LFW images | `lfw.tgz`, <https://ndownloader.figshare.com/files/5976018> (scikit-learn mirror) | SHA-256 `055f7d9c632d7370e6fb4afc7468d40f970c34a80d4c6f50ffec63f5a8d536c0` |
| LFW View 2 annotations | `pairs.txt`, <https://ndownloader.figshare.com/files/5976006> | SHA-256 `ea42330c…dc1592` (checked by `fetch_lfw_pairs.py`) |
| Alignment | MTCNN, facenet-pytorch 2.6.0, `image_size=160, margin=0` | 0 fallbacks on the 7,701 View 2 images |
| Model | InceptionResnetV1 pretrained on VGGFace2 (facenet-pytorch), 512-D, L2-normalized | weight hash in `manifest.json` |

Check the terms of use of LFW and of the VGGFace2-trained weights (research,
non-commercial) before use. `data/lfw/` contains only the public View 2
annotation file and its parsed form.

Environment used for the paper: Python 3.12, torch 2.2.2 (CPU),
facenet-pytorch 2.6.0, numpy 1.26.4, scipy. Keep images, weights and
embeddings outside the repository.

## Pipeline

Run from this folder:

```bash
python scripts/fetch_lfw_pairs.py            # data/lfw/pairs.txt (digest-checked)
python scripts/parse_lfw_pairs.py            # data/lfw/view2_pairs.csv, 10 fixed folds
python -I scripts/extract_embeddings.py --lfw-root <lfw-dir> --out <emb.npz> [--torch-home <dir>]
python -I scripts/score_and_analyze.py <emb.npz>      # results/scores_*.csv, lfw_view2_*.json
python -I scripts/dedup_calibration.py <emb.npz>      # results/dedup_calibration.json
python -I scripts/export_demo_vectors.py <emb.npz> <demo_vectors.json>   # input to the 512-D circuit demos
python -m unittest discover -s tests -v       # protocol and leakage checks of the scorer
```

Thresholds for the 1:1 protocol are chosen on the other nine folds and
errors are counted only on the held-out fold. The deduplication calibration
splits identities into a calibration half and a test half by a hash of the
name and selects thresholds on the calibration half only. Each script's
docstring states its frozen protocol.

`results/` holds the outputs reported in the paper (run IDs `R-LFW-20261027`
and `R-DEDUP-20261028` in `docs/run-register.csv`). Per-pair squared distances
are included; they are derived from public LFW pairs and contain no images or
embeddings.

## Bosphorus evasive re-enrollment

The Bosphorus database (2D images only) is not included and must be obtained
from Boğaziçi University. With the images extracted outside the repository:

```bash
python -I scripts/extract_bosphorus.py --root <BosphorusDB> --out <emb.npz>
python -I scripts/bosphorus_evasion.py --embeddings <emb.npz> --scores-out <scores.csv>
python -I scripts/make_bosphorus_tables.py --out-dir tables
```

The last command needs no licensed data: it regenerates the paper's full
Bosphorus table (`bosphorus-full.tex`) and the compact table of the arXiv
version (`bosphorus-compact.tex`) from `results/bosphorus_evasion.json`, and
its output is byte-identical to the tables in the manuscript.

The protocol is frozen in the docstrings of both scripts: the gallery holds each
subject's first neutral image, every other image of that subject is a probe,
thresholds come from `results/dedup_calibration.json` (LFW), and detection
failures count as missed duplicates. The seven subjects listed in the
database's `unallowed_subjects.txt` are skipped before any image is read. The
per-probe score file and the per-image list of failed detections contain
subject identifiers and are not part of this repository (`extract_bosphorus.py`
writes the list next to the embeddings, `bosphorus_evasion.py` reads it from
there); `results/extraction_bosphorus.json` gives the failure counts by
condition and `results/bosphorus_evasion.json` holds the aggregates (run ID
`R-BOSPHORUS-20261109`).

## Limits

LFW has 3,000 impostor pairs, so it supports no low-FAR claim. Only one public
model and one dataset were evaluated. The deduplication rates are
non-adversarial reference values, not the adversarial miss probability used
in the paper's security bound.
