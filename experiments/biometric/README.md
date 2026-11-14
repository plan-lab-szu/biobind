# Biometric experiments (LFW and Bosphorus)

This folder reproduces LFW View 2 accuracy under quantization, 1:N
deduplication threshold calibration, and the Bosphorus appearance-change
evaluation. See the root README and `docs/run-register.csv` for run IDs.
Table and figure numbers differ between manuscript versions. Face images,
model weights, embeddings and exported demo vectors are not included.

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

## Bosphorus appearance changes and re-enrollment

The Bosphorus database is not included. Obtain access from Boğaziçi
University under its usage terms and keep images and derived per-probe
records outside this repository. The gallery uses the first neutral image
of each of 98 subjects; the seven excluded subjects are skipped before
image loading. Every other image is a probe, with fixed LFW-calibrated
thresholds and no retuning. These are controlled appearance changes, not
an adaptive attack evaluation or a deployed station acceptance gate.

Generate inputs with the original extraction/scoring pipeline (Python 3.11
for the archived Bosphorus extraction):

```bash
python -I scripts/extract_bosphorus.py --root <BosphorusDB> --out <external-dir>/bosphorus_embeddings.npz
python -I scripts/bosphorus_evasion.py --embeddings <external-dir>/bosphorus_embeddings.npz --scores-out <external-dir>/bosphorus_scores.csv
```

The historical `results/bosphorus_evasion.json` and
`results/extraction_bosphorus.json` are unchanged. The old combined metric
counts a detection failure as a miss; it must not be interpreted as a
successful uniqueness verdict or credential issuance. The following command
reproduces the historical tables used in arXiv v1:

```bash
python -I scripts/make_bosphorus_tables.py --out-dir tables/historical
```

### Reanalysis of 14 November 2026

`results/bosphorus_reanalysis_20261114.json` separates detection failures
from matching misses and reports 95% subject-cluster bootstrap intervals.
In the original candidate attended-capture grouping, 3,273 probes include
26 detection failures and 3,247 detected probes. At the LFW per-pair FMR
calibration target of 10^-4, 32 detected probes miss the gallery:
32/3,247 = 0.99% (95% interval 0.57–1.47%). At 10^-5 the count is
125/3,247 = 3.85% (2.85–4.93%). If every detection failure rejects, the
corresponding offline candidate-acceptance fractions are 32/3,273 and
125/3,273; these are not measurements of issued duplicate credentials.

With the licensed per-probe inputs available locally, reproduce the full
reanalysis using NumPy 2.5.1 (the version recorded with this run):

```bash
python -I scripts/reanalyze_bosphorus.py --scores <external-dir>/bosphorus_scores.csv --failures <external-dir>/bosphorus_embeddings.failures.json --out <external-dir>/bosphorus_reanalysis_check.json
```

The defaults use 20,000 resamples of 98 whole subjects, NumPy PCG64 seed
20261114, pooled-count ratios and linear percentile quantiles. The gallery
and thresholds are held fixed. Zero-event intervals are omitted rather
than presented as zero-risk bounds. The output records input and script
SHA-256 hashes and the NumPy version; no per-subject identifiers are
published in the reanalysis output.

Without licensed inputs, reproduce the separated counts and rates from
the public historical aggregates, or render the current table from the
published reanalysis JSON:

```bash
python -I scripts/reanalyze_bosphorus.py --out <external-dir>/bosphorus_counts_only.json
python -I scripts/make_bosphorus_reanalysis_table.py
```

The first command cannot recover subject-cluster intervals from aggregate
counts alone; use a separate output path so it does not replace the full
archived result. The second needs no licensed inputs and writes
`tables/bosphorus-full.tex` with black text, including the published cluster
intervals. Historical tables are kept separate from this revised table.

## Limits

The evaluation uses one public face model on LFW and Bosphorus. LFW has
3,000 impostor pairs and does not establish performance at very low FAR.
Bosphorus estimates are conditional on a fixed gallery, thresholds and
finite, unequal sets of available probes. They do not estimate the
worst-case conditional biometric errors in the security argument or
validate capture provenance, liveness detection or attempt-budget controls.
