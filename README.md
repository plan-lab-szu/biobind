# BioBind: Binding Biometric Deduplication to Zero-Knowledge Authentication

Research artifact for the paper *BioBind: Binding Biometric Deduplication to
Zero-Knowledge Authentication*. Paper: <https://arxiv.org/abs/2611.12636> (arXiv:2611.12636).
Repository: <https://github.com/plan-lab-szu/biobind>.

Authors: Taotao Wang, Xiaoxiao Wu, Shengli Zhang
(College of Electronics and Information Engineering, Shenzhen University).

BioBind connects off-chain biometric enrollment to on-chain credential
issuance and authentication. It states four interface conditions that a 1:N
deduplication backend must meet under malicious enrollees and concurrent
sessions (input binding, authenticated gallery transitions, verdict
linearization, verdict soundness), realizes them for a BGV-based backend
(BioZKFHE) with bound enrollment requests, stale-session rejection and
committee-confirmed gallery-root migration, and links each issued credential
to later capture-bound zero-knowledge authentication.

This repository contains the smart contracts, Circom circuits, evaluation
scripts and tests of the prototype; the face-recognition and BGV component
experiments; and the archived outputs behind every number in the paper.

> **Research prototype, not for deployment.** All Groth16 keys come from
> local single-party benchmark setups and are not included. Capture devices
> are software mocks, the deduplication committee is simulated, and BioZKFHE's
> block proofs and threshold decryption are not executed in the pipeline. See
> [Limitations](#limitations).

## Repository layout

| Path | Contents |
|---|---|
| `prototype/contracts/` | Solidity: enrollment source (reference and compact), finalization adapter, public gateway (`UBCAAuthGateway`), gateway of the unlinkable profile with Poseidon Merkle trees (`PrivateAuthGateway`, `PoseidonMerkleTree`, generated `PoseidonT3`), baselines, generated Groth16 verifiers |
| `prototype/circuits/` | Circom: public-profile distance circuits and the authentication circuits of the unlinkable profile (`auth_private_v2_512_b12_dev20` is the evaluated configuration), attested-matching baseline |
| `prototype/scripts/` | Evaluation scripts (one per experiment, see below) and shared libraries in `scripts/lib/` (enrollment bridge, plaintext model of BioZKFHE's packed gallery, commitments, observer) |
| `prototype/test/` | Node test suite: 10 files, 45 tests |
| `prototype/reference/` | Python reference model of the capture attempt budget |
| `experiments/biometric/` | LFW pipeline: alignment, embedding, quantization, scoring, deduplication calibration ([README](experiments/biometric/README.md)) |
| `experiments/bgv/` | C++ / Microsoft SEAL component experiment for BGV enrollment, merge and query (`unified-20261031-runtime-r3/` is the configuration in the paper) ([README](experiments/bgv/README.md)) |
| `experiments/check-*.py` | Bounded enrollment-state model check; BGV noise-bound arithmetic |
| `results/prototype/` | Archived outputs of the prototype scripts (JSON, logs, reports) |
| `results/experiments/` | Archived outputs of the BGV experiments and their audits |
| `docs/run-register.csv` | Every run ID cited in the paper with its output file; column `repo_path` gives the location in this repository |

## Environment

The paper's measurements were taken on Windows 11 (Intel Core i9-9900T).

| Component | Version |
|---|---|
| Node.js | 24.19.0 |
| Circom | 2.2.3 (compiled with `--O2`) |
| snarkjs / circomlib / circomlibjs | 0.7.6 / 2.0.5 / 0.1.7 |
| solc (npm) / Ganache | 0.8.36, 200 optimizer runs, Shanghai / 7.9.2 |
| Python | 3.12 (biometric: torch 2.2.2 CPU, facenet-pytorch 2.6.0, numpy 1.26.4) |
| BGV | Microsoft SEAL 4.1.2, Zstandard 1.5.7, GCC 16.2.0 (w64devkit), CMake |

## Quick start

On Windows, `prototype/toolchain.ps1` downloads the pinned Node.js and Circom
into `prototype/.toolchain/` (both digest-checked) and installs the npm
dependencies:

```powershell
cd prototype
powershell -ExecutionPolicy Bypass -File .\toolchain.ps1
```

On other systems, install Node.js 24 and Circom 2.2.3, then run `npm ci` in
`prototype/`.

Run the test suite (each file separately; passing a directory to `node --test`
does not pick up the files on all platforms):

```bash
cd prototype
for f in test/*.test.mjs; do node --test "$f"; done
```

From a fresh checkout, 44 of the 45 tests pass. `pinned-policy-profile.test.mjs`
also needs the compiled 128-dimensional circuit and its benchmark keys in
`prototype/build/auth_distance_128/`; create them first with
`prove-benchmark.ps1` (which also creates the Powers of Tau file below).
A warning that `uws_win32_x64_*.node` is missing comes from an optional
Ganache dependency and does not affect the tests.

Circuit setups need a local Powers of Tau file. The scripts expect
`prototype/build/proving/local-benchmark-setup/pot15_final.ptau` (and
`pot16_final.ptau` for the 2^16-constraint circuits). `prove-benchmark.ps1`
creates the 2^15 file; equivalently:

```bash
cd prototype
mkdir -p build/proving/local-benchmark-setup && cd build/proving/local-benchmark-setup
npx snarkjs powersoftau new bn128 15 pot15_0000.ptau
npx snarkjs powersoftau contribute pot15_0000.ptau pot15_0001.ptau --name=local -e="local benchmark entropy"
npx snarkjs powersoftau prepare phase2 pot15_0001.ptau pot15_final.ptau
# repeat with 16 for pot16_final.ptau
```

These single-party files are for benchmarking only.

## From paper to code

Run each script from `prototype/` with `node scripts/<name>`. Outputs are
written to `prototype/build/<folder>/`; the archived copies used in the paper
are under `results/prototype/<folder>/`. Run IDs refer to
`docs/run-register.csv`.

| Paper item | Script | Archived output | Run ID |
|---|---|---|---|
| Counterexamples E1–E3 (provenance, capture, live state) | `provenance-security-evaluation.mjs` | `provenance-evaluation/` | R-PROV-20261028 |
| Counterexamples A1–A3 on the plaintext model of BioZKFHE's packed gallery | `enrollment-bridge-evaluation.mjs` | `enrollment-bridge/` | R-BRIDGE-20261025 |
| Snapshot race A3′ | `a3prime-snapshot-race.mjs` | `a3prime/` | R-A3P-20261027 |
| Dropped merge / gallery-root migration | `gallery-root-migration.mjs` | `gallery-root-migration/` | R-ROOTMIG-20261027 |
| Enrollment source: negative controls and gas | `enrollment-source-evaluation.mjs` | `enrollment-source/`, `enrollment-source-20261031/` | R-ENRSRC2-20261027, R-CALLDATA-20261027, R-SOURCE-20261031 |
| Gateway of the unlinkable profile: controls and gas | `private-gateway-evaluation.mjs` | `private-gateway/`, `private-gateway-20261030/` | R-PRIVGW2-20261027, R-PRIVGW-20261030 |
| Circuit of the unlinkable profile: constraints and proving time | `auth-private-v2-benchmark.mjs`, `prove-timing-interleaved.mjs` | `auth-private-v2/` | R-PRIVV2-20261028, R-PROVETIME-20261028 |
| End-to-end run with real LFW features, public-observer audit | `private-e2e-lfw512-v2.mjs` | `private-e2e-lfw512-v2/`, `private-observer-20261030/` | R-PRIVE2EV2TAU-20261028, R-PRIVOBS-20261030 |
| Equal-public-field signature baseline | `setup-private-attested.mjs`, `private-baseline-timing.mjs` | `private-attested-20261030/`, `private-baseline-timing-20261030/` | R-PRIVATT-20261030, R-PRIVTIME-20261030 |
| Public-profile signature baselines | `strong-baseline-evaluation.mjs` | `strong-baseline-20261030/` | R-BASE-20261030 |
| Generated PoseidonT3 vs. circomlibjs | `gen-poseidon-t3.mjs`, `poseidon-t3-check.mjs` | `poseidon-t3/` | R-POSEIDONT3-20261027 |
| Composed enrollment cost with BioZKFHE | `enrollment-cost-model.py` (needs BioZKFHE's published E2/E3 data) | `enrollment-cost/` | R-COST-20261027 |
| LFW accuracy, ROC, quantization | `experiments/biometric/` | `experiments/biometric/results/` | R-LFW-20261027 |
| Deduplication threshold calibration | `experiments/biometric/scripts/dedup_calibration.py` | `experiments/biometric/results/dedup_calibration.json` | R-DEDUP-20261028 |
| Evasive re-enrollment on Bosphorus (2D images; licensed data not included) | `experiments/biometric/scripts/extract_bosphorus.py`, `bosphorus_evasion.py`, `make_bosphorus_tables.py` | `experiments/biometric/results/bosphorus_evasion.json`, `extraction_bosphorus.json` | R-BOSPHORUS-20261109 |
| BGV components and three 16,384-registration histories | `experiments/bgv/unified-20261031-runtime-r3/` | `results/experiments/bgv-unified-20261031-runtime-r3*/` | R-BGV-RUNTIME-R3-* |
| Controls with BioZKFHE's original parameter sets (its experiment E3) | `experiments/bgv/run.py` | `results/experiments/bgv-measure-20261030/`, `bgv-repair-r3-*` | R-BGV-20261030, R-BGVFIX-* |
| Bounded enrollment-state model | `experiments/check-enrollment-model.py` | `results/experiments/enrollment-model-20261031.json` | R-MODEL-20261031 |

The 512-dimensional circuit benchmarks and the end-to-end run read LFW demo
vectors exported by `experiments/biometric/scripts/export_demo_vectors.py`;
pass the file path as the first argument.

## Limitations

- Groth16 setups are local and single-party; keys are not provided and must
  not be deployed.
- The enrollment station and authentication capture module are software
  implementations with software keys; nothing here demonstrates sensor
  provenance, presentation-attack detection or a tamper-resistant attempt
  budget.
- The deduplication committee is simulated over a plaintext model of BioZKFHE's packed gallery and
  transparent stand-in ciphertexts. Real BGV components are measured
  separately in `experiments/bgv/` and are not integrated into the pipeline.
  BioZKFHE's block proofs, the check that every block is proved, and
  threshold decryption are not executed; gas figures exclude them.
- Every gas figure is a single local Ganache run; timings come from one
  machine.
- The face-recognition evaluation uses one public model on LFW and cannot
  support low-FAR or adversarial claims. The Bosphorus run adds cooperative
  evasion attempts (occlusion, expression, pose) by 98 subjects; it gives
  empirical miss rates, not an adversary's bound. Its false-duplicate control
  is far above the LFW calibration at the loosest thresholds, so only the
  stricter operating points are meaningful.
- Archived outputs record the folder names of the development workspace (for example `prototype/route-a/build/...` and
  `dev-workspace/experiments/...`). `docs/run-register.csv` maps them to this
  repository. Some READMEs under `experiments/bgv/` link to internal design
  notes that are not part of this release.
- The paper avoids BioZKFHE's internal names. Code identifiers, file names and
  archived reports still use them: SCMV denotes BioZKFHE's packed gallery
  encoding, PVSC its block proofs, and "private" (as in `PrivateAuthGateway`)
  the unlinkable profile.

## Third-party code

`experiments/bgv/vendor/scmv_e3_benchmark.cpp` is copied from the BioZKFHE
artifact (commit `76ffb9f`) to fix the E3 parameter and layout source.
Microsoft SEAL and Zstandard are fetched and built separately; see
`experiments/bgv/README.md` and `seal-mingw-build.patch`.

## License

[MIT](LICENSE). The license covers the code and the result files in this
repository. It does not cover third-party material: the LFW images and the
VGGFace2-trained model weights that the biometric scripts download are
subject to their own terms, the Bosphorus database (obtained from Boğaziçi
University under its own use agreement and not redistributed here; its seven
subjects flagged as unpublishable are excluded from the run) is likewise not
covered, and `experiments/bgv/vendor/` holds a file taken
from the BioZKFHE artifact (see above).

## Citation

If you use this artifact, please cite the paper:

```bibtex
@misc{wang2026biobind,
  title         = {{BioBind}: Binding Biometric Deduplication to Zero-Knowledge Authentication},
  author        = {Wang, Taotao and Wu, Xiaoxiao and Zhang, Shengli},
  year          = {2026},
  eprint        = {2611.12636},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2611.12636}
}
```
