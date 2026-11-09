# Completed capacity evidence, 2026-10-31

Start with `dev-workspace/notes/bgv-full-capacity-20261031.md` in the extracted package.

The original runtime-r3 results are immutable. `audit.json` records a separate consistency audit; `checkpoints.csv` includes 8 smoke and 48 full-capacity checkpoints. Build evidence contains copies whose hashes match the original runtime build record. Three large measurement ciphertexts remain in the external scratch directory recorded in the launch JSON; their SHA-256 and Keccak-256 hashes were rechecked. No keys are exported.

This package preserves project-relative paths. Verify PACKAGE_SHA256.csv against the extracted files using Python hashlib. The external project manifest additionally hashes the ZIP itself. The package is for reading and source review, not a dependency-free Windows binary distribution.

The manuscript is intentionally absent and unchanged. Finite component tests and source-bound arithmetic are not independent mathematical review or full PVSC/threshold-decryption/chain integration. Historical blocked/running labels in frozen source metadata are superseded by the completed status and separate audit, never rewritten.
