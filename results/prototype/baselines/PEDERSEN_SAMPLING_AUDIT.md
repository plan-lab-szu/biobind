# Legacy Pedersen sampling baseline audit

Generated: 2026-09-08T09:43:58.491Z

## Scope

This is a reproducible audit of the exact without-replacement sampling formula and a transcription of the old manuscript's reported gas. It is **not** a new Pedersen contract measurement. Gas ratios are orientation only until both designs run in the same harness.

## 128-dimensional audit

The near-5% case is six bad coordinates (4.6875%), matching the old table's lambda=1 and lambda=8 values.

| lambda | samples | one bad: exact detection | six bad: exact detection | old table "5%" | reported spot gas | reported spot + Groth16 gas |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 7 | 5.47% | 29.14% | 29.14% | 701,400 | 972,600 |
| 2 | 14 | 10.94% | 50.83% | 49.79% | 981,900 | 1,253,100 |
| 4 | 28 | 21.88% | 78.02% | 74.79% | 1,568,200 | 1,839,400 |
| 8 | 56 | 43.75% | 97.12% | 97.12% | 2,874,200 | 3,145,400 |

The old table's lambda=2 and lambda=4 "5%" entries do not equal the stated exact hypergeometric formula: recomputation gives 50.83% and 78.02%, rather than 49.79% and 74.79%. The lambda=1 and lambda=8 entries do match six bad coordinates.

For one corrupted coordinate, detection is exactly t/N. At N=128, 95%, 99%, and deterministic detection require 122, 127, and 128 sampled coordinates respectively.

## 512-dimensional soundness projection

This table projects sampling probability only; it does not extrapolate gas.

| lambda | samples | coordinate coverage | one bad: detection | 26 bad: detection |
|---:|---:|---:|---:|---:|
| 1 | 9 | 1.76% | 1.76% | 37.68% |
| 2 | 18 | 3.52% | 3.52% | 61.50% |
| 4 | 36 | 7.03% | 7.03% | 85.71% |
| 8 | 72 | 14.06% | 14.06% | 98.25% |

At N=512, 95%, 99%, and deterministic detection of one corrupted coordinate require 487, 507, and 512 samples respectively.

## Same-harness BN254 Pedersen kernel

The following values were freshly measured with the same Node.js, solc, Ganache, optimizer, and Shanghai configuration as Route A. The kernel executes six consistency equations per sampled coordinate and reconstructs the distance commitment across all 128 coordinates. It deliberately excludes Fiat-Shamir sample derivation, enrollment storage, nonce state, and the legacy threshold Groth16 verifier, so it is not the full old protocol.

| case | samples | one bad: detection | transaction gas | execution after intrinsic | calldata bytes | tamper at coordinate 127 |
|---|---:|---:|---:|---:|---:|---|
| reconstruction-only | 0 | 0.00% | 999,981 | 585,633 | 24,900 | accepted |
| lambda-1 | 7 | 5.47% | 1,988,454 | 1,498,814 | 30,724 | accepted |
| lambda-2 | 14 | 10.94% | 2,984,186 | 2,419,362 | 36,548 | accepted |
| lambda-4 | 28 | 21.88% | 4,997,901 | 4,282,517 | 48,196 | accepted |
| lambda-8 | 56 | 43.75% | 9,113,567 | 8,097,063 | 71,492 | accepted |
| full-check | 128 | 100.00% | 20,237,503 | 18,446,123 | 131,396 | rejected |

The reconstruction-only row is not an authentication mode; it isolates the unavoidable O(N) product-commitment transport and reconstruction in the old relation. For every partial-check row, changing the unsampled coordinate 127 is accepted and changes the reconstructed commitment. FullCheck rejects the same modification.

## Current Route A reference

- Pure Groth16 verifier: 241,694 gas.
- Stateful authentication transaction: 282,479 gas, plus 76,689 gas for the first challenge transaction.
- Anchored first/steady authentication: 306,328 / 289,240 gas.
- The new relation checks every coordinate inside the circuit and has no sampling-miss term. Its prover time, proving-key size, and memory still scale with dimension.
