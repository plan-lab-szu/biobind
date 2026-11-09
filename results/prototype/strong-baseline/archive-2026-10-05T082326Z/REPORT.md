# Strong attested-match comparison

Generated: 2026-10-05T08:23:26.974Z

Both bound profiles use the same gateway, enrollment linkage, terminal adapter, capture signature, live-state checks, and freshness transition. Only the matching evidence backend differs.

| Profile | Valid match | Enrollment substitution rejected | Revoke/replay controls | Auth gas |
|---|---|---|---|---:|
| zk-unbound-control | true | true | true | 326928 |
| zk-bound | true | true | true | 329262 |
| attested-bound | true | true | true | 116104 |

Honest attested matching refuses the non-match. The unbound-threshold control accepts a real proof for an inflated epsilon. The bound ZK gateway rejects that proof and its relabelled variant. A matcher-only false-positive fault produces an accepted attestation; this violates the baseline's trusted-matching premise and is not a fair attack under the original model.

- No real TEE, sensor, or BioZKFHE upstream run
- Matcher-only fault is outside the honest trusted-matcher model; not a full TEE-compromise claim
- Two signatures and padded verifier ABI favor reuse; not an optimized attestation gas lower bound
- Unbound variant is a documented guard ablation, not a proposed baseline
- No empirical novelty claim or named-system vulnerability follows
