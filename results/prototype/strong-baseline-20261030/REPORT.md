# Strong attested-match comparison

Generated: 2026-10-30T04:45:24.163Z

Both bound profiles use the same gateway, enrollment linkage, terminal adapter, capture signature, live-state checks, and freshness transition. Only the matching evidence backend differs.

| Profile | Valid match | Enrollment substitution rejected | Revoke/replay controls | Auth gas |
|---|---|---|---|---:|
| zk-unbound-control | true | true | true | 333949 |
| zk-bound | true | true | true | 336239 |
| attested-bound | true | true | true | 123102 |
| attested-merged | true | true | true | 103440 |

Honest attested matching refuses the non-match. The unbound-threshold control accepts a real proof for an inflated epsilon. The bound ZK gateway rejects that proof and its relabelled variant. A matcher-only false-positive fault produces an accepted attestation; this violates the baseline's trusted-matching premise and is not a fair attack under the original model.

- No real TEE, sensor, or BioZKFHE upstream run
- Matcher-only fault is outside the honest trusted-matcher model; not a full TEE-compromise claim
- attested-bound keeps two signatures and a padded verifier ABI; attested-merged (B1') uses one capture-TCB signature and omits C_probe; neither is a proven gas lower bound
- Unbound variant is a documented guard ablation, not a proposed baseline
- No empirical novelty claim or named-system vulnerability follows
