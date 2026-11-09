# Authorized local provenance security evaluation

## Scope

This is a defensive academic experiment against researcher-owned code. It ran
only on an in-process Ganache test chain. No third-party endpoint, public
network, real account, or real biometric record was accessed.

The comparison contract is deliberately incomplete and does not represent a
claim about any named paper or deployed service. The proving key is explicitly
a benchmark-only key.

## Question

Do individually sound uniqueness, ZK matching, capture signing, freshness, and
authorization components automatically establish an end-to-end biometric
provenance chain when composed through natural but incomplete interfaces?

## Local negative and positive controls

| Observation | Result |
|---|---:|
| Offline Groth16 verification of host-constructed witness | PASS |
| Deliberately incomplete baseline accepts that valid proof | YES |
| Baseline rejects reuse of the same nullifier | YES |
| Valid same-chain terminal receipt is consumed and its lineage stored | YES |
| That one-time receipt still issues an unrelated enrollment commitment | YES |
| Authorized host-input signing API blesses a host-constructed probe | YES |
| Cached authorization remains usable after credential revocation | YES |
| Provenance-aware gateway rejects evidence signed outside the authorized device identity | YES |
| Rejected attempt leaves its challenge unconsumed | YES |
| Provenance-aware gateway checks live credential state at submission | YES |
| Same proof is accepted with the authorized mock capture signature | YES |
| Accepted attempt consumes its challenge and rejects replay | YES |

## Interpretation

The constructed probe equals the synthetic enrollment vector and therefore has
distance zero. The full-vector circuit, proof, uniqueness decision, one-time
receipt state, capture signature, and cached authorization are each functioning
as configured; this test does not break their underlying cryptography. Instead,
three composition seams remain: a canonical receipt derived from a valid
same-chain terminal state does not authenticate the independently chosen
enrollment commitment, a signing key does not prove its API derived the signed
commitment from a sensor, and a historical authorization does not imply current
eligibility at the acceptance linearization point.

The gateway rejects signatures outside its configured device and rejects the
prepared transaction after live credential revocation. However, the local
authorized-device positive control signs a host-supplied commitment, so its
acceptance also demonstrates why a contract signature check alone is
insufficient: the real MCU/TEE API must internally derive the commitment from
authenticated sensor data. This is a local composition-gap evaluation, not a
claim of compromising any external system.

## Limits

The authorized-device key is a software wallet used as a deterministic mock.
This run validates protocol composition and state transitions, not physical
sensor wiring, TEE key isolation, secure boot, PAD/liveness, or production
governance. Those require the separate hardware evaluation.

Machine-readable evidence: `result.json`.
