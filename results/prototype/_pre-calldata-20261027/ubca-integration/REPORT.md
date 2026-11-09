# Integrated UBCA local defensive evaluation

## Scope

This experiment ran entirely against researcher-owned contracts on an
in-process Ganache chain with synthetic vectors. It contacted no public network
or third-party service. The Groth16 key is benchmark-only. The adapter derives
receipts from a same-chain terminal-state interface; the source contract is a
local immutable-state fixture rather than the actual BioZKFHE deployment. The
capture key is a software-wallet mock rather than a hardware-isolated key.

## End-to-end chain

`atomic source-session consumption and enrollment co-attestation
-> active credential/device/policy
-> context-bound full-vector Groth16 proof -> authorized capture statement
-> atomic challenge consumption`

| Check | Result |
|---|---:|
| Unique receipt consumed by exactly the issued credential | PASS |
| Receipt derived from validated same-chain terminal state | PASS |
| Source session and destination credential change atomically | PASS |
| Legacy owner receipt path permanently disabled | PASS |
| Full-vector proof verifies offline | PASS |
| Capture signature outside authorized device identity rejected | PASS |
| Device revoked before submission rejects prepared authentication | PASS |
| Credential revoked before submission rejects prepared authentication | PASS |
| Policy revoked before submission rejects prepared authentication | PASS |
| Rejected controls preserve pending challenge | PASS |
| Authorized integrated authentication accepted | PASS |
| Acceptance consumes challenge and replay is rejected | PASS |
| Old policy cannot issue a challenge after replacement | PASS |
| Wrong successor signature preserves new source receipt | PASS |
| New receipt atomically supersedes the old credential | PASS |
| New-policy proof verifies and old-policy proof is rejected | PASS |
| Old enrollment commitment fails under successor policy digest | PASS |
| Successor authentication consumes its challenge | PASS |
| Budgeted EIP-712 signer replays exact bytes and blocks extra signatures | PASS |
| Policy replacement revokes the old signing scope | PASS |
| Local EIP-712 digests match gateway before and after migration | PASS |

## Public observer view of cross-application migration

This view is derived from decoded public gateway logs and credential getters,
without using the fixture's vectors or salts. The old and successor
application IDs, policy hashes, enrollment commitments, and device signing
keys differ. Nevertheless, both authentication events expose the same holder,
both credential-issuance events expose the same lineage ID, and a
`CredentialSuperseded` event names the old and new credential IDs. An
observer can therefore link these two synthetic sessions directly. Distinct
commitment bytes do not imply whole-transcript unlinkability.

| Public observation | Result |
|---|---:|
| Different application IDs and policy hashes | YES |
| Different enrollment commitments and device signing keys | YES |
| Same holder address and lineage ID | YES |
| Explicit old-to-new credential supersession link | YES |

This is an observer trace for one local migration, not a statistical privacy
experiment or a claim about separate users with no shared public metadata.

## Measurements

| Item | Value |
|---|---:|
| Gateway runtime bytecode | 20,360 bytes |
| Gateway deployment | 4,463,077 gas |
| Source adapter runtime bytecode | 4,035 bytes |
| Source adapter deployment | 929,036 gas |
| Local source fixture deployment | 411,994 gas |
| Canonical policy and threshold registration | 327,676 gas |
| Device registration | 190,137 gas |
| Local source finalization record | 250,487 gas |
| Atomic receipt consumption and credential issuance | 466,811 gas |
| Challenge issuance | 108,086 gas |
| Integrated authentication | 336,260 gas |
| Witness plus proof generation | 869.50 ms |
| Canonical policy replacement | 320,191 gas |
| Atomic successor issuance | 448,512 gas |
| Successor authentication | 336,284 gas |
| Successor witness plus proof | 560.14 ms |

## Interpretation and limits

This exercises the listed software-composition controls: the authentication
transaction reads the same monotonic credential, device, and policy state
created by atomic uniqueness-bound issuance. Adapter consumption, canonical
receipt checks, enrollment-link verification, and credential creation now share
one cross-contract EVM transaction. Canonical EVM ordering gives revocation
its intended meaning: a revocation transaction linearized before verification
causes the already-prepared proof and capture statement to fail.

The public proof threshold is now checked against its immutable policy mapping;
the separate strong-baseline evaluation covers threshold substitution and
compares the same gateway with an attested-matcher backend. These traces are
not a complete security proof or evidence of novelty over strong composition.

The local EIP-712 budget signer uses a durable SQLite counter and signs only
after reserving one unit. Exact transcript replay uses no new unit, and policy
replacement revokes the old signing scope. The host still computes cProbe
before requesting a signature and retains software key access in this fixture;
these checks are a signature budget, not pre-sensor exposure control.

This result exercises destination adapter logic and same-chain terminal
state checks, but does not claim that the local source fixture executed PVSC,
threshold decryption, or committee confirmation. The next source-side gate is
to expose the frozen view from the actual BioZKFHE contract. The hardware gate
remains a real sensor-to-commitment TCB instance.
