# Pre-exposure attempt-budget reference

`attempt_budget.py` models one durable software boundary. A trusted capture
component must call `reserve(scope, attempt_id)` **before** taking or revealing
a new probe; it must persist `commit_transcript` before returning the exact
signed transcript. `retransmit` returns those same bytes without another
capture. A crash after reservation consumes the unit; a restarted controller
cannot commit the abandoned reservation. SQLite `BEGIN IMMEDIATE` serializes
concurrent reservations, with WAL and full synchronous writes.

The scope ID is assumed to be derived from authenticated application,
account/credential version, device version, policy version and budget window.
The lower-level budget reference accepts a string and does not authenticate
that derivation. `budgeted_capture.py` adds a provisioned software wrapper:
its scope ID is SHA-256 of a versioned domain and fixed-width application ID,
holder, credential ID, device version ID, policy hash, budget-policy hash and
window ID, in that order. The capture API does not accept a host-selected
scope. It reserves durably before invoking the sensor callback, then persists
a canonical scope/attempt/challenge/probe-commitment transcript with a mock
HMAC before returning any bytes. Retransmission reads exactly the persisted
bytes; the sensor callback is not called again. `revoke_scope` stops future
publication or retransmission; a new version needs a new provisioned scope.
The HMAC is a software test signature, **not** the gateway's EIP-712 device
signature.
`../scripts/lib/eip712-budgeted-signer.mjs` is a separate Node 24 software
signer that derives the same scope ID, computes the gateway's EIP-712 digest
locally, reserves a SQLite unit before signing, and persists exact signed
bytes. Its four tests and the 128-D integration script verify digest equality
with the contract, replay, exhaustion and policy-scope revocation. The host
constructs `cProbe` before calling this signer, so this path budgets
**signatures**, not pre-sensor exposures. Both reference paths still require
a protected acquisition implementation to enforce the intended budget.

Run:

```powershell
python -m unittest -v test_attempt_budget.py test_budgeted_capture.py
python run_controls.py
```

`run_controls.py` writes a source-fingerprinted result to
`../build/budget-reference/results.json`.

The 11 tests cover exhaustion without a sensor call, failed host submission,
byte-identical replay after restart, crash after reservation, concurrent
capture attempts, policy migration, global attempt ID reuse and the case in
which two fresh acquisitions yield the same commitment.

This is **not** a protected sensor or TEE implementation. The provisioning
authority, sensor callback, HMAC key and SQLite state are all software trust
assumptions. The wrapper is not wired to the EVM capture signer, cannot
prevent a host with direct sensor/key access from bypassing it, cannot detect
rollback of device storage, and does not bind one person across multiple
accounts/devices. Budget windows also require trusted provisioning and clock
or epoch governance. None of those claims follows from the passing tests.
