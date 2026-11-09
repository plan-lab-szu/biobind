# Contract artifacts

`generated/Groth16Verifier128.sol` and `generated/Groth16Verifier512.sol` were
generated from the local benchmark-only zkeys. They exist solely to reproduce
the gas measurements and must not be deployed in a real system.

Production verifiers must be regenerated after the circuits and public-input
order are frozen, a public Powers of Tau transcript is independently verified,
and an auditable circuit-specific phase-2 ceremony is completed.

`UBCALifecycle.sol` is an independently tested reference state machine for
one-time uniqueness receipts, enrollment co-attestation, terminal revocation,
and atomic credential/device/policy successors. It is intentionally separate
from the measured `BioAuthGateway.sol` until the lifecycle interface is frozen.
Its owner currently models the BioZKFHE-result adapter and issuer, not a
production governance design.
