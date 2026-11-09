"""Software-only pre-exposure capture wrapper for the BioZERO budget model.

The provisioned scope, sensor callback and HMAC key stand in for a trusted
device boundary. HMAC transcripts are deliberately *not* EVM capture
signatures. A host with direct access to the sensor or key can bypass this
reference; deployment requires protected acquisition and anti-rollback state.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Callable

from attempt_budget import AttemptBudget, BudgetError


SCOPE_DOMAIN = b"BioZERO/budget-scope/v1\0"
TRANSCRIPT_DOMAIN = b"BioZERO/capture-reference/v1\0"
TRANSCRIPT_BYTES = len(TRANSCRIPT_DOMAIN) + 32 * 5


def _fixed(value: bytes, length: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


@dataclass(frozen=True)
class CaptureScope:
    application_id: bytes
    holder: bytes
    credential_id: bytes
    device_version_id: bytes
    policy_hash: bytes
    budget_policy_hash: bytes
    window_id: bytes

    def scope_id(self) -> str:
        fields = (
            _fixed(self.application_id, 32, "application_id"),
            _fixed(self.holder, 20, "holder"),
            _fixed(self.credential_id, 32, "credential_id"),
            _fixed(self.device_version_id, 32, "device_version_id"),
            _fixed(self.policy_hash, 32, "policy_hash"),
            _fixed(self.budget_policy_hash, 32, "budget_policy_hash"),
            _fixed(self.window_id, 32, "window_id"),
        )
        return hashlib.sha256(SCOPE_DOMAIN + b"".join(fields)).hexdigest()


class BudgetedCapture:
    """One provisioned software device reference; scope is never host-selected.

    `sensor` returns a 32-byte probe commitment. It must acquire/derive the
    commitment internally in a real device. This reference tests call order,
    persistence and exact transcript replay, not physical provenance.
    """

    def __init__(
        self,
        budget: AttemptBudget,
        scope: CaptureScope,
        signing_key: bytes,
        sensor: Callable[[], bytes],
    ) -> None:
        self.budget = budget
        self.scope = scope
        self.scope_id = scope.scope_id()
        self.signing_key = _fixed(signing_key, 32, "signing_key")
        self.sensor = sensor

    def provision(self, max_exposures: int) -> None:
        self.budget.register_scope(self.scope_id, max_exposures)

    def capture(self, attempt_id: bytes, challenge_digest: bytes) -> bytes:
        attempt = _fixed(attempt_id, 32, "attempt_id")
        challenge = _fixed(challenge_digest, 32, "challenge_digest")
        # The durable transaction commits before sensor invocation. Any
        # subsequent failure conservatively spends this unit.
        self.budget.reserve(self.scope_id, attempt.hex())
        commitment = _fixed(self.sensor(), 32, "probe_commitment")
        payload = (
            TRANSCRIPT_DOMAIN
            + bytes.fromhex(self.scope_id)
            + attempt
            + challenge
            + commitment
        )
        signature = hmac.digest(self.signing_key, payload, "sha256")
        transcript = payload + signature
        self.budget.commit_transcript(attempt.hex(), transcript)
        return transcript

    def retransmit(self, attempt_id: bytes) -> bytes:
        attempt = _fixed(attempt_id, 32, "attempt_id")
        transcript = self.budget.retransmit(attempt.hex())
        if not self.verify(transcript, attempt):
            raise BudgetError("transcript does not belong to this provisioned device/scope")
        return transcript

    def verify(self, transcript: bytes, attempt_id: bytes) -> bool:
        attempt = _fixed(attempt_id, 32, "attempt_id")
        if len(transcript) != TRANSCRIPT_BYTES:
            return False
        payload, signature = transcript[:-32], transcript[-32:]
        scope_start = len(TRANSCRIPT_DOMAIN)
        return (
            payload.startswith(TRANSCRIPT_DOMAIN)
            and payload[scope_start:scope_start + 32] == bytes.fromhex(self.scope_id)
            and payload[scope_start + 32:scope_start + 64] == attempt
            and hmac.compare_digest(hmac.digest(self.signing_key, payload, "sha256"), signature)
        )

    def revoke(self) -> None:
        self.budget.revoke_scope(self.scope_id)
