"""End-to-end software controls for pre-exposure reservation and publication."""

from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Lock

from attempt_budget import AttemptBudget, BudgetError
from budgeted_capture import BudgetedCapture, CaptureScope


def field(value: int, size: int = 32) -> bytes:
    return value.to_bytes(size, "big")


class BudgetedCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "capture.sqlite"
        self.budget = AttemptBudget(self.database)
        self.scope = CaptureScope(
            application_id=field(1), holder=field(2, 20), credential_id=field(3),
            device_version_id=field(4), policy_hash=field(5),
            budget_policy_hash=field(6), window_id=field(7),
        )
        self.key = field(99)
        self.sensor_calls = 0
        self.sensor_lock = Lock()

    def sensor(self) -> bytes:
        with self.sensor_lock:
            self.sensor_calls += 1
            return field(1_000 + self.sensor_calls)

    def device(self, scope: CaptureScope | None = None) -> BudgetedCapture:
        return BudgetedCapture(self.budget, scope or self.scope, self.key, self.sensor)

    def test_reserve_precedes_sensor_and_failed_host_verification_still_spends(self) -> None:
        device = self.device()
        device.provision(1)
        attempt = field(10)
        transcript = device.capture(attempt, field(20))
        self.assertTrue(device.verify(transcript, attempt))
        self.assertEqual(self.sensor_calls, 1)
        # A failed or unsubmitted host proof cannot refund a disclosed probe.
        with self.assertRaisesRegex(BudgetError, "budget exhausted"):
            device.capture(field(11), field(21))
        self.assertEqual(self.sensor_calls, 1)
        self.assertEqual(self.budget.usage(device.scope_id), (1, 1, True))

    def test_retransmit_is_byte_identical_after_restart_without_sensor_call(self) -> None:
        device = self.device()
        device.provision(2)
        attempt = field(12)
        first = device.capture(attempt, field(22))
        restarted = BudgetedCapture(AttemptBudget(self.database), self.scope,
                                    self.key, self.sensor)
        self.assertEqual(restarted.retransmit(attempt), first)
        self.assertEqual(self.sensor_calls, 1)
        with self.assertRaises(BudgetError):
            restarted.capture(attempt, field(23))
        self.assertEqual(self.sensor_calls, 1)
        self.assertEqual(self.budget.usage(device.scope_id), (1, 2, True))
        self.assertFalse(restarted.verify(first[:-1] + bytes([first[-1] ^ 1]), attempt))

    def test_sensor_failure_and_restart_conservatively_consume_one_unit(self) -> None:
        def failed_sensor() -> bytes:
            with self.sensor_lock:
                self.sensor_calls += 1
            raise RuntimeError("simulated sensor crash")

        device = BudgetedCapture(self.budget, self.scope, self.key, failed_sensor)
        device.provision(1)
        with self.assertRaisesRegex(RuntimeError, "sensor crash"):
            device.capture(field(13), field(23))
        self.assertEqual(self.sensor_calls, 1)
        restarted = self.device()
        with self.assertRaises(BudgetError):
            restarted.retransmit(field(13))
        with self.assertRaisesRegex(BudgetError, "budget exhausted"):
            restarted.capture(field(14), field(24))
        self.assertEqual(self.sensor_calls, 1)

    def test_equal_commitment_on_new_capture_still_spends_new_unit(self) -> None:
        calls = 0

        def same_vector_sensor() -> bytes:
            nonlocal calls
            calls += 1
            return field(55)

        device = BudgetedCapture(self.budget, self.scope, self.key,
                                 same_vector_sensor)
        device.provision(2)
        first = device.capture(field(41), field(51))
        second = device.capture(field(42), field(52))
        self.assertEqual(calls, 2)
        self.assertNotEqual(first, second)
        self.assertEqual(self.budget.usage(device.scope_id), (2, 2, True))

    def test_policy_migration_revokes_old_scope_and_requires_new_scope(self) -> None:
        old = self.device()
        old.provision(2)
        old_attempt = field(15)
        old.capture(old_attempt, field(25))
        old.revoke()
        with self.assertRaises(BudgetError):
            old.retransmit(old_attempt)
        with self.assertRaises(BudgetError):
            old.capture(field(16), field(26))

        new_scope = replace(self.scope, application_id=field(30),
                            credential_id=field(31), device_version_id=field(32),
                            policy_hash=field(33))
        successor = self.device(new_scope)
        self.assertNotEqual(old.scope_id, successor.scope_id)
        successor.provision(1)
        new_attempt = field(17)
        successor.capture(new_attempt, field(27))
        self.assertEqual(self.sensor_calls, 2)
        self.assertEqual(self.budget.usage(old.scope_id), (1, 2, False))
        self.assertEqual(self.budget.usage(successor.scope_id), (1, 1, True))
        # Attempt identifiers are global: a host cannot reuse an old event ID
        # to claim another capture even under a newly provisioned scope.
        another_scope = replace(new_scope, window_id=field(40))
        another = self.device(another_scope)
        another.provision(1)
        with self.assertRaisesRegex(BudgetError, "attempt_id already used"):
            another.capture(old_attempt, field(28))
        self.assertEqual(self.sensor_calls, 2)

    def test_concurrent_capture_callbacks_never_exceed_budget(self) -> None:
        device = self.device()
        device.provision(3)

        def capture_one(index: int) -> bool:
            worker = BudgetedCapture(AttemptBudget(self.database), self.scope,
                                     self.key, self.sensor)
            try:
                worker.capture(field(100 + index), field(200 + index))
                return True
            except BudgetError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted = list(pool.map(capture_one, range(12)))
        self.assertEqual(sum(accepted), 3)
        self.assertEqual(self.sensor_calls, 3)
        self.assertEqual(self.budget.usage(device.scope_id), (3, 3, True))

    def test_scope_derivation_changes_with_every_authorized_field(self) -> None:
        base = self.scope.scope_id()
        for field_name, new_value in (
            ("application_id", field(21)), ("holder", field(22, 20)),
            ("credential_id", field(23)), ("device_version_id", field(24)),
            ("policy_hash", field(25)), ("budget_policy_hash", field(26)),
            ("window_id", field(27)),
        ):
            with self.subTest(field_name=field_name):
                self.assertNotEqual(replace(self.scope, **{field_name: new_value}).scope_id(), base)


if __name__ == "__main__":
    unittest.main()
