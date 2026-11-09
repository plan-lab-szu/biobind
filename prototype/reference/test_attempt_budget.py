"""Fault and concurrency checks for the durable exposure-budget model."""

from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from attempt_budget import AttemptBudget, BudgetError


class AttemptBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "budget.sqlite"
        self.budget = AttemptBudget(self.db_path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_retransmission_reuses_persisted_bytes_without_new_unit(self) -> None:
        self.budget.register_scope("app/account/credential/device/window1", 2)
        self.budget.reserve("app/account/credential/device/window1", "capture-1")
        self.budget.commit_transcript("capture-1", b"signed-canonical-transcript")
        self.assertEqual(self.budget.retransmit("capture-1"), b"signed-canonical-transcript")
        self.assertEqual(AttemptBudget(self.db_path).retransmit("capture-1"),
                         b"signed-canonical-transcript")
        self.assertEqual(self.budget.usage("app/account/credential/device/window1"),
                         (1, 2, True))
        with self.assertRaises(BudgetError):
            self.budget.reserve("app/account/credential/device/window1", "capture-1")
        self.assertEqual(self.budget.usage("app/account/credential/device/window1")[0], 1)

    def test_crash_after_reservation_consumes_unit(self) -> None:
        self.budget.register_scope("scope", 1)
        self.budget.reserve("scope", "capture-1")
        restarted = AttemptBudget(self.db_path)
        with self.assertRaises(BudgetError):
            restarted.commit_transcript("capture-1", b"new-sample")
        with self.assertRaises(BudgetError):
            restarted.retransmit("capture-1")
        with self.assertRaises(BudgetError):
            restarted.reserve("scope", "capture-2")
        self.assertEqual(restarted.usage("scope"), (1, 1, True))

    def test_revocation_invalidates_pending_and_retransmission(self) -> None:
        self.budget.register_scope("old-version", 2)
        self.budget.reserve("old-version", "pending")
        self.budget.reserve("old-version", "committed")
        self.budget.commit_transcript("committed", b"signed")
        self.budget.revoke_scope("old-version")
        for operation in (
            lambda: self.budget.commit_transcript("pending", b"late"),
            lambda: self.budget.retransmit("committed"),
            lambda: self.budget.reserve("old-version", "new"),
        ):
            with self.assertRaises(BudgetError):
                operation()
        self.assertEqual(self.budget.usage("old-version"), (2, 2, False))
        self.budget.register_scope("new-version", 1)
        self.budget.reserve("new-version", "new")
        self.assertEqual(self.budget.usage("new-version"), (1, 1, True))

    def test_concurrent_reservations_never_exceed_budget(self) -> None:
        self.budget.register_scope("scope", 3)

        def reserve_one(index: int) -> bool:
            controller = AttemptBudget(self.db_path)
            try:
                controller.reserve("scope", f"capture-{index}")
                return True
            except BudgetError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted = list(pool.map(reserve_one, range(12)))
        self.assertEqual(sum(accepted), 3)
        self.assertEqual(self.budget.usage("scope"), (3, 3, True))


if __name__ == "__main__":
    unittest.main()
