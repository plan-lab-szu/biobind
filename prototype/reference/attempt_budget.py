"""Durable pre-exposure budget reference state machine for BioZERO.

This module does not capture biometrics or protect a device key. A trusted
acquisition implementation must call reserve *before* exposing a new sample
and commit_transcript before returning signed bytes to the host.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class BudgetError(RuntimeError):
    pass


class AttemptBudget:
    def __init__(self, database: str | Path):
        self.database = str(database)
        self._live_reservations: set[str] = set()
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS scopes (
                    scope_id TEXT PRIMARY KEY,
                    max_exposures INTEGER NOT NULL CHECK (max_exposures > 0),
                    used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0),
                    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
                    state TEXT NOT NULL CHECK (state IN ('reserved', 'committed')),
                    transcript BLOB,
                    CHECK ((state = 'reserved' AND transcript IS NULL)
                        OR (state = 'committed' AND transcript IS NOT NULL))
                );
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA journal_mode = WAL")
            db.execute("PRAGMA synchronous = FULL")
            yield db
        finally:
            db.close()

    def register_scope(self, scope_id: str, max_exposures: int) -> None:
        """Register one versioned application/credential/device/window scope."""
        if not scope_id or max_exposures < 1:
            raise ValueError("nonempty scope and positive budget required")
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO scopes(scope_id,max_exposures) VALUES (?,?)",
                    (scope_id, max_exposures),
                )
            except sqlite3.IntegrityError as exc:
                raise BudgetError("scope already registered") from exc

    def reserve(self, scope_id: str, attempt_id: str) -> None:
        """Consume one unit before capture; a crash leaves it consumed."""
        if not attempt_id:
            raise ValueError("attempt_id required")
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT max_exposures,used,active FROM scopes WHERE scope_id=?",
                    (scope_id,),
                ).fetchone()
                if row is None or row[2] != 1:
                    raise BudgetError("inactive or unknown scope")
                if row[1] >= row[0]:
                    raise BudgetError("budget exhausted")
                db.execute(
                    "INSERT INTO attempts(attempt_id,scope_id,state) VALUES (?,?,'reserved')",
                    (attempt_id, scope_id),
                )
                db.execute("UPDATE scopes SET used=used+1 WHERE scope_id=?", (scope_id,))
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise BudgetError("attempt_id already used") from exc
            except Exception:
                db.rollback()
                raise
        self._live_reservations.add(attempt_id)

    def commit_transcript(self, attempt_id: str, transcript: bytes) -> None:
        """Persist exact signed output before exposing it to the host."""
        if attempt_id not in self._live_reservations:
            raise BudgetError("reservation belongs to an earlier process or is absent")
        if not transcript:
            raise ValueError("nonempty canonical transcript required")
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    """SELECT attempts.state,scopes.active FROM attempts
                       JOIN scopes USING(scope_id) WHERE attempt_id=?""",
                    (attempt_id,),
                ).fetchone()
                if row != ("reserved", 1):
                    raise BudgetError("reservation invalidated or already committed")
                db.execute(
                    "UPDATE attempts SET state='committed',transcript=? WHERE attempt_id=?",
                    (transcript, attempt_id),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        self._live_reservations.remove(attempt_id)

    def retransmit(self, attempt_id: str) -> bytes:
        """Return exactly the already exposed bytes; never capture again."""
        with self._connect() as db:
            row = db.execute(
                """SELECT attempts.state,attempts.transcript,scopes.active
                   FROM attempts JOIN scopes USING(scope_id) WHERE attempt_id=?""",
                (attempt_id,),
            ).fetchone()
        if row is None or row[0] != "committed" or row[2] != 1:
            raise BudgetError("no active committed transcript")
        return bytes(row[1])

    def revoke_scope(self, scope_id: str) -> None:
        """Stop new captures and retransmissions; consumed units remain used."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE scopes SET active=0 WHERE scope_id=? AND active=1",
                (scope_id,),
            ).rowcount
            if changed != 1:
                db.rollback()
                raise BudgetError("unknown or inactive scope")
            db.commit()

    def usage(self, scope_id: str) -> tuple[int, int, bool]:
        with self._connect() as db:
            row = db.execute(
                "SELECT used,max_exposures,active FROM scopes WHERE scope_id=?",
                (scope_id,),
            ).fetchone()
        if row is None:
            raise BudgetError("unknown scope")
        return row[0], row[1], bool(row[2])
