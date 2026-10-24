"""The audited event log.

Each entry records *what* happened and *why it was allowed*. The append ordering
is what makes the log trustworthy: an entry cannot claim a tool was approved
before it existed, because the sequence number is assigned at write time and the
tree is append-only.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

from .merkle import MerkleTree, TreeHead, verify_inclusion


class LogError(ValueError):
    """The log cannot accept this entry."""


@dataclass(frozen=True)
class Event:
    seq: int
    at: float
    kind: str
    subject: str
    decision: str
    reason: str
    detail: dict = field(default_factory=dict)

    def canonical(self) -> bytes:
        """Deterministic bytes: key order must not change the hash."""
        return json.dumps(
            {
                "seq": self.seq,
                "at": round(self.at, 6),
                "kind": self.kind,
                "subject": self.subject,
                "decision": self.decision,
                "reason": self.reason,
                "detail": self.detail,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "at": self.at, "kind": self.kind,
            "subject": self.subject, "decision": self.decision,
            "reason": self.reason, "detail": self.detail,
        }


_KINDS = frozenset({
    "tool-registered", "tool-approved", "tool-revoked", "tool-changed",
    "call-allowed", "call-blocked", "policy-changed",
})
_DECISIONS = frozenset({"allow", "deny", "note"})


class AuditLog:
    """Append-only event log with a Merkle tree over every entry."""

    def __init__(self, clock=time.time) -> None:
        self._tree = MerkleTree()
        self._events: list[Event] = []
        self._clock = clock

    def __len__(self) -> int:
        return len(self._events)

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def head(self) -> TreeHead:
        return self._tree.head()

    def append(self, kind: str, subject: str, decision: str, reason: str,
               detail: dict | None = None, at: float | None = None) -> Event:
        if kind not in _KINDS:
            raise LogError(f"unknown event kind {kind!r}")
        if decision not in _DECISIONS:
            raise LogError(f"unknown decision {decision!r}")
        if not subject:
            raise LogError("an event needs a subject")

        event = Event(
            seq=len(self._events),
            at=self._clock() if at is None else at,
            kind=kind,
            subject=subject,
            decision=decision,
            reason=reason,
            detail=dict(detail or {}),
        )
        # Hash before storing, so a hashing failure cannot leave a half-written
        # entry in the list with no leaf in the tree.
        self._tree.add(event.canonical())
        self._events.append(event)
        return event

    def inclusion_proof(self, seq: int) -> list[str]:
        return self._tree.inclusion_proof(seq)

    def verify(self, seq: int) -> bool:
        """Self-check: does entry `seq` prove into the current head?"""
        if not 0 <= seq < len(self._events):
            return False
        return verify_inclusion(
            index=seq,
            size=len(self._events),
            data=self._events[seq].canonical(),
            proof=self.inclusion_proof(seq),
            root_hex=self.head().root,
        )

    def verify_all(self) -> list[int]:
        """Every sequence number whose proof fails. Empty means intact."""
        return [e.seq for e in self._events if not self.verify(e.seq)]

    def tamper(self, seq: int, **changes: Any) -> None:
        """Rewrite an entry *without* updating the tree.

        Exists so tests can demonstrate that tampering is detected. Any caller
        reaching for this in production is the attack.
        """
        if not 0 <= seq < len(self._events):
            raise IndexError(seq)
        old = self._events[seq]
        detail = {**old.detail, **changes.pop("detail", {})}
        self._events[seq] = Event(
            seq=old.seq,
            at=changes.pop("at", old.at),
            kind=changes.pop("kind", old.kind),
            subject=changes.pop("subject", old.subject),
            decision=changes.pop("decision", old.decision),
            reason=changes.pop("reason", old.reason),
            detail=detail,
        )

    def to_json(self) -> str:
        return json.dumps(
            {"head": self.head().as_dict(),
             "events": [e.as_dict() for e in self._events]},
            indent=2, sort_keys=True,
        )

    def __iter__(self) -> Iterator[Event]:
        return iter(self._events)

    def find(self, *, kind: str | None = None, subject: str | None = None,
             decision: str | None = None) -> list[Event]:
        return [
            e for e in self._events
            if (kind is None or e.kind == kind)
            and (subject is None or e.subject == subject)
            and (decision is None or e.decision == decision)
        ]


def replay(path: str) -> AuditLog:
    """Rebuild a log from exported JSON and confirm the head still matches."""
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)

    log = AuditLog(clock=lambda: 0.0)
    for raw in payload.get("events", []):
        log.append(
            kind=raw["kind"], subject=raw["subject"],
            decision=raw["decision"], reason=raw["reason"],
            detail=raw.get("detail") or {}, at=raw["at"],
        )

    expected = payload.get("head", {}).get("root")
    actual = log.head().root
    if expected != actual:
        raise LogError(
            f"replayed head {actual} does not match the exported head {expected}"
        )
    return log
