"""Tamper-evident audit logging for agent tool use."""

from .gate import Decision, Gate, PolicyError
from .log import AuditLog, Event, LogError, replay
from .merkle import MerkleTree, TreeHead, verify_inclusion

__all__ = [
    "AuditLog", "Decision", "Event", "Gate", "LogError", "MerkleTree",
    "PolicyError", "TreeHead", "replay", "verify_inclusion",
]

__version__ = "1.0.0"
