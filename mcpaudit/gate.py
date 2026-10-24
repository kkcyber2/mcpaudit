"""A tool-permission gate whose every decision is recorded."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from .log import AuditLog


class PolicyError(ValueError):
    """The policy itself is malformed."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class Gate:
    """Deny by default; allow only what a rule names.

    Rules are evaluated in order and the first match wins, so an explicit deny
    placed before an allow is a real override rather than a suggestion.
    """

    def __init__(self, log: AuditLog) -> None:
        self.log = log
        self._rules: list[tuple[str, str]] = []   # (pattern, allow|deny)
        self._approved: dict[str, str] = {}       # tool -> digest at approval

    def add_rule(self, pattern: str, effect: str) -> None:
        if effect not in ("allow", "deny"):
            raise PolicyError(f"effect must be allow or deny, got {effect!r}")
        if not pattern:
            raise PolicyError("a rule needs a pattern")
        self._rules.append((pattern, effect))

    def clear_rules(self) -> None:
        self._rules.clear()

    def approve(self, tool: str, digest: str) -> None:
        """Approve a tool at a specific definition digest.

        The digest is recorded, not just the name: approving `read_file` and
        later swapping its implementation must not silently inherit the
        approval, which is the whole point of change detection.
        """
        self._approved[tool] = digest
        self.log.append("tool-approved", tool, "allow",
                        f"approved at digest {digest[:12]}", {"digest": digest})

    def revoke(self, tool: str) -> bool:
        if tool not in self._approved:
            return False
        del self._approved[tool]
        self.log.append("tool-revoked", tool, "deny", "approval withdrawn")
        return True

    def check(self, tool: str, digest: str | None = None,
              arguments: dict | None = None) -> Decision:
        decision = self._decide(tool, digest, arguments or {})
        self.log.append(
            "call-allowed" if decision.allowed else "call-blocked",
            tool,
            "allow" if decision.allowed else "deny",
            decision.reason,
            {"digest": digest} if digest else {},
        )
        return decision

    def _decide(self, tool: str, digest: str | None,
                arguments: dict) -> Decision:
        for pattern, effect in self._rules:
            if fnmatchcase(tool, pattern):
                if effect == "deny":
                    return Decision(False, f"rule {pattern!r} denies this tool")
                # First match wins, so an allow rule must actually allow. Falling
                # through to the approval check would make every allow a no-op.
                return Decision(True, f"rule {pattern!r} allows this tool")

        if tool in self._approved:
            if digest and digest != self._approved[tool]:
                return Decision(
                    False,
                    "tool definition changed since it was approved "
                    f"({self._approved[tool][:12]} -> {digest[:12]})",
                )
            return Decision(True, "approved and unchanged")

        return Decision(False, "no rule allows this tool and it is not approved")
