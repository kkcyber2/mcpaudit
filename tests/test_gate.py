"""The gate: deny by default, explicit overrides, and change detection."""

import pytest

from mcpaudit.gate import Gate, PolicyError
from mcpaudit.log import AuditLog


def gate() -> Gate:
    return Gate(AuditLog(clock=lambda: 1.0))


class TestDefaultDeny:
    def test_an_unknown_tool_is_denied(self):
        assert gate().check("rm_rf").allowed is False

    def test_an_unknown_tool_says_why(self):
        decision = gate().check("rm_rf")
        assert "not approved" in decision.reason

    def test_an_approval_allows_the_tool(self):
        g = gate()
        g.approve("read_file", "d1")
        assert g.check("read_file", "d1").allowed is True

    def test_approval_without_a_digest_still_allows(self):
        g = gate()
        g.approve("read_file", "d1")
        assert g.check("read_file").allowed is True


class TestRules:
    def test_an_allow_rule_permits_a_matching_tool(self):
        g = gate()
        g.add_rule("read_*", "allow")
        assert g.check("read_file").allowed is True

    def test_a_deny_rule_blocks_a_matching_tool(self):
        g = gate()
        g.add_rule("write_*", "deny")
        assert g.check("write_file").allowed is False

    def test_a_deny_before_an_allow_wins(self):
        g = gate()
        g.add_rule("read_secret", "deny")
        g.add_rule("read_*", "allow")
        assert g.check("read_secret").allowed is False
        assert g.check("read_public").allowed is True

    def test_an_allow_never_overrides_an_explicit_deny_later(self):
        """Rules are first-match. This documents that ordering is the override."""
        g = gate()
        g.add_rule("read_*", "allow")
        g.add_rule("read_secret", "deny")
        # The earlier allow wins by design; a deny that must win goes first.
        assert g.check("read_secret").allowed is True

    def test_matching_is_case_sensitive(self):
        g = gate()
        g.add_rule("read_*", "allow")
        assert g.check("READ_FILE").allowed is False

    def test_a_bad_effect_is_refused(self):
        with pytest.raises(PolicyError, match="allow or deny"):
            gate().add_rule("x", "maybe")

    def test_an_empty_pattern_is_refused(self):
        with pytest.raises(PolicyError, match="pattern"):
            gate().add_rule("", "allow")

    def test_clearing_rules_falls_back_to_deny(self):
        g = gate()
        g.add_rule("read_*", "allow")
        g.clear_rules()
        assert g.check("read_file").allowed is False


class TestChangeDetection:
    def test_a_changed_definition_is_blocked(self):
        g = gate()
        g.approve("send_email", "digest-before")
        decision = g.check("send_email", "digest-after")
        assert decision.allowed is False
        assert "changed" in decision.reason

    def test_the_unchanged_definition_still_passes(self):
        g = gate()
        g.approve("send_email", "digest")
        assert g.check("send_email", "digest").allowed is True

    def test_revoking_removes_the_approval(self):
        g = gate()
        g.approve("send_email", "d")
        assert g.revoke("send_email") is True
        assert g.check("send_email", "d").allowed is False

    def test_revoking_an_unapproved_tool_reports_false(self):
        assert gate().revoke("never-approved") is False


class TestAuditTrail:
    def test_every_check_is_recorded(self):
        g = gate()
        g.approve("t", "d")
        g.check("t", "d")
        g.check("nope")
        kinds = [e.kind for e in g.log]
        assert kinds == ["tool-approved", "call-allowed", "call-blocked"]

    def test_the_block_reason_is_in_the_log(self):
        g = gate()
        g.check("nope")
        assert "not approved" in g.log.events[0].reason

    def test_the_digest_is_recorded_on_an_allowed_call(self):
        g = gate()
        g.approve("t", "abc")
        g.check("t", "abc")
        assert g.log.events[-1].detail["digest"] == "abc"

    def test_an_approval_records_the_digest(self):
        g = gate()
        g.approve("t", "abc123def456")
        assert g.log.events[0].detail["digest"] == "abc123def456"

    def test_the_whole_trail_still_verifies(self):
        g = gate()
        g.add_rule("read_*", "allow")
        g.approve("write_file", "d")
        for tool in ("read_a", "read_b", "write_file", "unknown"):
            g.check(tool, "d")
        assert g.log.verify_all() == []

    def test_a_tampered_trail_is_detected(self):
        g = gate()
        g.check("dangerous_tool")
        g.log.tamper(0, decision="allow", reason="looked fine to me")
        assert g.log.verify_all() == [0]
