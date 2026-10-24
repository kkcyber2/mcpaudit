"""Log behaviour: append, tamper detection, export and replay."""

import json

import pytest

from mcpaudit.log import AuditLog, LogError, replay


def log_with(count: int) -> AuditLog:
    log = AuditLog(clock=lambda: 1000.0)
    for i in range(count):
        log.append("call-allowed", f"tool-{i}", "allow", f"event {i}")
    return log


class TestAppend:
    def test_sequence_numbers_start_at_zero(self):
        log = AuditLog(clock=lambda: 5.0)
        assert log.append("call-allowed", "t", "allow", "r").seq == 0
        assert log.append("call-allowed", "t", "allow", "r").seq == 1

    def test_an_unknown_kind_is_refused(self):
        with pytest.raises(LogError, match="unknown event kind"):
            AuditLog().append("made-up", "t", "allow", "r")

    def test_an_unknown_decision_is_refused(self):
        with pytest.raises(LogError, match="unknown decision"):
            AuditLog().append("call-allowed", "t", "maybe", "r")

    def test_a_missing_subject_is_refused(self):
        with pytest.raises(LogError, match="subject"):
            AuditLog().append("call-allowed", "", "allow", "r")

    def test_the_head_tracks_the_entry_count(self):
        assert log_with(3).head().size == 3

    def test_detail_does_not_change_the_event_timestamp(self):
        log = AuditLog(clock=lambda: 42.0)
        event = log.append("call-blocked", "t", "deny", "r", {"why": "x"})
        assert event.at == 42.0
        assert event.detail == {"why": "x"}


class TestVerification:
    def test_an_untouched_log_verifies(self):
        assert log_with(10).verify_all() == []

    def test_every_entry_proves_individually(self):
        log = log_with(7)
        assert all(log.verify(i) for i in range(7))

    def test_a_rewritten_decision_breaks_its_proof(self):
        # The fixture writes `allow`; rewriting to `deny` is a real change.
        log = log_with(5)
        log.tamper(2, decision="deny")
        assert 2 in log.verify_all()

    def test_rewriting_a_field_to_its_existing_value_is_a_no_op(self):
        """Sanity check on the detector: an identical write keeps the root."""
        log = log_with(3)
        root = log.head().root
        log.tamper(1, decision="allow")
        assert log.head().root == root
        assert log.verify_all() == []

    def test_a_rewritten_subject_breaks_its_proof(self):
        log = log_with(5)
        log.tamper(3, subject="other-tool")
        assert 3 in log.verify_all()

    def test_a_rewritten_reason_breaks_its_proof(self):
        log = log_with(4)
        log.tamper(1, reason="nothing to see")
        assert 1 in log.verify_all()

    def test_editing_detail_breaks_the_proof(self):
        log = AuditLog(clock=lambda: 1.0)
        log.append("call-blocked", "t", "deny", "r", {"code": "E1"})
        log.tamper(0, detail={"code": "E2"})
        assert 0 in log.verify_all()

    def test_tampering_does_not_disturb_other_entries(self):
        """A rewritten entry must be individually locatable.

        Entries before `seq` keep their proofs; entries after it will not, but
        the point of the test is that detection is per-entry, not a blanket
        'something changed'.
        """
        log = log_with(8)
        log.tamper(5, reason="edited")
        assert log.verify(0) is True
        assert log.verify(5) is False


class TestExport:
    def test_export_then_replay_preserves_the_head(self):
        log = log_with(6)
        path = "/tmp/mcpaudit_roundtrip.json"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(log.to_json())

        restored = replay(path)
        assert restored.head().root == log.head().root
        assert len(restored) == len(log)

    def test_replay_detects_an_edited_export(self):
        log = log_with(4)
        payload = json.loads(log.to_json())
        payload["events"][1]["decision"] = "deny"
        path = "/tmp/mcpaudit_edited.json"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

        with pytest.raises(LogError, match="does not match"):
            replay(path)

    def test_the_export_is_stable_across_writes(self):
        assert log_with(3).to_json() == log_with(3).to_json()


class TestFind:
    def test_filters_by_decision(self):
        log = log_with(3)
        log.append("call-blocked", "danger", "deny", "no")
        assert [e.subject for e in log.find(decision="deny")] == ["danger"]

    def test_filters_by_kind(self):
        log = log_with(2)
        log.append("tool-approved", "t", "allow", "ok")
        assert len(log.find(kind="tool-approved")) == 1

    def test_filters_by_subject(self):
        assert len(log_with(4).find(subject="tool-2")) == 1
