import json

import pytest

from unraid_updater.evidence import (
    EvidenceError,
    append_audit,
    append_jsonl,
    verify_audit,
    write_json,
)


def test_json_is_redacted_and_atomic(tmp_path):
    path = write_json(tmp_path, "containers/app.json", {"token": "secret", "ok": 1})
    assert json.loads(path.read_text()) == {"token": "[REDACTED]", "ok": 1}


def test_jsonl_append_and_audit_chain(tmp_path):
    append_jsonl(tmp_path, "events.jsonl", {"event": "scan"})
    append_audit(tmp_path, "audit/audit.jsonl", {"event": "one", "password": "x"})
    append_audit(tmp_path, "audit/audit.jsonl", {"event": "two"})
    assert verify_audit(tmp_path, "audit/audit.jsonl")
    assert "[REDACTED]" in (tmp_path / "audit/audit.jsonl").read_text()


def test_path_traversal_is_rejected(tmp_path):
    with pytest.raises(EvidenceError):
        write_json(tmp_path, "../escape.json", {})
