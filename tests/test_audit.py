import json

from faraday.core.audit import GENESIS_HASH, AuditChain


def test_audit_chain_append_and_verify(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    chain.append(
        session_id="session_test",
        event="session_started",
        metadata={"mode": "strict-local"},
    )

    chain.append(
        session_id="session_test",
        event="secret_blocked",
        metadata={"rule": "aws_access_key"},
    )

    ok, message, head = chain.verify()

    assert ok is True
    assert "2 audit events verified" in message
    assert head != GENESIS_HASH


def test_audit_chain_detects_tampering(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    chain.append(
        session_id="session_test",
        event="session_started",
        metadata={"mode": "strict-local"},
    )

    lines = chain.events_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["event"] = "tampered_event"
    lines[0] = json.dumps(payload)

    chain.events_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, message, head = chain.verify()

    assert ok is False


def test_audit_metadata_redacts_forbidden_keys(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    event = chain.append(
        session_id="session_test",
        event="secret_blocked",
        metadata={
            "rule": "aws_access_key",
            "matched": "AKIAFAKEEXAMPLE12345",
            "value": "super-secret-value",
        },
    )

    assert event.metadata["matched"] == "[REDACTED]"
    assert event.metadata["value"] == "[REDACTED]"
    assert event.metadata["rule"] == "aws_access_key"


def test_audit_detects_removed_middle_event(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    for index in range(3):
        chain.append(
            session_id="session_test",
            event=f"event_{index}",
            metadata={"index": index},
        )

    lines = chain.events_path.read_text(encoding="utf-8").splitlines()
    # Drop the middle event, keeping the tail so the chain is broken.
    chain.events_path.write_text(
        "\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8"
    )

    ok, message, head = chain.verify()

    assert ok is False
    assert "previous_hash" in message


def test_audit_tail_truncation_is_undetectable_by_chain_alone(tmp_path):
    """Documents a real limitation, not a bug.

    Removing events from the tail leaves a shorter but internally consistent
    chain, so verification still passes. Detecting truncation requires pinning
    the head hash outside the log (e.g. an anchored proof report).
    """

    chain = AuditChain(root=tmp_path / "audit")

    for index in range(3):
        chain.append(
            session_id="session_test",
            event=f"event_{index}",
            metadata={"index": index},
        )

    lines = chain.events_path.read_text(encoding="utf-8").splitlines()
    chain.events_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    ok, message, head = chain.verify()

    assert ok is True
    assert "2 audit events verified" in message


def test_audit_head_hash_cache_is_invalidated_on_append(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    first = chain.append(
        session_id="session_test",
        event="session_started",
        metadata={},
    )
    assert chain.head_hash() == first.hash

    second = chain.append(
        session_id="session_test",
        event="secret_blocked",
        metadata={},
    )

    assert second.previous_hash == first.hash
    assert chain.head_hash() == second.hash


def test_audit_export_writes_jsonl(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")
    chain.append(session_id="session_test", event="session_started", metadata={})

    destination = chain.export(tmp_path / "exported.jsonl")

    assert destination.exists()
    assert len(destination.read_text(encoding="utf-8").splitlines()) == 1


def test_audit_session_metadata_roundtrip(tmp_path):
    from faraday.core.session import create_session

    chain = AuditChain(root=tmp_path / "audit")
    session = create_session(tool="qwen-coder", mode="strict-local", policy_version="default-v1")
    session.add_finding(
        type="secret",
        severity="critical",
        source="file",
        rule="aws_access_key",
        path=".env.fake",
    )
    session.finish(status="completed")

    chain.save_session(session)
    rows = chain.load_sessions()

    assert len(rows) == 1
    assert rows[0]["id"] == session.id
    assert rows[0]["findings_count"] == 1
    assert rows[0]["status"] == "completed"
