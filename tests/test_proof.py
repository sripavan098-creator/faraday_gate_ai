from faraday.core.audit import AuditChain
from faraday.core.proof import ProofError, build_proof, label_egress
from faraday.core.session import create_session


def _seed_session(chain):
    session = create_session(
        tool="wrap",
        mode="strict-local",
        policy_version="default-v1",
    )

    chain.append(
        session_id=session.id,
        event="session_started",
        metadata={"tool": session.tool},
    )

    chain.append(
        session_id=session.id,
        event="finding",
        metadata={
            "finding_type": "secret",
            "severity": "critical",
            "recommended_action": "block",
        },
    )

    chain.append(
        session_id=session.id,
        event="finding",
        metadata={
            "finding_type": "prompt_injection",
            "severity": "critical",
            "recommended_action": "block",
        },
    )

    chain.append(
        session_id=session.id,
        event="redaction",
        metadata={
            "finding_type": "pii",
            "placeholder": "[EMAIL_1]",
        },
    )

    chain.append(
        session_id=session.id,
        event="policy_decision",
        metadata={
            "status": "blocked",
            "mode": "strict-local",
            "egress_method": "faraday-originated",
            "files_scanned": 2,
            "prompt_tokens_scanned": 5,
        },
    )

    session.finish(status="blocked")
    session.audit_head = chain.head_hash()
    chain.save_session(session)

    return session


def test_build_proof_basic(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    session = _seed_session(chain)

    report = build_proof(chain, "latest")

    assert report.session_id == session.id
    assert report.secrets_blocked == 1
    assert report.injections_blocked == 1
    assert report.redactions_total == 1
    assert report.sensitive_redactions == 1
    assert report.files_scanned == 2
    assert report.prompt_tokens_scanned == 5
    assert report.audit_chain_valid is True


def test_build_proof_includes_limitations(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")
    _seed_session(chain)

    report = build_proof(chain, "latest")

    assert report.limitations
    assert any("network isolation" in item for item in report.limitations)


def test_build_proof_egress_label(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")
    _seed_session(chain)

    report = build_proof(chain, "latest")

    assert report.egress_method == "faraday-originated"
    assert "No Faraday-originated" in report.egress_label


def test_build_proof_no_sessions_raises(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    try:
        build_proof(chain, "latest")
    except ProofError as exc:
        assert "No Faraday sessions" in str(exc)
    else:
        raise AssertionError("expected ProofError")


def test_build_proof_unknown_session_raises(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")
    _seed_session(chain)

    try:
        build_proof(chain, "session_does_not_exist")
    except ProofError as exc:
        assert "Session not found" in str(exc)
    else:
        raise AssertionError("expected ProofError")


def test_build_proof_counts_path_and_command_blocks(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    session = create_session(
        tool="wrap",
        mode="strict-local",
        policy_version="default-v1",
    )

    chain.append(
        session_id=session.id,
        event="finding",
        metadata={
            "finding_type": "path",
            "severity": "critical",
            "recommended_action": "block",
        },
    )

    chain.append(
        session_id=session.id,
        event="finding",
        metadata={
            "finding_type": "command_guard",
            "severity": "high",
            "recommended_action": "block",
        },
    )

    session.finish(status="blocked")
    session.audit_head = chain.head_hash()
    chain.save_session(session)

    report = build_proof(chain, "latest")

    assert report.path_blocks == 1
    assert report.command_guard_blocks == 1


def test_build_proof_reports_model_events(tmp_path):
    chain = AuditChain(root=tmp_path / "audit")

    session = create_session(
        tool="wrap",
        mode="strict-local",
        policy_version="default-v1",
    )

    chain.append(
        session_id=session.id,
        event="model_event",
        metadata={
            "backend_name": "faraday-mock-coder",
            "device_name": "local",
            "model_role": "coder",
            "status": "simulated",
        },
    )

    session.finish(status="completed")
    session.audit_head = chain.head_hash()
    chain.save_session(session)

    report = build_proof(chain, "latest")

    assert any("faraday-mock-coder" in backend for backend in report.model_backends)
    assert any("simulated" in item for item in report.limitations)


def test_label_egress_unknown_method():
    label, details = label_egress("something-else")

    assert "not recorded" in label
    assert details


def test_proof_is_json_serializable(tmp_path):
    import json

    from faraday.core.proof import proof_to_dict

    chain = AuditChain(root=tmp_path / "audit")
    _seed_session(chain)

    report = build_proof(chain, "latest")

    payload = json.dumps(proof_to_dict(report), default=str)

    assert "session_id" in payload
