from __future__ import annotations

from typing import List, Optional

from faraday.core.audit import AuditChain
from faraday.core.policy import Policy
from faraday.core.session import Session, SessionStatus, create_session
from faraday.redactor.text_redactor import RedactionRecord
from faraday.scanners.base import ScanFinding, finding_to_session_kwargs


def create_session_for_policy(policy: Policy, tool: str) -> Session:
    """Create a session from the active policy."""

    return create_session(
        tool=tool,
        mode=policy.mode,
        policy_version=policy.policy_version,
    )


def append_session_started(chain: AuditChain, session: Session) -> None:
    """Record the session start event."""

    chain.append(
        session_id=session.id,
        event="session_started",
        metadata={
            "tool": session.tool,
            "mode": session.mode,
            "policy_version": session.policy_version,
        },
    )


def add_scan_findings(session: Session, findings: List[ScanFinding]) -> None:
    """Add scanner findings to the session.

    Important:
        This uses finding_to_session_kwargs(), which excludes internal
        span/matched data.
    """

    for finding in findings:
        session.add_finding(**finding_to_session_kwargs(finding))


def append_findings(
    chain: AuditChain,
    session: Session,
    findings: List[ScanFinding],
) -> None:
    """Append finding events to the audit chain.

    Security rule:
        No raw matched content is written to audit metadata.
    """

    for finding in findings:
        chain.append(
            session_id=session.id,
            event="finding",
            metadata={
                "finding_type": finding.type,
                "severity": finding.severity,
                "rule": finding.rule,
                "origin": finding.origin,
                "path": finding.path,
                "line": finding.line,
                "recommended_action": finding.recommended_action,
            },
        )


def append_redactions(
    chain: AuditChain,
    session: Session,
    records: List[RedactionRecord],
) -> None:
    """Append redaction events to the audit chain.

    Security rule:
        Only placeholders and finding metadata are stored.
    """

    for record in records:
        chain.append(
            session_id=session.id,
            event="redaction",
            metadata={
                "placeholder": record.placeholder,
                "finding_type": record.finding_type,
                "rule": record.rule,
                "origin": record.origin,
                "path": record.path,
                "line": record.line,
            },
        )


def finalize_session(
    chain: AuditChain,
    session: Session,
    status: SessionStatus,
    output_text: Optional[str] = None,
) -> None:
    """Finish a session, append final events, and store session metadata.

    This also persists model events and command events.

    The session audit head is set after the final audit event so the stored
    session points at the latest chain head.
    """

    session.finish(
        status=status,
        output_text=output_text,
    )

    for model_event in session.model_events:
        chain.append(
            session_id=session.id,
            event="model_event",
            metadata={
                "backend_name": model_event.backend_name,
                "device_name": model_event.device_name,
                "model_role": model_event.model_role,
                "status": model_event.status,
                "latency_ms": model_event.latency_ms,
            },
        )

    for command_event in session.command_events:
        chain.append(
            session_id=session.id,
            event="command_event",
            metadata={
                "command": command_event.command,
                "action": command_event.action,
                "rule": command_event.rule,
                "reason": command_event.reason,
            },
        )

    chain.append(
        session_id=session.id,
        event="session_finished",
        metadata={
            "status": status,
            "findings": len(session.findings),
            "decisions": len(session.decisions),
            "redactions": len(session.redactions),
        },
    )

    session.audit_head = chain.head_hash()
    chain.save_session(session)
