from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]

FindingType = Literal[
    "secret",
    "pii",
    "prompt_injection",
    "command_guard",
    "path",
    "semantic_leak",
    "output",
]

DecisionAction = Literal[
    "allow",
    "warn",
    "redact",
    "ask",
    "block",
    "quarantine",
]

SessionStatus = Literal[
    "created",
    "running",
    "blocked",
    "completed",
    "degraded",
    "error",
]

EgressMethod = Literal[
    "not-measured",
    "faraday-originated",
    "blocked-config",
    "measured-process",
    "os-isolation",
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ContextItem(BaseModel):
    """A unit of context that may be considered for agent use.

    Important:
        Do not store raw sensitive content here.
    """

    id: str
    source: str
    path: Optional[str] = None
    content_hash: Optional[str] = None
    size: Optional[int] = None
    classification: str = "unknown"


class Finding(BaseModel):
    """A scanner finding.

    Important:
        Do not store raw matched secrets in findings.
        Store rule, location, severity, and sanitized details only.
    """

    id: str
    type: FindingType
    severity: Severity
    source: str
    path: Optional[str] = None
    line: Optional[int] = None
    rule: str
    confidence: float = 1.0
    recommended_action: DecisionAction = "block"
    details: Optional[str] = None


class Decision(BaseModel):
    """A policy decision tied to findings and/or context items."""

    id: str
    finding_ids: List[str] = Field(default_factory=list)
    context_item_id: Optional[str] = None
    action: DecisionAction
    reason_codes: List[str] = Field(default_factory=list)
    policy_version: str
    timestamp: datetime = Field(default_factory=utcnow)


class RedactionRecord(BaseModel):
    """A record that a finding was replaced by a placeholder.

    Important:
        Do not store the original sensitive value.
    """

    id: str
    finding_id: str
    placeholder: str
    path: Optional[str] = None
    line: Optional[int] = None


class ModelEvent(BaseModel):
    """A local model/backend event."""

    backend_name: str
    device_name: str
    model_role: str
    status: str
    latency_ms: Optional[float] = None


class CommandEvent(BaseModel):
    """A proposed command inspected by the action guard."""

    command: str
    action: DecisionAction
    rule: Optional[str] = None
    reason: Optional[str] = None


class EgressObservation(BaseModel):
    """An explicit egress observation.

    This is intentionally labeled so the proof report does not overclaim.

    Methods:
        not-measured: No measurement was performed.
        faraday-originated: Faraday itself made no external requests.
        blocked-config: Configured policy blocked known/configured egress paths.
        measured-process: Process/network egress was measured.
        os-isolation: OS-level isolation was enforced and verified.
    """

    method: EgressMethod
    external_requests: int = 0
    bytes_sent: int = 0
    details: str = ""


class Session(BaseModel):
    """A Faraday Gate protected session.

    A session may represent:
        - a standalone scan
        - a redaction operation
        - a wrapped agent invocation
        - a dashboard/proof inspection session
    """

    id: str
    started_at: datetime = Field(default_factory=utcnow)
    ended_at: Optional[datetime] = None

    tool: str = "faraday"
    mode: str = "strict-local"
    policy_version: str = "default-v1"
    status: SessionStatus = "created"

    context_manifest: List[ContextItem] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    decisions: List[Decision] = Field(default_factory=list)
    redactions: List[RedactionRecord] = Field(default_factory=list)
    model_events: List[ModelEvent] = Field(default_factory=list)
    command_events: List[CommandEvent] = Field(default_factory=list)
    egress: List[EgressObservation] = Field(default_factory=list)

    files_scanned: int = 0
    prompt_tokens_scanned: int = 0

    output_hash: Optional[str] = None
    audit_head: Optional[str] = None

    def next_finding_id(self) -> str:
        return f"finding_{len(self.findings) + 1:03d}"

    def next_decision_id(self) -> str:
        return f"decision_{len(self.decisions) + 1:03d}"

    def next_redaction_id(self) -> str:
        return f"redaction_{len(self.redactions) + 1:03d}"

    def add_context_item(
        self,
        *,
        source: str,
        path: Optional[str] = None,
        content_hash: Optional[str] = None,
        size: Optional[int] = None,
        classification: str = "unknown",
    ) -> ContextItem:
        item = ContextItem(
            id=f"ctx_{len(self.context_manifest) + 1:03d}",
            source=source,
            path=path,
            content_hash=content_hash,
            size=size,
            classification=classification,
        )
        self.context_manifest.append(item)
        return item

    def add_finding(
        self,
        *,
        type: FindingType,
        severity: Severity,
        source: str,
        rule: str,
        path: Optional[str] = None,
        line: Optional[int] = None,
        confidence: float = 1.0,
        recommended_action: DecisionAction = "block",
        details: Optional[str] = None,
    ) -> Finding:
        finding = Finding(
            id=self.next_finding_id(),
            type=type,
            severity=severity,
            source=source,
            path=path,
            line=line,
            rule=rule,
            confidence=confidence,
            recommended_action=recommended_action,
            details=details,
        )
        self.findings.append(finding)
        return finding

    def add_decision(
        self,
        *,
        action: DecisionAction,
        reason_codes: List[str],
        finding_ids: Optional[List[str]] = None,
        context_item_id: Optional[str] = None,
    ) -> Decision:
        decision = Decision(
            id=self.next_decision_id(),
            finding_ids=finding_ids or [],
            context_item_id=context_item_id,
            action=action,
            reason_codes=reason_codes,
            policy_version=self.policy_version,
        )
        self.decisions.append(decision)
        return decision

    def add_redaction(
        self,
        *,
        finding_id: str,
        placeholder: str,
        path: Optional[str] = None,
        line: Optional[int] = None,
    ) -> RedactionRecord:
        record = RedactionRecord(
            id=self.next_redaction_id(),
            finding_id=finding_id,
            placeholder=placeholder,
            path=path,
            line=line,
        )
        self.redactions.append(record)
        return record

    def add_model_event(
        self,
        *,
        backend_name: str,
        device_name: str,
        model_role: str,
        status: str,
        latency_ms: Optional[float] = None,
    ) -> ModelEvent:
        event = ModelEvent(
            backend_name=backend_name,
            device_name=device_name,
            model_role=model_role,
            status=status,
            latency_ms=latency_ms,
        )
        self.model_events.append(event)
        return event

    def add_command_event(
        self,
        *,
        command: str,
        action: DecisionAction,
        rule: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> CommandEvent:
        event = CommandEvent(
            command=command,
            action=action,
            rule=rule,
            reason=reason,
        )
        self.command_events.append(event)
        return event

    def add_egress_observation(
        self,
        *,
        method: EgressMethod,
        external_requests: int = 0,
        bytes_sent: int = 0,
        details: str = "",
    ) -> EgressObservation:
        observation = EgressObservation(
            method=method,
            external_requests=external_requests,
            bytes_sent=bytes_sent,
            details=details,
        )
        self.egress.append(observation)
        return observation

    def finish(
        self,
        status: SessionStatus,
        output_text: Optional[str] = None,
        audit_head: Optional[str] = None,
    ) -> None:
        self.ended_at = utcnow()
        self.status = status

        if output_text is not None:
            self.output_hash = sha256_text(output_text)

        if audit_head is not None:
            self.audit_head = audit_head


def create_session(
    tool: str,
    mode: str,
    policy_version: str,
) -> Session:
    """Create a new Faraday session."""

    return Session(
        id=make_id("session"),
        tool=tool,
        mode=mode,
        policy_version=policy_version,
    )
