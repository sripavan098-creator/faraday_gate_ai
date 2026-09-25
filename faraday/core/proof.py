from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from faraday.core.audit import AuditChain, AuditError


class ProofError(Exception):
    """Raised when a proof report cannot be generated."""


BLOCK_ACTIONS = {"block", "quarantine"}


@dataclass
class ProofReport:
    session_id: str
    started_at: Optional[str]
    tool: str
    mode: str
    policy_version: str
    status: str

    files_scanned: int
    prompt_tokens_scanned: int

    findings_total: int
    secrets_blocked: int
    injections_blocked: int
    command_guard_blocks: int
    path_blocks: int

    redactions_total: int
    sensitive_redactions: int

    model_backends: List[str] = field(default_factory=list)

    egress_method: str = "not-recorded"
    egress_label: str = ""
    egress_details: str = ""

    audit_chain_valid: bool = False
    audit_message: str = ""
    audit_head: str = ""

    output_hash: Optional[str] = None

    limitations: List[str] = field(default_factory=list)


def label_egress(method: str) -> Tuple[str, str]:
    """Return a human-readable egress label and details.

    This follows the "no security theater" rule.
    """

    if method == "faraday-originated":
        return (
            "No Faraday-originated external requests observed",
            "Application-level observation only. "
            "This does not prove OS-level network isolation.",
        )

    if method == "not-measured":
        return (
            "Egress not measured",
            "External process execution occurred or was requested. "
            "Faraday did not measure process/network egress in this MVP.",
        )

    if method == "blocked-config":
        return (
            "Configured egress controls blocked known egress paths",
            "Policy/config-level blocking was applied. "
            "OS-level isolation may not have been verified.",
        )

    if method == "measured-process":
        return (
            "Process egress measured",
            "Process/network egress was measured by the implementation.",
        )

    if method == "os-isolation":
        return (
            "OS-level isolation enforced",
            "An OS-level isolation boundary was enforced and verified.",
        )

    return (
        "Egress status not recorded",
        "No egress observation was recorded for this session.",
    )


def build_proof(chain: AuditChain, session_id: str = "latest") -> ProofReport:
    """Build a proof report from SQLite session metadata and JSONL audit events."""

    sessions = chain.load_sessions(limit=200)

    if not sessions:
        raise ProofError("No Faraday sessions found. Run a Faraday command first.")

    if session_id == "latest":
        row = sessions[0]
    else:
        row = next((s for s in sessions if s["id"] == session_id), None)

        if row is None:
            raise ProofError(f"Session not found: {session_id}")

    sid = str(row["id"])

    try:
        audit_ok, audit_message, audit_head = chain.verify()
    except AuditError as exc:
        raise ProofError(f"Audit verification failed: {exc}") from exc

    mode = str(row.get("mode") or "unknown")
    policy_version = str(row.get("policy_version") or "unknown")
    status = str(row.get("status") or "unknown")
    tool = str(row.get("tool") or "unknown")
    started_at = row.get("started_at")
    output_hash = row.get("output_hash")

    files_scanned = int(row.get("files_scanned") or 0)
    prompt_tokens_scanned = int(row.get("prompt_tokens_scanned") or 0)
    egress_method = "not-recorded"

    findings_total = 0
    secrets_blocked = 0
    injections_blocked = 0
    command_guard_blocks = 0
    path_blocks = 0

    redactions_total = 0
    sensitive_redactions = 0

    model_backends: List[str] = []

    for event in chain.iter_events():
        if event.session_id != sid:
            continue

        metadata: Dict[str, Any] = event.metadata or {}

        if event.event == "finding":
            findings_total += 1

            finding_type = metadata.get("finding_type")
            action = metadata.get("recommended_action") or metadata.get("action")

            if finding_type == "secret" and action in BLOCK_ACTIONS:
                secrets_blocked += 1

            if finding_type == "prompt_injection" and action in BLOCK_ACTIONS:
                injections_blocked += 1

            if finding_type == "command_guard" and action in BLOCK_ACTIONS:
                command_guard_blocks += 1

            if finding_type == "path" and action in BLOCK_ACTIONS:
                path_blocks += 1

        elif event.event == "redaction":
            redactions_total += 1

            if metadata.get("finding_type") == "pii":
                sensitive_redactions += 1

        elif event.event == "policy_decision":
            if metadata.get("mode"):
                mode = str(metadata["mode"])

            if metadata.get("status"):
                status = str(metadata["status"])

            if metadata.get("egress_method"):
                egress_method = str(metadata["egress_method"])

            if metadata.get("files_scanned") is not None:
                files_scanned = int(metadata["files_scanned"])

            if metadata.get("prompt_tokens_scanned") is not None:
                prompt_tokens_scanned = int(metadata["prompt_tokens_scanned"])

        elif event.event == "model_event":
            backend_name = str(metadata.get("backend_name") or "unknown")
            device_name = str(metadata.get("device_name") or "unknown")
            model_role = str(metadata.get("model_role") or "")
            model_status = str(metadata.get("status") or "")

            if model_role:
                label = f"{backend_name} ({device_name}, {model_role}, {model_status})"
            else:
                label = f"{backend_name} ({device_name}, {model_status})"

            if label not in model_backends:
                model_backends.append(label)

    if not model_backends:
        if tool in {"wrap", "qwen-coder", "openhands", "generic"}:
            model_backends.append("faraday-mock-coder (simulated, inferred)")
        else:
            model_backends.append("none recorded")

    egress_label, egress_details = label_egress(egress_method)

    limitations: List[str] = []

    if any("simulated" in backend for backend in model_backends):
        limitations.append(
            "Local model activity may be simulated in this MVP unless a real "
            "backend is recorded."
        )

    if egress_method == "faraday-originated":
        limitations.append(
            "Egress status means no Faraday-originated external requests were "
            "observed. It does not prove OS-level network isolation."
        )
    elif egress_method == "not-measured":
        limitations.append(
            "Egress was not measured. Do not interpret this session as verified "
            "zero-egress."
        )
    elif egress_method == "not-recorded":
        limitations.append("No egress observation was recorded for this session.")

    limitations.append(
        "Detection is defense-in-depth and not a guarantee of perfect secret or "
        "injection detection."
    )

    limitations.append("The audit chain is local-only and is not remotely anchored.")

    if not audit_ok:
        limitations.append("Audit chain verification failed for this trail.")

    return ProofReport(
        session_id=sid,
        started_at=started_at,
        tool=tool,
        mode=mode,
        policy_version=policy_version,
        status=status,
        files_scanned=files_scanned,
        prompt_tokens_scanned=prompt_tokens_scanned,
        findings_total=findings_total,
        secrets_blocked=secrets_blocked,
        injections_blocked=injections_blocked,
        command_guard_blocks=command_guard_blocks,
        path_blocks=path_blocks,
        redactions_total=redactions_total,
        sensitive_redactions=sensitive_redactions,
        model_backends=model_backends,
        egress_method=egress_method,
        egress_label=egress_label,
        egress_details=egress_details,
        audit_chain_valid=audit_ok,
        audit_message=audit_message,
        audit_head=audit_head,
        output_hash=output_hash,
        limitations=limitations,
    )


def proof_to_dict(report: ProofReport) -> Dict[str, Any]:
    """Convert proof report to JSON-safe dictionary."""

    return asdict(report)


def format_proof_plain(report: ProofReport) -> str:
    """Plain-text proof report for accessibility and scripting."""

    lines = [
        "FARADAY GATE PROOF REPORT",
        "=========================",
        f"Session ID: {report.session_id}",
        f"Started At: {report.started_at or '-'}",
        f"Tool: {report.tool}",
        f"Mode: {report.mode}",
        f"Policy Version: {report.policy_version}",
        f"Status: {report.status}",
        "",
        f"Files Scanned: {report.files_scanned}",
        f"Prompt Tokens Scanned: {report.prompt_tokens_scanned}",
        "",
        f"Findings Total: {report.findings_total}",
        f"Secrets Blocked: {report.secrets_blocked}",
        f"Injections Blocked: {report.injections_blocked}",
        f"Command Guard Blocks: {report.command_guard_blocks}",
        f"Path Blocks: {report.path_blocks}",
        "",
        f"Redactions Total: {report.redactions_total}",
        f"Sensitive Redactions: {report.sensitive_redactions}",
        "",
        "Model Backends:",
    ]

    if report.model_backends:
        for backend in report.model_backends:
            lines.append(f"- {backend}")
    else:
        lines.append("- none recorded")

    lines.extend(
        [
            "",
            f"Egress Method: {report.egress_method}",
            f"Egress Label: {report.egress_label}",
            f"Egress Details: {report.egress_details}",
            "",
            f"Audit Chain Valid: {report.audit_chain_valid}",
            f"Audit Message: {report.audit_message}",
            f"Audit Head: {report.audit_head}",
            f"Output Hash: {report.output_hash or '-'}",
            "",
            "Limitations:",
        ]
    )

    for limitation in report.limitations:
        lines.append(f"- {limitation}")

    return "\n".join(lines)


def render_proof(console: Console, report: ProofReport) -> None:
    """Render rich table proof report.

    Accessibility: uses explicit labels such as [SAFE] and [BLOCKED].
    """

    console.print(
        Panel.fit(
            "[bold cyan]FARADAY GATE PROOF REPORT[/bold cyan]",
            border_style="cyan",
        )
    )

    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Session ID", report.session_id)
    table.add_row("Started At", report.started_at or "-")
    table.add_row("Tool", report.tool)
    table.add_row("Mode", report.mode)
    table.add_row("Policy Version", report.policy_version)
    table.add_row("Status", report.status)
    table.add_row("Files Scanned", str(report.files_scanned))
    table.add_row("Prompt Tokens Scanned", str(report.prompt_tokens_scanned))
    table.add_row("Findings Total", str(report.findings_total))
    table.add_row("Secrets Blocked", str(report.secrets_blocked))
    table.add_row("Injections Blocked", str(report.injections_blocked))
    table.add_row("Command Guard Blocks", str(report.command_guard_blocks))
    table.add_row("Path Blocks", str(report.path_blocks))
    table.add_row("Redactions Total", str(report.redactions_total))
    table.add_row("Sensitive Redactions", str(report.sensitive_redactions))
    table.add_row("Model Backends", "\n".join(report.model_backends) or "none recorded")
    table.add_row("Egress Method", report.egress_method)
    table.add_row("Egress Label", report.egress_label)
    table.add_row("Egress Details", report.egress_details)

    if report.audit_chain_valid:
        table.add_row("Audit Chain", "[SAFE] valid")
    else:
        table.add_row("Audit Chain", "[BLOCKED] invalid")

    table.add_row("Audit Message", report.audit_message)
    table.add_row("Audit Head", report.audit_head)
    table.add_row("Output Hash", report.output_hash or "-")

    console.print(table)

    if report.limitations:
        limitations_text = "\n".join(
            f"- {limitation}" for limitation in report.limitations
        )

        console.print(
            Panel(
                limitations_text,
                title="Limitations",
                border_style="yellow",
            )
        )
