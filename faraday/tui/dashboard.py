from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from faraday.config import config_path
from faraday.core.audit import AuditChain, AuditError
from faraday.core.policy import Policy


@dataclass
class DashboardReport:
    project: str
    mode: str
    egress_policy: str
    redaction_level: str
    policy_version: str
    config_path: str

    sessions_count: int
    latest_session: Optional[Dict[str, Any]]

    events_count: int
    audit_head: str
    audit_valid: Optional[bool]
    audit_message: str

    npu_status: str
    warnings: List[str] = field(default_factory=list)


def build_dashboard_report(
    policy: Policy,
    chain: AuditChain,
    verify_chain: bool = True,
) -> DashboardReport:
    """Build dashboard data from policy, SQLite sessions, and audit chain."""

    sessions = chain.load_sessions(limit=1)
    sessions_count = len(chain.load_sessions(limit=1000))

    latest_session = sessions[0] if sessions else None

    events_count = 0

    try:
        for _ in chain.iter_events():
            events_count += 1
    except AuditError as exc:
        return DashboardReport(
            project="faraday-gate",
            mode=policy.mode,
            egress_policy=policy.network.egress,
            redaction_level=policy.redaction.level,
            policy_version=policy.policy_version,
            config_path=str(config_path()),
            sessions_count=sessions_count,
            latest_session=latest_session,
            events_count=events_count,
            audit_head="",
            audit_valid=False,
            audit_message=str(exc),
            npu_status="not verified in MVP",
            warnings=["Audit chain could not be read."],
        )

    audit_valid: Optional[bool] = None
    audit_message = "verification skipped"
    audit_head = ""

    try:
        if verify_chain:
            audit_valid, audit_message, audit_head = chain.verify()
        else:
            audit_head = chain.head_hash()
            audit_message = "verification skipped"
    except AuditError as exc:
        audit_valid = False
        audit_message = str(exc)
        audit_head = ""

    warnings: List[str] = []

    if verify_chain and audit_valid is False:
        warnings.append("Audit chain is invalid or corrupted.")

    if events_count == 0:
        warnings.append("No audit events found.")

    return DashboardReport(
        project="faraday-gate",
        mode=policy.mode,
        egress_policy=policy.network.egress,
        redaction_level=policy.redaction.level,
        policy_version=policy.policy_version,
        config_path=str(config_path()),
        sessions_count=sessions_count,
        latest_session=latest_session,
        events_count=events_count,
        audit_head=audit_head,
        audit_valid=audit_valid,
        audit_message=audit_message,
        npu_status="not verified in MVP",
        warnings=warnings,
    )


def dashboard_to_dict(report: DashboardReport) -> Dict[str, Any]:
    """JSON-safe dashboard representation."""

    return asdict(report)


def format_dashboard_plain(report: DashboardReport) -> str:
    """Plain-text dashboard for accessibility and scripting."""

    lines = [
        "FARADAY GATE DASHBOARD",
        "======================",
        f"Mode: {report.mode}",
        f"Egress Policy: {report.egress_policy}",
        f"Redaction Level: {report.redaction_level}",
        f"Policy Version: {report.policy_version}",
        f"Config Path: {report.config_path}",
        f"NPU Status: {report.npu_status}",
        "",
        f"Sessions: {report.sessions_count}",
        f"Audit Events: {report.events_count}",
        f"Audit Head: {report.audit_head or '-'}",
        f"Audit Valid: {report.audit_valid if report.audit_valid is not None else 'unknown'}",
        f"Audit Message: {report.audit_message}",
    ]

    if report.latest_session:
        lines.extend(
            [
                "",
                "Latest Session:",
                f"  ID: {report.latest_session.get('id')}",
                f"  Tool: {report.latest_session.get('tool')}",
                f"  Status: {report.latest_session.get('status')}",
                f"  Findings: {report.latest_session.get('findings_count')}",
                f"  Redactions: {report.latest_session.get('redactions_count')}",
            ]
        )
    else:
        lines.extend(["", "Latest Session: none"])

    if report.warnings:
        lines.extend(["", "Warnings:"])

        for warning in report.warnings:
            lines.append(f"- {warning}")

    return "\n".join(lines)


def render_dashboard(console: Console, report: DashboardReport) -> None:
    """Render Rich dashboard.

    This is the MVP fallback dashboard. Textual may be added later.
    """

    if report.audit_valid is True:
        audit_status = "[SAFE] valid"
    elif report.audit_valid is False:
        audit_status = "[BLOCKED] invalid"
    else:
        audit_status = "[WARNING] unknown"

    console.print(
        Panel.fit(
            "[bold cyan]FARADAY GATE[/bold cyan]\nCLI-native AI agent firewall",
            border_style="cyan",
        )
    )

    table = Table(title="Current State")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Mode", report.mode)
    table.add_row("Egress Policy", report.egress_policy)
    table.add_row("Redaction Level", report.redaction_level)
    table.add_row("Policy Version", report.policy_version)
    table.add_row("Config Path", report.config_path)
    table.add_row("NPU Status", report.npu_status)
    table.add_row("Sessions", str(report.sessions_count))
    table.add_row("Audit Events", str(report.events_count))
    table.add_row("Audit Chain", audit_status)
    table.add_row("Audit Message", report.audit_message)
    table.add_row("Audit Head", report.audit_head or "-")

    console.print(table)

    if report.latest_session:
        session_table = Table(title="Latest Session")
        session_table.add_column("Key", style="cyan")
        session_table.add_column("Value", style="white")

        session_table.add_row("ID", str(report.latest_session.get("id")))
        session_table.add_row("Started At", str(report.latest_session.get("started_at")))
        session_table.add_row("Tool", str(report.latest_session.get("tool")))
        session_table.add_row("Mode", str(report.latest_session.get("mode")))
        session_table.add_row("Status", str(report.latest_session.get("status")))
        session_table.add_row(
            "Findings", str(report.latest_session.get("findings_count"))
        )
        session_table.add_row(
            "Redactions", str(report.latest_session.get("redactions_count"))
        )
        session_table.add_row(
            "Output Hash", str(report.latest_session.get("output_hash") or "-")
        )
        session_table.add_row(
            "Audit Head", str(report.latest_session.get("audit_head") or "-")
        )

        console.print(session_table)
    else:
        console.print("[yellow]No sessions found. Run a Faraday command first.[/yellow]")

    if report.warnings:
        warning_text = "\n".join(f"- {warning}" for warning in report.warnings)

        console.print(
            Panel(
                warning_text,
                title="[WARNING] Warnings",
                border_style="yellow",
            )
        )
