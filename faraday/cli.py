from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import typer
import yaml
from rich.console import Console
from rich.table import Table

from faraday import __version__
from faraday.config import (
    ConfigError,
    config_path,
    default_policy_path,
    ensure_faraday_structure,
    load_policy,
    save_policy,
)
from faraday.core.audit import AuditChain, AuditError
from faraday.core.flow import (
    add_scan_findings,
    append_findings,
    append_redactions,
    append_session_started,
    create_session_for_policy,
    finalize_session,
)
from faraday.core.policy import default_policy
from faraday.redactor import redact_text
from faraday.scanners.base import ScanFinding
from faraday.scanners.files import read_git_diff, scan_path
from faraday.scanners.path_rules import scan_path_denial
from faraday.scanners.pipeline import scan_text

app = typer.Typer(
    help="Faraday Gate: zero-egress AI agent firewall for AI coding agents.",
    no_args_is_help=True,
)

policy_app = typer.Typer(
    help="Manage Faraday Gate policy.",
    no_args_is_help=True,
)

audit_app = typer.Typer(
    help="Inspect the Faraday Gate audit trail.",
    no_args_is_help=True,
)

app.add_typer(policy_app, name="policy")
app.add_typer(audit_app, name="audit")

console = Console()


def severity_color(severity: str) -> str:
    return {
        "critical": "red",
        "high": "magenta",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }.get(severity, "white")


def finding_payload(finding: ScanFinding) -> dict:
    """Serializable finding payload. Never includes raw matched text."""

    return {
        "type": finding.type,
        "severity": finding.severity,
        "scanner": finding.scanner,
        "origin": finding.origin,
        "path": finding.path,
        "line": finding.line,
        "rule": finding.rule,
        "confidence": finding.confidence,
        "recommended_action": finding.recommended_action,
        "details": finding.details,
    }


def output_findings(findings: List[ScanFinding], fmt: str) -> None:
    """Output scanner findings in table, plain, or JSON format."""

    if fmt == "json":
        typer.echo(
            json.dumps([finding_payload(finding) for finding in findings], indent=2)
        )
        return

    if fmt == "plain":
        for finding in findings:
            location = finding.path or finding.origin

            typer.echo(
                f"[{finding.severity.upper()}] "
                f"type={finding.type} "
                f"rule={finding.rule} "
                f"location={location}:{finding.line or '-'} "
                f"action={finding.recommended_action}"
            )

        return

    if fmt != "table":
        console.print("[red]Unsupported format. Use table, plain, or json.[/red]")
        raise typer.Exit(code=2)

    table = Table(title="Faraday Findings")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Location")
    table.add_column("Line")
    table.add_column("Rule")
    table.add_column("Action")
    table.add_column("Details")

    for finding in findings:
        location = finding.path or finding.origin
        color = severity_color(finding.severity)

        table.add_row(
            f"[{color}]{finding.severity}[/{color}]",
            finding.type,
            location,
            str(finding.line or "-"),
            finding.rule,
            finding.recommended_action,
            finding.details or "-",
        )

    console.print(table)


def dependency_status(
    module_name: str,
    package_name: Optional[str] = None,
) -> Tuple[bool, str]:
    """Return dependency availability and version if possible."""

    try:
        spec = importlib.util.find_spec(module_name)
    except Exception as exc:
        return False, str(exc)

    if spec is None:
        return False, "not installed"

    package = package_name or module_name

    try:
        version = importlib.metadata.version(package)
        return True, version
    except Exception:
        return True, "installed, version unknown"


def detect_npu() -> Tuple[bool, str]:
    """MVP NPU detection placeholder.

    No NPU acceleration is claimed unless a later benchmark/diagnostic path
    verifies it.
    """

    return False, "not verified in MVP"


def require_policy():
    """Load policy or exit 2 (fail closed)."""

    try:
        return load_policy()
    except ConfigError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=2)


@app.callback()
def main() -> None:
    """Faraday Gate: zero-egress AI agent firewall for AI coding agents."""


@app.command()
def version() -> None:
    """Show Faraday Gate version."""

    console.print(f"faraday-gate {__version__}")


@app.command()
def init(
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing .faraday/config.yaml if present.",
    )
) -> None:
    """Initialize Faraday Gate in the current repository."""

    root = ensure_faraday_structure()
    target_config = config_path()
    target_default_policy = default_policy_path()

    if target_config.exists() and not force:
        console.print(f"[yellow]Faraday config already exists:[/yellow] {target_config}")
        console.print("Use [bold]--force[/bold] to overwrite.")
        raise typer.Exit(code=2)

    policy = default_policy()
    save_policy(policy, target_config)

    if force or not target_default_policy.exists():
        save_policy(policy, target_default_policy)

    console.print("[green]Faraday Gate initialized.[/green]")
    console.print(f"Root: {root}")
    console.print(f"Config: {target_config}")
    console.print(f"Default policy: {target_default_policy}")


@app.command()
def doctor() -> None:
    """Check Faraday Gate environment and dependencies."""

    table = Table(title="Faraday Doctor")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    def add_row(check: str, ok: bool, details: str = "") -> None:
        status = "[SAFE] OK" if ok else "[WARNING] FAIL"
        table.add_row(check, status, details)

    add_row("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])

    add_row("Config exists", config_path().exists(), str(config_path()))

    try:
        policy = load_policy()
        add_row("Config loads", True, f"mode={policy.mode}")
    except ConfigError as exc:
        add_row("Config loads", False, str(exc))

    add_row(
        "Audit directory",
        (Path.cwd() / ".faraday" / "audit").exists(),
        ".faraday/audit",
    )

    core_dependencies = [
        ("typer", "typer"),
        ("rich", "rich"),
        ("yaml", "PyYAML"),
        ("pydantic", "pydantic"),
    ]

    for module_name, package_name in core_dependencies:
        ok, details = dependency_status(module_name, package_name)
        add_row(f"Dependency: {module_name}", ok, details)

    optional_dependencies = [
        ("textual", "textual"),
        ("tree_sitter", "tree-sitter"),
        ("onnxruntime", "onnxruntime"),
        ("llama_cpp", "llama-cpp-python"),
        ("qai_hub", "qai-hub"),
    ]

    for module_name, package_name in optional_dependencies:
        ok, details = dependency_status(module_name, package_name)
        add_row(f"Optional: {module_name}", ok, details)

    for tool in ("git", "qwen-coder", "openhands"):
        path = shutil.which(tool)
        add_row(f"Tool: {tool}", path is not None, path or "not found")

    npu_ok, npu_details = detect_npu()
    add_row("Snapdragon NPU", npu_ok, npu_details)

    console.print(table)


@app.command()
def scan(
    path: str = typer.Argument(
        ".",
        help="File or directory to scan.",
    ),
    prompt: Optional[str] = typer.Option(
        None,
        "--prompt",
        "-p",
        help="Scan prompt text instead of filesystem paths.",
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Scan the working-tree git diff.",
    ),
    diff_ref: Optional[str] = typer.Option(
        None,
        "--diff-ref",
        help="Scan the git diff against a ref, for example: --diff-ref HEAD.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, plain, or json.",
    ),
    max_files: int = typer.Option(
        500,
        "--max-files",
        help="Maximum number of files to scan.",
    ),
    max_file_bytes: int = typer.Option(
        1_000_000,
        "--max-file-bytes",
        help="Maximum file size in bytes to scan.",
    ),
) -> None:
    """Scan a file, directory, prompt, or git diff.

    Exit codes:
        0 = completed without blocking findings
        1 = blocking findings detected
        2 = configuration/usage error
        3 = internal security subsystem error
    """

    if prompt is not None and (diff or diff_ref is not None):
        console.print("[red]Use only one of --prompt, --diff, or --diff-ref.[/red]")
        raise typer.Exit(code=2)

    scan_diff = diff or diff_ref is not None

    if scan_diff and path != ".":
        console.print(
            "[red]Provide either a path or a diff, not both.[/red]"
        )
        raise typer.Exit(code=2)

    policy = require_policy()

    chain = AuditChain()
    session = create_session_for_policy(policy, "scan")
    append_session_started(chain, session)

    findings: List[ScanFinding] = []
    files_scanned = 0
    tokens_scanned = 0

    if prompt is not None:
        tokens_scanned = len(prompt.split())
        findings = scan_text(prompt, origin="prompt", policy=policy)

    elif scan_diff:
        try:
            diff_text = read_git_diff(diff_ref)
        except Exception as exc:
            console.print(f"[red]Git diff error:[/red] {exc}")
            raise typer.Exit(code=2)

        tokens_scanned = len(diff_text.split())
        findings = scan_text(diff_text, origin="git-diff", policy=policy)

    else:
        target = Path(path)

        if not target.exists():
            console.print(f"[red]Path does not exist: {path}[/red]")
            raise typer.Exit(code=2)

        try:
            result = scan_path(
                target,
                policy,
                max_files=max_files,
                max_file_bytes=max_file_bytes,
            )
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2)
        except Exception as exc:
            console.print(f"[red]Scan error:[/red] {exc}")
            raise typer.Exit(code=3)

        findings = result.findings
        files_scanned = result.files_scanned
        tokens_scanned = result.tokens_scanned

        for scanned_file in result.scanned_files:
            session.add_context_item(
                source="repository",
                path=scanned_file.path,
                content_hash=scanned_file.content_hash,
                size=scanned_file.size,
                classification=scanned_file.classification,
            )

    session.files_scanned = files_scanned
    session.prompt_tokens_scanned = tokens_scanned

    add_scan_findings(session, findings)
    append_findings(chain, session, findings)

    blocked = [
        finding for finding in findings if finding.recommended_action == "block"
    ]

    status = "blocked" if blocked else "completed"
    finalize_session(chain, session, status=status)

    output_findings(findings, format)

    if format != "json":
        console.print(
            f"Files scanned: {files_scanned} | "
            f"Tokens scanned: {tokens_scanned} | "
            f"Findings: {len(findings)} | "
            f"Blocking: {len(blocked)}"
        )

    if blocked:
        if format != "json":
            console.print("[BLOCKED] Blocking findings detected.")
        raise typer.Exit(code=1)


@app.command()
def redact(
    file: Optional[str] = typer.Argument(
        None,
        help="File to redact.",
    ),
    prompt: Optional[str] = typer.Option(
        None,
        "--prompt",
        "-p",
        help="Redact prompt text.",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text or json.",
    ),
    mode: str = typer.Option(
        "sensitive",
        "--mode",
        "-m",
        help="Redaction mode: default, sensitive, or all.",
    ),
) -> None:
    """Redact sensitive content from a file, prompt, or stdin.

    Exit codes:
        0 = redaction completed safely
        1 = blocked by security findings
        2 = configuration/usage error
        3 = internal security subsystem error
    """

    policy = require_policy()

    chain = AuditChain()
    session = create_session_for_policy(policy, "redact")
    append_session_started(chain, session)

    text: str
    origin: str
    path_value: Optional[str] = None

    if prompt is not None:
        text = prompt
        origin = "prompt"

    elif file:
        target = Path(file)

        if not target.exists():
            console.print(f"[red]File does not exist: {file}[/red]")
            raise typer.Exit(code=2)

        denial = scan_path_denial(target, policy.paths.deny)

        if denial is not None:
            findings = [denial]
            add_scan_findings(session, findings)
            append_findings(chain, session, findings)
            finalize_session(chain, session, status="blocked")

            console.print("[BLOCKED] Path denied by policy.")
            console.print(f"Path: {target}")
            raise typer.Exit(code=1)

        try:
            text = target.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            console.print(f"[red]Could not read file:[/red] {exc}")
            raise typer.Exit(code=2)

        origin = str(target)
        path_value = str(target)

    elif not sys.stdin.isatty():
        text = sys.stdin.read()
        origin = "stdin"

    else:
        console.print("[red]Provide a file, --prompt, or pipe stdin.[/red]")
        raise typer.Exit(code=2)

    findings = scan_text(
        text,
        origin=origin,
        path=path_value,
        policy=policy,
    )

    add_scan_findings(session, findings)
    append_findings(chain, session, findings)

    try:
        result = redact_text(text, findings, mode=mode)
    except ValueError as exc:
        console.print(f"[red]Redaction error:[/red] {exc}")
        raise typer.Exit(code=2)

    for record in result.records:
        finding_id = "unknown"

        for session_finding in session.findings:
            if (
                session_finding.rule == record.rule
                and session_finding.line == record.line
                and (
                    session_finding.path == record.path
                    or session_finding.source == record.origin
                )
            ):
                finding_id = session_finding.id
                break

        session.add_redaction(
            finding_id=finding_id,
            placeholder=record.placeholder,
            path=record.path,
            line=record.line,
        )

    append_redactions(chain, session, result.records)

    if result.blocked:
        finalize_session(chain, session, status="blocked")

        if format == "json":
            typer.echo(
                json.dumps(
                    {"status": "blocked", "blocked_count": len(result.blocked)},
                    indent=2,
                )
            )
        else:
            console.print("[BLOCKED] Redaction blocked due to security findings.")

        raise typer.Exit(code=1)

    finalize_session(
        chain,
        session,
        status="completed",
        output_text=result.redacted_text,
    )

    if format == "json":
        typer.echo(
            json.dumps(
                {
                    "status": "completed",
                    "redacted_text": result.redacted_text,
                    "replacements_count": result.replacements_count,
                    "records": [
                        {
                            "placeholder": record.placeholder,
                            "finding_type": record.finding_type,
                            "rule": record.rule,
                            "origin": record.origin,
                            "path": record.path,
                            "line": record.line,
                        }
                        for record in result.records
                    ],
                },
                indent=2,
            )
        )
    else:
        typer.echo(result.redacted_text)


@policy_app.command("show")
def policy_show(
    format: str = typer.Option(
        "yaml",
        "--format",
        "-f",
        help="Output format: yaml or json.",
    )
) -> None:
    """Show the active Faraday Gate policy."""

    policy = require_policy()

    if format == "json":
        typer.echo(policy.model_dump_json(indent=2))
    elif format == "yaml":
        typer.echo(
            yaml.safe_dump(policy.model_dump(), sort_keys=False, allow_unicode=True)
        )
    else:
        console.print("[red]Unsupported format. Use yaml or json.[/red]")
        raise typer.Exit(code=2)


@policy_app.command("validate")
def policy_validate() -> None:
    """Validate the active Faraday Gate policy."""

    policy = require_policy()

    console.print("[SAFE] Policy is valid.")
    console.print(f"Policy version: {policy.policy_version}")
    console.print(f"Mode: {policy.mode}")
    console.print(f"Egress: {policy.network.egress}")
    console.print(f"Secret action: {policy.secrets.action}")
    console.print(f"PII action: {policy.pii.action}")
    console.print(f"Injection action: {policy.prompt_injection.action}")
    console.print(f"Command action: {policy.commands.action}")


@policy_app.command("path")
def policy_path() -> None:
    """Print the active config path."""

    typer.echo(str(config_path()))


@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Number of recent events to show.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, plain, or json.",
    ),
) -> None:
    """Show recent audit events."""

    chain = AuditChain()

    try:
        events = list(chain.iter_events())
    except AuditError as exc:
        console.print(f"[red]Audit error:[/red] {exc}")
        raise typer.Exit(code=3)

    if not events:
        console.print("[yellow]No audit events found.[/yellow]")
        return

    events = events[-limit:]

    if format == "json":
        typer.echo(
            json.dumps([event.model_dump() for event in events], default=str, indent=2)
        )
        return

    if format == "plain":
        for event in events:
            typer.echo(
                f"[EVENT] {event.event} | "
                f"id={event.event_id} | "
                f"session={event.session_id} | "
                f"time={event.timestamp}"
            )
        return

    if format != "table":
        console.print("[red]Unsupported format. Use table, plain, or json.[/red]")
        raise typer.Exit(code=2)

    table = Table(title="Faraday Audit Events")
    table.add_column("Event ID", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Session")
    table.add_column("Event")
    table.add_column("Metadata")

    for event in events:
        metadata_text = json.dumps(event.metadata, default=str)

        if len(metadata_text) > 80:
            metadata_text = metadata_text[:77] + "..."

        table.add_row(
            event.event_id,
            event.timestamp,
            event.session_id,
            event.event,
            metadata_text,
        )

    console.print(table)


@audit_app.command("verify")
def audit_verify() -> None:
    """Verify the SHA-256 audit hash chain."""

    chain = AuditChain()

    try:
        ok, message, head = chain.verify()
    except AuditError as exc:
        console.print(f"[red]Audit error:[/red] {exc}")
        raise typer.Exit(code=3)

    if ok:
        console.print(f"[SAFE] {message}")
        console.print(f"Head: {head}")
        return

    console.print(f"[BLOCKED] {message}")
    raise typer.Exit(code=3)


@audit_app.command("export")
def audit_export(
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Destination file.",
    )
) -> None:
    """Export the JSONL audit trail."""

    chain = AuditChain()

    try:
        destination = chain.export(out)
    except AuditError as exc:
        console.print(f"[red]Audit export failed:[/red] {exc}")
        raise typer.Exit(code=2)

    console.print(f"Exported audit trail to: {destination}")


if __name__ == "__main__":
    app()
