from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

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
from faraday.core.policy import default_policy

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
    """Initialize Faraday Gate in the current repository.

    Creates:
        .faraday/config.yaml
        .faraday/policies/
        .faraday/audit/
        .faraday/cache/
        .faraday/reports/
    """

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

    try:
        policy = load_policy()
    except ConfigError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=2)

    if format == "json":
        typer.echo(policy.model_dump_json(indent=2))
    elif format == "yaml":
        yaml_text = yaml.safe_dump(
            policy.model_dump(),
            sort_keys=False,
            allow_unicode=True,
        )
        typer.echo(yaml_text)
    else:
        console.print("[red]Unsupported format. Use yaml or json.[/red]")
        raise typer.Exit(code=2)


@policy_app.command("validate")
def policy_validate() -> None:
    """Validate the active Faraday Gate policy.

    Exit codes:
        0 = valid
        2 = configuration/usage error
    """

    try:
        policy = load_policy()
    except ConfigError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=2)

    console.print("[green]Policy is valid.[/green]")
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
        typer.echo(json.dumps([event.model_dump() for event in events], default=str, indent=2))
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
    """Verify the SHA-256 audit hash chain.

    Exit codes:
        0 = valid
        3 = audit chain invalid or audit subsystem error
    """

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
        help="Destination file. Defaults to .faraday/reports/audit-export-<timestamp>.jsonl",
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
