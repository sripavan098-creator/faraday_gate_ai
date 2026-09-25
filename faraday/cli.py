from __future__ import annotations

import typer
import yaml
from rich.console import Console

from faraday import __version__
from faraday.config import (
    ConfigError,
    config_path,
    default_policy_path,
    ensure_faraday_structure,
    load_policy,
    save_policy,
)
from faraday.core.policy import default_policy

app = typer.Typer(
    help="Faraday Gate: zero-egress AI agent firewall for AI coding agents.",
    no_args_is_help=True,
)

policy_app = typer.Typer(
    help="Manage Faraday Gate policy.",
    no_args_is_help=True,
)

app.add_typer(policy_app, name="policy")

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


if __name__ == "__main__":
    app()
