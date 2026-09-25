from __future__ import annotations

import typer
from rich.console import Console

from faraday import __version__

app = typer.Typer(
    help="Faraday Gate: zero-egress AI agent firewall for AI coding agents.",
    no_args_is_help=True,
)

console = Console()


@app.callback()
def main() -> None:
    """Faraday Gate: zero-egress AI agent firewall for AI coding agents."""


@app.command()
def version() -> None:
    """Show Faraday Gate version."""
    console.print(f"faraday-gate {__version__}")


if __name__ == "__main__":
    app()
