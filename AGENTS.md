# AGENTS.md

Repository memory for Faraday Gate. Keep this file updated as the build progresses.

## What this project is

Faraday Gate — a CLI-native, zero-egress AI agent firewall for AI coding agents
(OpenHands, Qwen Coder CLI) targeting the Snapdragon AI PC / HP PC challenge.

## Repository layout

The Python package lives at the repository root, not in a nested `faraday-gate/` folder.

```
faraday/
  __init__.py      # __version__
  cli.py           # Typer app + `faraday` entrypoint
  core/            # session, policy, audit, proof, workspace
  scanners/        # secrets, pii, injection, command_guard, semantic_leak
  redactor/        # text_redactor, ast_redactor, vault
  models/          # backend, coder, classifier, embeddings
  adapters/        # openhands, qwen_coder
  tui/             # components, theme, live_view
policies/          # default YAML policy files
samples/           # fake demo repo (fake secrets only — never real credentials)
tests/             # pytest suite
docs/              # architecture, security model, pitch
```

## Environment

- Python 3.11+ required (`requires-python = ">=3.10"`), dev container has 3.13.
- Virtualenv at `.venv/`.

## Commands

```bash
# Install (editable)
python -m venv .venv
.venv/bin/pip install -e .

# Install with dev/test extras
.venv/bin/pip install -e ".[dev]"

# Run the CLI
.venv/bin/faraday version
.venv/bin/faraday --help

# Tests (once tests exist)
.venv/bin/pytest

# Lint / types
.venv/bin/ruff check .
.venv/bin/mypy faraday
```

## Conventions and gotchas

- **Typer version behavior**: `typer>=0.9` resolves to modern Typer (0.27+), which
  collapses a single-command app into one command. `faraday/cli.py` therefore
  defines an explicit `@app.callback()`. Do not remove it or `faraday <command>`
  subcommands will stop working.
- **Security**: all demo/sample secrets must be fake (`AKIAFAKEEXAMPLE123`,
  `sk_test_fake...`). Never commit real credentials or call external cloud APIs.
- **CLI contract**: every command must support plain-text and `--format json`
  output for accessibility and scriptability.

## Build progress

- [x] Step 1 — project foundation (structure, pyproject, CLI skeleton)
- [ ] Step 2 — configuration and policy model
- [ ] Step 3 — session and audit chain
- [ ] Step 4 — scanners
- [ ] Step 5 — redaction engine
- [ ] Step 6 — core CLI commands
- [ ] Step 7 — agent wrapping
- [ ] Step 8 — proof, dashboard, benchmark
- [ ] Step 9 — sample demo repository
- [ ] Step 10 — tests
- [ ] Step 11 — submission and pitch
