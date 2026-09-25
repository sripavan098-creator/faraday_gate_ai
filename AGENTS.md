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
- **Use `app.add_typer(...)`, not `app.add_subapp(...)`.** `add_subapp` is not a
  Typer API; it fails at import time.
- **No optional-value options.** Typer 0.27 rejects `--flag[=VALUE]` style (tested
  `is_flag=False, flag_value=...`; it errors). Hence `scan` exposes the git diff as
  a boolean `--diff` plus `--diff-ref TEXT`, not `--diff [REF]`. Consequences:
  `faraday scan --diff --format plain` (correct) vs `faraday scan --diff HEAD`
  (now a usage error — use `--diff-ref HEAD`). Without this split, `--format plain`
  was silently forwarded to `git diff` and crashed.
- **Use `Optional[Path]` / `Optional[str]`, not `Path | None` / `str | None`, in CLI
  signatures.** With `from __future__ import annotations`, Typer evaluates the
  annotation string and can raise on PEP 604 unions under `requires-python >=3.10`.
- **Security**: all demo/sample secrets must be fake (`AKIAFAKEEXAMPLE123`,
  `sk_test_fake...`). Never commit real credentials or call external cloud APIs.
- **CLI contract**: every command must support plain-text and `--format json`
  output for accessibility and scriptability.

## Exit-code semantics

```
0 = success / valid
1 = policy blocked operation
2 = configuration/usage error
3 = internal security subsystem error
```

## Configuration

`.faraday/config.yaml` is the active policy; `.faraday/policies/default.yaml` is
the reference copy written by `faraday init`. Both are typed by
`faraday/core/policy.py` (Pydantic) and loaded via `faraday/config.py`.

Loading is **fail-closed**: missing file, invalid YAML, non-mapping root, or
schema violation all raise `ConfigError`, and CLI commands exit `2`. Protected
operations must never proceed on an invalid policy.

## Audit chain

`.faraday/audit/events.jsonl` is an append-only SHA-256 hash chain; the head
hash is cached in-process and invalidated by file size/mtime, so writes stay
O(1) instead of O(n²).

**Known limitation (documented, not a bug):** a bare hash chain detects edits,
insertions, and *middle* deletions, but **not tail truncation** — deleting the
last N events leaves a shorter yet internally consistent chain that still
verifies. Detecting that needs the head hash anchored outside the log, which is
what the Step 8 proof report must do. Do not overclaim tamper-proofing in the
pitch; say "tamper-evident" and explain the anchoring.



## Build progress

- [x] Step 1 — project foundation (structure, pyproject, CLI skeleton)
- [x] Step 2 — configuration and policy model (`init`, `policy show/validate/path`)
- [x] Step 3 — session and audit chain (`audit show/verify/export`)
- [x] Step 4 — scanners (secrets, pii, injection, command guard, path rules, pipeline)
- [x] Step 5 — redaction engine (placeholders, overlap-safe, syntax-preserving)
- [x] Step 6 — core CLI commands (`doctor`, `scan`, `redact`)
- [ ] Step 7 — agent wrapping
- [ ] Step 8 — proof, dashboard, benchmark
- [ ] Step 9 — sample demo repository
- [ ] Step 10 — tests
- [ ] Step 11 — submission and pitch
