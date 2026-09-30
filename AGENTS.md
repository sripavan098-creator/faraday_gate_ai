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
- **Escape all dynamic text before passing it to `rich`.** Rich parses `[square
  brackets]` as markup, so `[faraday-mock-coder]` in wrap output was silently
  deleted from the terminal panel. Use `rich.markup.escape(...)` on safe output
  and warnings. (JSON/plain output paths are unaffected.)
- **`wrap` passthrough**: `faraday wrap [OPTIONS] -- CMD ...`. Everything after
  `--` is the wrapped command, including anything that looks like a faraday
  option — place `--format` etc. *before* `--`.
- **Escaping and markup** applies to proof/dashboard titles too — that is why
  panel titles use `[SAFE]`/`[BLOCKED]` deliberately as Rich color tags.
- **`pytest` collection is scoped to `tests/` via `testpaths`.** `samples/repo`
  contains its own `tests/` package that otherwise collides with the top-level
  `tests` package and breaks collection.
- **Audit corruption semantics.** A structurally corrupt `events.jsonl` (invalid
  JSON) raises `AuditError` from `iter_events()`. `prove` catches it and exits 3.
  `dashboard` catches it at the `verify()` call and renders a degraded report,
  then exits 3 when `audit_valid is False`. With `--no-verify` a corrupt chain
  still exits 3 because the report still marks the chain invalid.
- **Redaction narrowing must not split URL values.** `DATABASE_URL = "postgres://..."`
  contains `:`; assignment narrowing must check `context_is_assignment()` first,
  otherwise `postgres` is mistaken for a key and the output becomes
  `DATABASE_URL = "postgres:"[SECRET_2]""`.
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



## Tests

`tests/` holds 242 tests: scanner unit tests, redaction, audit chain, golden
fixtures for `samples/repo`, CLI smoke tests over every command (asserting the
exit-code contract), adversarial payloads, and gate-mode semantics.

Test files use the `workspace` fixture from `tests/conftest.py`, which writes a
real `.faraday/config.yaml` through the same code path as `faraday init`.
Protected commands fail closed without it, so a raw `tmp_path` is not enough
for tests that exercise them.

## Release gate

Before pushing or merging a release branch, the full gate must pass:

```bash
pip install -e ".[dev]"   # installs everything the suite needs
pytest -q
ruff check .
mypy
bandit -r faraday -lll    # CI fails only on High severity
pip-audit
./scripts/smoke.sh
./scripts/e2e.sh
```

`scripts/e2e.sh` is the real go/no-go check: it builds a throwaway hostile
repository and asserts 20 behaviours. It asserts **exact exit codes**, not just
non-zero, so a crash (2 or 3) cannot be mistaken for a deliberate block (1).

**The `dev` extra must stay a superset of what the tests exercise.** Three
separate red-suite bugs came from this: `.[dev]` alone failed on the AST
redactor (needs tree-sitter) and on `wrap --execute` measurement (needs
psutil). Those are shipped features with real tests, so their dependencies live
in `dev`, not only in the `ast`/`egress` extras. A clean
`pip install -e ".[dev]" && pytest` must be green: 242 passed on a quiet
machine, and 241 passed + 1 skipped under ambient traffic. The skip is the
quiet-workload egress test, which cannot attribute system-wide connections to
the workload (see the egress note below).

Git hygiene: `.faraday/` (config, audit chain, cached policies), `reports/`,
and `.env` are all gitignored. `samples/repo/.env.fake` is force-kept via a
negation so the demo repo stays runnable.

Egress attribution: `egress_monitor` samples `psutil.net_connections()` with no
`pid` filter, so it is system-wide. `wrap` uses a blocking `subprocess.run`, so
the child pid never reaches the sampling thread. Do not describe egress results
as per-process. The quiet-workload test skips (rather than fails) when it sees
ambient connections, because those are not evidence about the workload.

## Security tooling findings

`bandit -r faraday -ll` reports 0 High, 1 Medium, 6 Low. The Medium is
`B104` on `_IGNORED_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}` in
`egress_monitor.py` -- a false positive, that is a filter list, not a bind.
The Low items are `try/except/pass` in the sampling loop (deliberate: a
transient error must not abort a measurement) and subprocess notices for
list-arg calls. `shell=True` appears nowhere. `pip-audit` is clean.

## Web site (Vercel)

`web/` is a static documentation site only. The CLI engine is never deployed.
`report.js` renders `faraday prove --format json` client-side; it builds nodes
with `textContent` because report fields derive from repository content and
could contain markup. Never introduce `innerHTML` there. The CSP in
`vercel.json` has no `unsafe-inline`, so `index.html` must have no inline
handlers or `style=` attributes.

The page also loads nothing from another origin: three.js is vendored under
`web/vendor/three.min.js` and the fonts are self-hosted woff2 files under
`web/vendor/fonts/`. The CSP (`default-src 'none'`, `font-src 'self'`,
`connect-src 'none'`) would block a CDN anyway, and a site about zero-egress
tooling should not make cross-origin requests. Tests assert this. Landing-page
behaviour lives in `web/landing.js`; because a parse error in an external
script is invisible in the markup, a test runs `node --check` on it.

## Build progress

- [x] Step 1 — project foundation (structure, pyproject, CLI skeleton)
- [x] Step 2 — configuration and policy model (`init`, `policy show/validate/path`)
- [x] Step 3 — session and audit chain (`audit show/verify/export`)
- [x] Step 4 — scanners (secrets, pii, injection, command guard, path rules, pipeline)
- [x] Step 5 — redaction engine (placeholders, overlap-safe, syntax-preserving)
- [x] Step 6 — core CLI commands (`doctor`, `scan`, `redact`)
- [x] Step 7 — agent wrapping (`wrap`, adapters, wrap engine)
- [x] Step 8 — proof, dashboard, benchmark
- [x] Step 9 — sample demo repository (`samples/repo`)
- [x] Step 10 — tests (242 passing)
- [x] Step 11 — submission and pitch (`README.md`, `docs/`)

## Deliverable documents

```
README.md                # final, verified against the CLI
docs/SUBMISSION.md       # submission form copy
docs/PITCH.md            # 3-min pitch + final demo script
docs/PITCH_DECK.md       # slide content
docs/JUDGE_QNA.md        # judge Q&A with honest caveats
docs/ROADMAP.md          # 4 phases
docs/ARCHITECTURE.md     # implemented architecture
docs/DESIGN.md           # design rationale
docs/TECH_STACK.md       # dependencies and storage
```

Every command and flag referenced in these docs was executed against the real
CLI before being documented. All 17 scanner rule names were verified to exist.
Do not add claims that are not backed by a run or a code path.

## Protection modes

Three modes are defined by `mode_policy()` in `faraday/core/policy.py`, which is
the single source of truth. `faraday init --preset <mode>` and
`faraday gate --mode <mode>` both route through it, so the two documented ways
of choosing a mode cannot drift apart.

| Mode | Egress | Secrets | PII | Injection | Commands |
|---|---|---|---|---|---|
| `strict-local` (default) | deny | block | redact | block | block |
| `sanitize-external` | allow | block | redact | block | block |
| `observe-only` | deny | warn | warn | warn | warn |

Path deny rules and the audit chain stay active in every mode.

**Gotcha that had already shipped a bug:** scanning functions accept a `policy`
argument but the scanners return a *hardcoded* `recommended_action`. Blocking
must therefore be decided with `classify_findings(findings, policy)`
(`faraday/core/wrap.py`), not by testing `finding.recommended_action == "block"`.
Doing the latter made `observe-only` silently hard-block on secrets, ignoring the
policy the user selected. `scan` and `wrap` now share the helper; any new
command that reports a block decision must use it too.

## Tooling

`ruff` and `mypy` configs live in `pyproject.toml`; both must pass, and CI
(`.github/workflows/ci.yml`) enforces them plus the test suite on 3.10-3.12.
The demo job in CI asserts the block/pass exit codes from a clean install, so a
change that breaks the on-stage demo fails the build.

Scanner pattern tables are annotated with the `Severity` / `DecisionAction`
literals from `faraday/core/session.py`. Annotating the tables (rather than
casting at the call site) is what keeps mypy useful for detecting a typo'd
severity in a new rule.



Both are now implemented and tested. Test suite: `242 passing`.

### AST-aware redaction (`faraday/redactor/ast_redactor.py`)

The text redactor (`text_redactor.py`) corrupts structured code: an f-string
such as `f"postgres://{user}:{SECRET}@localhost/db"` was rewritten to
`f"[SECRET_1]"`, destroying the interpolations. The AST redactor edits only
`string_content` node ranges via tree-sitter, so quoting, prefixes (`f`, `r`),
and `{interpolation}` expressions survive. It re-parses its own output on
Python and raises `RedactionValidationError` when the input does not parse or
no grammar is available.

`faraday/cli.py::_redact_source` prefers AST redaction when the path maps to a
known grammar, and falls back to `redact_text` otherwise (stdin, `.env`,
config files). The AST redactor is *not* general-purpose: use it only for real
source files.

### Egress measurement (`faraday/core/egress_monitor.py`)

`wrap --execute` previously hardcoded `egress_method = "not-measured"`. It now
samples `psutil.net_connections(kind="inet")` in a background thread around the
subprocess and reports `measured-process`.

Two things that are easy to get wrong here:

1. Connections are keyed by `(local_port, remote_ip, remote_port)`, not by
   remote endpoint alone. Keying on the remote endpoint hides a *repeat*
   connection to an endpoint already in the baseline snapshot.
2. The stored audit value stays inside the `EgressMethod` literal set
   (`measured-process`). `EgressResult.describe()` is a *display* string
   (`egress-observed` / `no-egress-observed`) and must not be stored as
   `method` -- doing so raises a pydantic validation error in
   `Session.add_egress_observation`.

Measurement is polling-based, so a connection opening and closing between
samples can be missed. This limitation is stated in the proof report and must
not be softened: "none observed" never means "none happened". Faraday does not
block network access at the OS level in this MVP.

`wrap` now emits an `egress_observation` audit event, and `proof` reads it to
surface observed remote endpoints.

### Optional dependency extras

`ast`, `ai`, and `egress` extras in `pyproject.toml` are not installed in the
default environment. Code paths that need them must degrade gracefully
(`ASTRedactor.available`, `probe_available()`) rather than import at module
level.

