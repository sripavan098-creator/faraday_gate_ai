# Faraday Gate — Architecture

This document describes the implemented architecture of the Faraday Gate MVP.
It reflects the code in `faraday/`, not an aspirational design.

## System boundary

Faraday Gate protects one boundary:

```text
local developer context  →  Faraday Gate  →  AI coding agent
```

Everything the agent would otherwise receive passes through the gate first.
The gate never modifies the agent's internals; it wraps the agent's CLI.

## Layered view

```text
Developer Prompt / Repository Context
        ↓
Faraday Gate CLI            faraday/cli.py
        ↓
Context Collector           faraday/core/wrap.py, faraday/cli.py
        ↓
Policy Engine               faraday/core/policy.py, faraday/config.py
        ↓
Scanner Pipeline            faraday/scanners/pipeline.py
  ├─ secret scanner         faraday/scanners/secrets.py
  ├─ PII scanner            faraday/scanners/pii.py
  ├─ injection scanner      faraday/scanners/injection.py
  ├─ command guard          faraday/scanners/command_guard.py
  ├─ path denial            faraday/scanners/path_rules.py
  └─ file walker            faraday/scanners/files.py
        ↓
Text Redactor               faraday/redactor/text_redactor.py
        ↓
Local Model Orchestrator    faraday/models/  [simulated in MVP]
        ↓
Safe Agent Execution        faraday/core/wrap.py
        ↓
Audit Chain                 faraday/core/audit.py
        ↓
Proof Report                faraday/core/proof.py
```

## Module responsibilities

| Module | Responsibility |
|---|---|
| `faraday/cli.py` | Typer command routing; all user-facing output |
| `faraday/config.py` | `.faraday/` layout, config load/save, `ConfigError` |
| `faraday/core/policy.py` | Pydantic `Policy` model, `default_policy()` |
| `faraday/core/session.py` | Session + Finding + Decision models, counters |
| `faraday/core/audit.py` | `AuditChain` append, SHA-256 chaining, `verify()` |
| `faraday/core/wrap.py` | Wrap engine: extract prompt, guard command, scan repo, decide |
| `faraday/core/flow.py` | Orchestrates scan/redact sessions end to end |
| `faraday/core/proof.py` | Proof report assembly, egress labeling, limitations |
| `faraday/core/benchmark.py` | Deterministic scanner throughput measurement |
| `faraday/scanners/*` | Individual detectors + normalization pipeline |
| `faraday/redactor/*` | Placeholder state and text redaction |
| `faraday/adapters/*` | Prompt extraction for generic/OpenHands/Qwen |
| `faraday/models/*` | Local backend abstraction (simulated) |
| `faraday/tui/dashboard.py` | Dashboard report + table/plain/json renderers |

## Data flow: `faraday wrap`

1. **Adapter selection.** The registry matches the wrapped command's argv to a
   known adapter; unknown tools fall back to `generic`.
2. **Prompt extraction.** The adapter pulls the user prompt from positional
   arguments or `--prompt` / `--task` / `--prompt=`.
3. **Prompt scan.** The prompt is scanned by the full pipeline.
4. **Command guard.** The wrapped argv is checked for dangerous commands.
5. **Repo scan (optional).** With `--scan-repo`, files under `--workdir` are
   walked. Denied paths are recorded but not read.
6. **Policy decision.** Findings map to actions. `block`/`quarantine` block;
   `warn`/`ask` pass with a warning; `redact` produces sanitized output.
7. **Execution.** Safe path → simulated local response. `--execute` → real
   subprocess, whose egress is labeled `not-measured`.
8. **Audit + finalize.** Findings, redactions, policy decision, model/command
   events, and session end are appended to the hash chain.

## Audit model

```text
GENESIS_HASH
   ↓  sha256(prev_hash + canonical(event))
event 1 → event 2 → event 3 → ... → head_hash
```

Each JSONL record carries `prev_hash` and `hash`. `verify()` recomputes the
chain from genesis and compares the head. Event types are:

`session_started`, `wrap_invocation`, `finding`, `redaction`,
`policy_decision`, `model_event`, `command_event`, `session_finished`.

Matched secret values are never written: metadata keys such as `matched` and
`value` are replaced with `[REDACTED]`.

Session counters are also persisted to SQLite so a proof report survives even
if it must fall back to database state.

## Redaction model

Redaction is session-scoped and deterministic:

- each distinct value gets a stable placeholder per type
  (`[SECRET_1]`, `[EMAIL_1]`, `[PHONE_1]`, …)
- the same value in the same session reuses the same placeholder
- candidate spans are normalized per finding type, then
  `select_non_overlapping()` resolves conflicts by severity, then span length
- assignment-style secrets are narrowed to the value so the key survives
- a URL scheme (`postgres://`) is never mistaken for a key separator
- unquoted secret assignments are re-quoted so output stays parseable

## Trust boundaries

| Boundary | Trust |
|---|---|
| Repository content | **Untrusted** — may contain injection payloads |
| User prompt | Untrusted input; scanned, never treated as instructions to Faraday |
| Policy file | Local operator-controlled |
| Wrapped agent | Untrusted output; wrapped process is not isolated |
| Network | Denied by policy; not enforced at OS level in the MVP |

## What the architecture deliberately does not do

- It does not enforce OS-level network isolation.
- It does not sandbox the wrapped process.
- It does not perform AST-level redaction (text-level heuristics only).
- It does not run a real local model in the MVP.
- It does not produce cryptographic signatures on the audit chain.
