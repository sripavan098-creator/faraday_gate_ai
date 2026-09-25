# Faraday Gate — Design

## Design principle

The product is a firewall, not a scanner. A scanner reports after the fact; a
firewall makes a decision at the boundary and records it. Every design choice
below follows from that.

## 1. Deterministic before probabilistic

Detection runs in two tiers:

1. **Deterministic** — path rules, secret patterns, command guard, PII regex,
   injection phrase rules. Fast, explainable, no model weights.
2. **Learned (roadmap)** — local classifiers, embeddings, semantic leak review.

The MVP ships tier 1 only and labels tier 2 as roadmap. This is deliberate: a
security control that cannot explain *why* it blocked something is not
auditable, and an audit trail is a core deliverable.

## 2. Fail closed

- Missing or invalid config raises `ConfigError`; protected operations refuse to
  run rather than proceeding unprotected.
- Unsupported CLI output format exits `2`.
- A structurally corrupt audit trail exits `3` from `prove` and `dashboard`.
- `strict-local` is the default mode.

## 3. Modes

| Mode | Intent |
|---|---|
| `strict-local` | Block secrets, injection, denied paths, dangerous commands |
| `sanitize-external` | Redact and continue where possible |
| `observe-only` | Record findings, do not block |

## 4. Scanner design

Every scanner returns the same normalized `ScanFinding`:

```python
type, rule, severity, location, line, start, end, matched, recommended_action
```

This uniformity is what lets one redactor and one policy engine serve all
detectors, and what makes the audit trail homogeneous.

Detectors:

| Scanner | Examples of rules |
|---|---|
| `secrets` | `aws_access_key_id`, `aws_secret_access_key`, `stripe_secret_key`, `private_key_block`, `database_url`, `generic_secret_assignment` |
| `pii` | `email_address`, `phone_number_india`, `account_identifier` |
| `injection` | `ignore_instructions`, `disregard_instructions`, `read_env`, `network_exfiltration` |
| `command_guard` | `curl`, `cat_env`, `rm_rf` |
| `path_rules` | `denied_path` |

Secrets additionally use Shannon entropy as a hint for generated values.

## 5. Action vocabulary

Policy supports `allow`, `warn`, `redact`, `ask`, `block`, `quarantine`.
The current scanners emit `allow`, `warn`, `redact`, and `block`; `ask` and
`quarantine` are defined in the vocabulary and consumed by the wrap engine's
`BLOCK_ACTIONS` / `WARN_ACTIONS` sets, but no scanner produces them yet. The
documentation states this rather than implying full coverage.

## 6. Redaction design

Goals, in priority order:

1. Never leave the sensitive value in the output.
2. Keep the output syntactically valid where possible.
3. Keep the output deterministic and reproducible.

Mechanism:

- **Placeholder state** is session-scoped and content-addressed by a
  fingerprint of the value, so the same value always maps to the same
  placeholder within a session.
- **Span normalization** narrows an assignment to its value so the key is
  preserved: `api_key = "secret"` → `api_key = "[SECRET_1]"`.
- **URL guard** rejects `//` so `postgres://user:pass@host/db` is not parsed as
  a key named `postgres`.
- **Overlap resolution** picks by severity then span length, preventing
  double-substitution artifacts.
- **Quoting** wraps placeholders for unquoted secret assignments so the result
  still parses.

Two real bugs shaped this design, both from the same root cause — an early
return in `find_value_span` that decided narrowing was unnecessary:

- value-only spans skipped *needed* narrowing, corrupting URLs into
  `postgres:"[SECRET_2]""`
- key-first spans skipped narrowing that *would have preserved* the key, so
  `api_key = "..."` became `"[SECRET_1]"`

The fix removed the early return entirely and let the `//` guard decide.

## 7. Audit design

- Append-only JSONL, one record per event.
- Hash chain: `hash = sha256(prev_hash + canonical(event))`.
- Raw secret values are never persisted; matched values become `[REDACTED]`.
- SQLite holds session metadata so proof reports can survive a JSONL read
  failure.
- Honest scope: an unkeyed SHA-256 chain detects tampering but cannot stop an
  actor who rewrites the whole log. HMAC/anchoring is roadmap.

## 8. Wrapper design

- Generic subprocess wrapping, so agent internals can change freely.
- Adapters only extract prompts; they do not require agent cooperation.
- Egress is labeled, never assumed:
  `faraday-originated`, `blocked-by-policy`, `not-measured`.
- The simulated local coder is labeled simulated in output and in the proof.

## 9. Accessibility and scripting

- Every command supports `--format table|plain|json`.
- Status labels are plain words: `[SAFE]`, `[WARNING]`, `[BLOCKED]`.
- Exit codes are meaningful and documented.

## 10. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, nothing blocking |
| `1` | Blocking findings, or blocked wrap |
| `2` | Usage / configuration error |
| `3` | Audit-chain verification failure or audit read error |

## 11. Non-goals in the MVP

OS-level network isolation, process sandboxing, AST-level redaction, real local
inference, and signed audit records. Each has a roadmap phase and none is
claimed as present.
