# Faraday Gate Roadmap

## Phase 1 — Competition MVP

Status: implemented in this build.

Included:

- CLI
- policy engine
- secret scanner
- PII scanner
- prompt-injection scanner
- command guard
- path denial
- text redactor
- agent wrapper
- OpenHands/Qwen adapters
- SHA-256 audit chain
- proof report
- dashboard
- benchmark
- automated tests
- fake sample repository

---

## Phase 2 — Hard Build

Status: partially implemented in this build. Items marked **shipped** are in the
code today and covered by tests; the rest remain open.

Goals:

- tree-sitter AST-aware redaction — **shipped** (`faraday/redactor/ast_redactor.py`)
- syntax validation after redaction — **shipped** (the redactor re-parses and
  raises rather than emitting invalid output)
- semantic leak detector — **shipped as deterministic heuristics**
  (`faraday/scanners/semantic_leak.py`); a learned version remains roadmap
- sanitized workspace mode
- local classifier integration
- local embedding index
- stronger action guard rules
- reversible encrypted redaction vault
- keyed (HMAC) audit chain and external anchoring

Also shipped ahead of this phase: real process-based egress measurement
(`faraday/core/egress_monitor.py`).

---

## Phase 3 — Snapdragon Optimization

Goals:

- Snapdragon-compatible runtime detection
- quantized local models
- NPU benchmarking where verified
- latency/power measurements
- local Qwen Coder inference
- local risk classifier
- local PII/NER model
- benchmark-driven model selection

Important rule:

Do not claim NPU acceleration unless verified by diagnostic/benchmark tooling.

---

## Phase 4 — Production Hardening

Goals:

- stronger process isolation
- OS-level network isolation where feasible
- signed policy versions
- enterprise policy packs
- CI integration
- pre-commit hooks
- agent protocol adapters
- remote anchoring of audit reports
- security review and penetration testing
