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

Goals:

- tree-sitter AST-aware redaction
- syntax validation after redaction
- sanitized workspace mode
- local classifier integration
- local embedding index
- semantic leak detector
- stronger action guard rules
- reversible encrypted redaction vault
- keyed (HMAC) audit chain and external anchoring

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
