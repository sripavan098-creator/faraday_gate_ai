# Faraday Gate Pitch Deck

## Slide 1 — Title

# Faraday Gate

**Your agents. Your code. No leaks.**

A CLI-native AI agent firewall for Snapdragon-powered HP PCs.

---

## Slide 2 — Hook

AI coding agents are becoming incredibly powerful.

But to be useful, they need context.

And context often contains:

- secrets
- private code
- customer data
- internal infrastructure

---

## Slide 3 — Problem

When developers use AI agents, they risk leaking:

- credentials
- proprietary logic
- sensitive data

to external systems.

Even worse:

Malicious instructions hidden inside repository files can trick agents into exposing information or attempting unsafe actions.

---

## Slide 4 — Agitation

This is why many teams are afraid to let AI agents touch real codebases.

The productivity upside is huge.

The security risk is unacceptable.

---

## Slide 5 — Solution

Faraday Gate is a zero-egress security layer for AI coding agents.

It wraps tools like:

- OpenHands
- Qwen Coder CLI

and protects the context boundary.

It:

- scans prompts
- scans files
- scans commands
- detects secrets
- detects PII
- detects prompt injection
- redacts or blocks risky content
- generates a hash-chained proof report

---

## Slide 6 — Demo

Run a coding task under Faraday Gate against a sample repo.

Watch it:

1. block a fake `.env`
2. detect fake credentials
3. catch a prompt-injection payload hidden in a README
4. redact sensitive values
5. produce a proof report
6. verify the audit chain

---

## Slide 7 — Why Snapdragon

This only works if scanning and eventual local inference run fast and efficiently on-device.

That is exactly what Snapdragon AI PCs are built for.

Privacy here is not a policy setting.

It is an architectural property.

---

## Slide 8 — Architecture

```text
Developer Prompt / Repository Context
        ↓
Faraday Gate CLI
        ↓
Context Collector
        ↓
Policy Engine
        ↓
Secret / PII / Injection / Command Scanners
        ↓
Redactor
        ↓
Local Model Orchestrator [simulated in MVP]
        ↓
Safe Agent Execution
        ↓
Output Scanner
        ↓
Audit Chain + Proof Report
```

---

## Slide 9 — Security Principles

- Local-first
- Fail closed in strict mode
- Deterministic before probabilistic
- Least context
- Defense in depth
- Observable decisions
- Reproducible sanitization
- No security theater

---

## Slide 10 — Technical Implementation

Implemented in the MVP:

- Typer CLI
- Rich terminal output
- Pydantic policy validation
- YAML policy configuration
- deterministic secret scanner
- PII scanner
- prompt-injection scanner
- command guard
- syntax-aware text redaction
- SHA-256 audit chain
- SQLite session metadata
- JSONL audit export
- proof report
- dashboard
- benchmark
- automated tests

---

## Slide 11 — Innovation

Most security tools scan after the fact.

Faraday Gate protects the live boundary between developer context and AI agents.

It combines:

- AI agent security
- prompt-injection defense
- secret redaction
- auditability
- local-first privacy

---

## Slide 12 — Accessibility & Deployment

Faraday Gate is CLI-native.

It supports:

- plain output
- JSON output
- table output
- explicit labels: `[SAFE]`, `[WARNING]`, `[BLOCKED]`
- predictable exit codes
- scriptable workflows

---

## Slide 13 — Vision

Faraday Gate makes AI agents safe enough for real engineering.

Developers move fast without leaking what matters.

---

## Slide 14 — Roadmap

Phase 1:

- competition MVP

Phase 2:

- AST-aware redaction
- sanitized workspace
- local classifiers
- action guard expansion

Phase 3:

- Snapdragon optimization
- NPU benchmarking where verified
- local Qwen Coder inference

Phase 4:

- production hardening
- stronger isolation
- enterprise policy packs

---

## Slide 15 — Close

# Faraday Gate

**Your agents. Your code. No leaks.**
