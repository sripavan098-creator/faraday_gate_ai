# Faraday Gate

## Tagline

Your agents. Your code. No leaks.

## One-Line Description

Faraday Gate is a CLI-native AI agent firewall that protects AI coding workflows on Snapdragon-powered HP PCs from secret leakage, sensitive-data exposure, and prompt-injection attacks.

## Short Description

AI coding agents need repository context to be useful, but that context often contains secrets, private code, customer data, and proprietary logic. Faraday Gate protects the exact moment where local context enters an AI agent. It scans prompts, files, and commands; detects secrets, PII, and prompt-injection attempts; blocks or redacts risky content; records decisions in a hash-chained audit trail; and generates a proof report with explicit limitations.

## Problem

Developers are adopting AI coding agents rapidly, but these agents need broad context to be useful. That context can include API keys, database credentials, private keys, PII, internal URLs, and proprietary algorithms.

At the same time, repository content can contain malicious instructions that attempt to manipulate the agent. For example, a README may tell an agent to ignore previous instructions, read `.env`, reveal environment variables, or execute network commands.

The result is a serious security gap:

- developers want AI productivity
- teams cannot safely expose sensitive context
- agents can be manipulated by untrusted repository content

## Solution

Faraday Gate is a local security control plane for AI coding agents.

It wraps tools such as OpenHands and Qwen Coder CLI and protects the context boundary.

Faraday Gate:

- scans prompts before they reach the agent
- scans repository files and diffs
- detects secrets using patterns, entropy, and path awareness
- detects PII and sensitive keywords
- detects prompt-injection attempts
- blocks denied paths such as `.env.fake`
- blocks dangerous commands such as `curl`, `cat .env`, and `rm -rf`
- redacts sensitive values with deterministic placeholders
- preserves code syntax where possible
- writes every material decision to a SHA-256 hash-chained audit trail
- generates a proof report with explicit limitations

## Why Snapdragon

Faraday Gate is designed for local-first AI workflows.

Its value depends on efficient on-device processing:

- secret scanning
- PII detection
- prompt-injection detection
- future local classification
- future local embeddings
- future local code generation

Snapdragon-powered HP PCs are the right platform because privacy here is not just a policy setting. It is an architectural property.

The MVP benchmarks deterministic scanner throughput and exposes backend integration points for future local model runtimes, including ONNX Runtime, llama.cpp, and Snapdragon-compatible paths where verified.

## How We Built It

Faraday Gate is built as a Python-first CLI.

Core stack:

- Python
- Typer
- Rich
- Pydantic
- YAML
- SQLite
- JSONL
- SHA-256 audit chaining
- deterministic scanner pipeline

The MVP uses deterministic scanners first, following the security principle:

> Deterministic before probabilistic.

The local model layer is currently simulated and clearly labeled. The architecture exposes a backend abstraction so future local inference can be added without changing the security engine.

## Technical Implementation

Faraday Gate implements:

- CLI command routing
- typed policy engine
- session manager
- context collector
- secret scanner
- PII scanner
- prompt-injection scanner
- command guard
- path denial rules
- syntax-aware text redactor
- agent wrapper
- OpenHands/Qwen adapters
- SHA-256 audit chain
- proof generator
- dashboard
- benchmark
- automated tests

## Application Use Case & Innovation

Most AI security tools scan after the fact.

Faraday Gate protects the live context boundary:

```text
local developer context → Faraday Gate → AI agent
```

This is innovative because it combines:

- developer tooling
- AI agent security
- prompt-injection defense
- redaction
- auditability
- proof reporting
- local-first privacy

## Deployment & Accessibility

Faraday Gate is CLI-native and scriptable.

It supports:

- plain-text output
- JSON output
- table output
- explicit labels such as `[SAFE]`, `[WARNING]`, and `[BLOCKED]`
- predictable exit codes
- keyboard-friendly terminal workflows

It can be installed with:

```bash
pip install -e .
```

## Presentation & Documentation

The submission includes:

- README
- architecture documentation
- design documentation
- pitch script
- sample fake repository
- automated tests
- demo commands
- proof report examples

## Challenges We Faced

The hardest challenges were:

1. Protecting a moving boundary: AI agent context can come from prompts, files, diffs, commands, and outputs.
2. Avoiding security theater: we had to label egress status honestly instead of overclaiming.
3. Balancing security and usability: blocking too much hurts productivity; blocking too little creates risk.
4. Building a tamper-evident audit trail without storing raw secrets.
5. Designing redaction that preserves syntax without a full AST engine in the MVP.

## Accomplishments

We built a working hackathon MVP that demonstrates:

- blocked `.env.fake`
- detected fake credentials
- detected fake PII
- detected prompt injection
- safe redaction
- protected CLI wrapping
- hash-chained audit trail
- proof report
- dashboard
- benchmark
- automated tests

## What We Learned

We learned that AI agent security must be enforced at the context boundary.

Post-hoc scanning is not enough.

Developers need a local control plane that can make decisions before sensitive context reaches the agent.

## What's Next

Next phases:

1. AST-aware redaction using tree-sitter
2. sanitized workspace isolation
3. real local model orchestration
4. local Qwen Coder inference
5. semantic leak detection
6. Snapdragon/NPU benchmarking where verified
7. stronger process/network isolation
8. enterprise policy packs

## Security Statement

Faraday Gate is a defense-in-depth security layer.

It reduces accidental leakage and prompt-injection risk.

It is not a mathematical guarantee of perfect security.
