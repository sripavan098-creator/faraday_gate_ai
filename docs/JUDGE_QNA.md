# Faraday Gate — Judge Q&A

## Question 1: Why not just use existing secret scanners?

Most secret scanners run after code is committed or pushed.

Faraday Gate protects the live AI-agent boundary.

It scans prompts, repository context, commands, and outputs before sensitive material reaches the agent.

Secret scanning is one layer inside a broader agent-firewall architecture.

---

## Question 2: Why is this relevant to Snapdragon-powered HP PCs?

Faraday Gate depends on local processing.

The MVP uses deterministic scanners now, but the roadmap includes:

- local classifiers
- local embeddings
- local code generation
- local semantic leak review

These workloads benefit from Snapdragon AI PC acceleration and power efficiency.

The privacy story becomes stronger when AI processing can remain on-device.

---

## Question 3: Does Faraday Gate prove zero egress?

No, and the product does not claim it does.

The MVP distinguishes between egress labels:

- `faraday-originated` — Faraday itself made no external network requests
- `blocked-by-policy` — policy denied network-capable operations
- `not-measured` — a subprocess ran under `--execute` and its own network
  activity was not observed or isolated

The competition MVP does not claim OS-level network isolation.

The proof report explicitly states what was observed and what was not measured.

---

## Question 4: Is the local model real?

In the current MVP, the local model response path is simulated and clearly labeled.

The architecture exposes a backend abstraction so real local inference can be added through:

- ONNX Runtime
- llama.cpp
- localhost model server
- Snapdragon-compatible runtime where verified

---

## Question 5: Is redaction perfect?

No.

Faraday Gate is a defense-in-depth layer.

The MVP uses syntax-aware text redaction.

The hard-mode roadmap includes tree-sitter AST-aware redaction with syntax validation.

---

## Question 6: How do you handle false positives?

Faraday Gate uses layered detection and policy actions.

The policy vocabulary supports:

- allow
- warn
- redact
- ask
- block
- quarantine

In the current build the scanners emit `allow`, `warn`, `redact`, and `block`.
`ask` and `quarantine` are reserved in the policy vocabulary but are not yet
produced by any scanner.

The default policy is strict for secrets, prompt injection, denied paths, and dangerous commands.

PII is redacted by default.

---

## Question 7: How do you handle false negatives?

We do not claim perfect detection.

Faraday Gate uses defense in depth:

- path rules
- secret patterns
- entropy hints
- PII rules
- injection heuristics
- command guard
- audit trail
- proof reporting

The roadmap adds classifiers, AST awareness, and semantic leak detection.

---

## Question 8: Does Faraday Gate modify OpenHands or Qwen Coder?

No.

The MVP uses a generic subprocess wrapper pattern.

This makes Faraday Gate resilient to changes in agent internals.

Dedicated adapters help extract prompts and commands, but deep modification of the agent is not required.

---

## Question 9: What happens when something dangerous is detected?

Depends on mode and policy.

In strict-local mode:

- denied paths are blocked
- dangerous commands are blocked
- prompt injection is blocked
- secrets are blocked by default
- audit events are written
- the operation exits with code `1`

---

## Question 10: What if the NPU is unavailable?

Faraday Gate uses a backend abstraction.

If a Snapdragon/NPU backend is unavailable, the system can fall back to:

- deterministic scanners
- CPU execution
- local runtimes where installed

The proof report and `faraday doctor` report NPU status as
`not verified in MVP`. NPU acceleration is not claimed unless it can be
measured on the target hardware.

---

## Question 11: Is this production-ready?

No.

This is a hackathon MVP.

It demonstrates the architecture, workflow, and security boundary.

Production hardening would require:

- stronger process/network isolation
- signed policies
- enterprise integrations
- broader language support
- verified model backends
- performance optimization
- security review

---

## Question 12: Why is the audit chain useful?

The audit chain provides tamper evidence for protected sessions.

It records:

- session start
- findings
- redactions
- policy decisions
- model/backend events
- command events
- session end

It does not store raw secrets: findings record the rule and location, and the
matched value is written as `[REDACTED]`.

Honest limitation: the chain is a plain unkeyed SHA-256 hash chain. It detects
edits, insertions, and deletions in the middle of the log, but it does **not**
detect tail truncation — deleting the last N events leaves a shorter chain that
still verifies, because there is no externally anchored head hash. It is also
not signed, so an actor who can rewrite the entire log can recompute a
consistent chain. Head anchoring, HMAC-based keying, and external notarization
are on the production-hardening roadmap. We say "tamper-evident", not
"tamper-proof".

---

## Question 13: What is the most innovative part?

The boundary.

Faraday Gate does not treat AI security as a post-commit scanner or a cloud policy dashboard.

It protects the exact moment where local developer context enters the AI agent.

---

## Question 14: What would you build next?

The next high-value features are:

1. AST-aware redaction using tree-sitter
2. sanitized workspace isolation
3. real local Qwen Coder inference
4. semantic leak detection
5. Snapdragon/NPU benchmarking where verified

---

## Question 15: What is the one-sentence summary?

Faraday Gate makes AI coding agents safe enough for real engineering by protecting the local context boundary.
