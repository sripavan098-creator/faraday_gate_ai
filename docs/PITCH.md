# Faraday Gate — Three-Minute Pitch

## Hook

AI coding agents are becoming incredibly powerful.

But to be useful, they need context.

And context often contains secrets, private code, customer data, and internal infrastructure.

## Problem

When developers use AI agents, they risk leaking credentials, proprietary logic, and sensitive data to external systems.

Worse, malicious instructions hidden inside repository files can trick agents into exposing information or performing unsafe actions.

## Agitation

That is why many teams are afraid to let AI agents touch real codebases.

The productivity upside is huge.

The security risk is unacceptable.

## Solution

Faraday Gate is a zero-egress security layer for AI coding agents.

It wraps tools like OpenHands and Qwen Coder CLI.

It scans prompts, files, and commands.

It detects secrets and prompt-injection attempts.

It redacts or blocks risky content while preserving code syntax.

And it generates a hash-chained proof report.

## Why Snapdragon

This only works if the scanning and eventual local inference run fast and efficiently on-device.

That is exactly what Snapdragon AI PCs are built for.

Privacy here is not a policy setting.

It is an architectural property.

## Demo

We run a coding task under Faraday Gate against a sample repository.

You can watch it block a fake `.env`, redact fake credentials, catch a prompt-injection payload hidden in a README, and produce a proof report showing explicit egress status and audit-chain validity.

## Vision

Faraday Gate makes AI agents safe enough for real engineering.

Developers move fast without leaking what matters.

## Close

Your agents.

Your code.

No leaks.

---

# Final Demo Script

## Setup

Open a terminal at the repository root with the virtual environment active.

```bash
faraday doctor
```

Show that dependencies are available, and note that NPU status reads
`not verified in MVP`.

---

## Step 1: Initialize Faraday Gate

```bash
faraday init
```

> This creates the local Faraday policy, audit, cache, and report structure.

---

## Step 2: Set strict-local mode

```bash
faraday gate --mode strict-local
```

> We are now in strict-local mode. External egress is denied by policy.

---

## Step 3: Scan the sample repository

```bash
faraday scan samples/repo
```

Show:

- denied `.env.fake`
- fake secret findings
- fake PII findings
- prompt-injection finding
- exit code `1`

> Faraday detects dangerous paths, fake credentials, fake PII, and a simulated
> prompt-injection payload inside the README.

---

## Step 4: Redact a fake source file

```bash
faraday redact samples/repo/src/config.py
```

Show:

```python
STRIPE_SECRET_KEY = "[SECRET_1]"
DATABASE_URL = "[SECRET_2]"
```

> Faraday replaces sensitive values with deterministic placeholders while
> keeping the code readable — the keys and the syntax survive.

---

## Step 5: Safe wrapped agent invocation

```bash
faraday wrap --format plain -- qwen-coder "Fix the login bug"
```

Show:

```text
Adapter: qwen-coder | Status: completed | Files scanned: 0 | Prompt tokens: 4 | Blocking: 0 | Redactable: 0 | Egress: faraday-originated
```

> The prompt is scanned first. Since it is safe, Faraday allows a simulated
> local response. Note the egress label is honest — no external request was made
> by Faraday.

---

## Step 6: Malicious repository wrap invocation

```bash
faraday wrap --format plain --workdir samples/repo --scan-repo -- qwen-coder "Fix the login bug and explain the auth flow"
```

Show:

```text
Adapter: qwen-coder | Status: blocked | Files scanned: 9 | Prompt tokens: 4 | Blocking: 8 | Redactable: 4 | Egress: faraday-originated
```

> When repository context is included, Faraday blocks dangerous context before
> it can reach the agent.

---

## Step 7: Generate proof report

```bash
faraday prove latest --format plain
```

Show:

- mode
- files scanned
- secrets blocked
- injections blocked
- path blocks
- egress status
- audit-chain validity
- limitations

> The proof report distinguishes observed facts from claims. It does not
> overstate zero-egress protection.

---

## Step 8: Verify audit chain

```bash
faraday audit verify
```

Show:

```text
[SAFE] 42 audit events verified
```

---

## Step 9: Dashboard

```bash
faraday dashboard --format plain
```

Show:

- mode
- latest session
- audit status
- NPU status: not verified in MVP

---

## Close

> Faraday Gate makes AI agents safe enough for real engineering.
>
> Your agents. Your code. No leaks.
