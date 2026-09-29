# Faraday Gate Security Review

## Scope

This review covers the Faraday Gate hackathon MVP: the `faraday` CLI, its
scanners, redactor, audit chain, and the `wrap` execution path.

Faraday Gate is a defense-in-depth CLI security layer. It is not a guarantee of
perfect security, and this document does not claim otherwise.

## How to reproduce

Every check below was run from the repository root against commit
`release/e2e-hardening`.

```bash
pip install -e ".[dev]"
pytest -q                       # unit/integration suite
./scripts/smoke.sh              # CLI smoke test
./scripts/e2e.sh                # behavioural release gate
ruff check .                    # style
mypy faraday                    # types
bandit -r faraday -ll           # security lint
pip-audit                       # dependency vulnerabilities
```

## Risk Register

| Risk | Severity | Likelihood | Mitigation | Status |
|---|---:|---:|---|---|
| Accidental secret leakage into an AI agent | Critical | High | Deterministic secret scanner, path denial, redaction, `wrap` blocking | Implemented |
| Prompt injection in repository files | High | High | Injection heuristics, command guard, blocked `wrap` flow | Implemented |
| Command injection through a wrapped command | High | Medium | `subprocess.run` with list args, `shell=True` used nowhere, command guard | Verified |
| Path traversal during scan/redact | High | Medium | Path normalization, deny paths, fail-closed config | Verified |
| Secret leakage in audit logs | Critical | Medium | Metadata-only audit records, no raw matched values | Implemented |
| Audit tampering | Medium | Medium | SHA-256 hash chain, `audit verify` | Implemented |
| Regex denial of service | Medium | Low | File size and file count limits, simple anchored patterns | Partial |
| False positives blocking a developer | Medium | High | Policy actions, `observe-only` mode | Implemented |
| False negatives missing a secret | High | Medium | Layered scanners, no perfect-security claim | Accepted |
| Overclaimed zero egress | High | Medium | Explicit egress labels, proof-report limitations | Implemented |
| Dependency vulnerability | Medium | Medium | `pip-audit`, `dev`/`egress` extras | Verified |
| Malicious Unicode or path names | Low | Low | Path normalization, fake-sample tests | Partial |
| Model output leakage | High | Medium | Output scanner; local model path is labeled simulated | Partial / roadmap |

## Vulnerability Checks Performed

### Static analysis

`ruff check .` and `mypy faraday` both pass clean across 35 source files.

### Bandit security lint

`bandit -r faraday -ll` reports **0 High**, **1 Medium**, **6 Low**.

The Medium finding is `B104 hardcoded_bind_all_interfaces` at
`faraday/core/egress_monitor.py:42`. This is a false positive: the line is a
set of *ignored addresses* used to filter loopback and unspecified endpoints out
of observed connections.

```python
_IGNORED_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}
```

The Low findings are two `B110 try_except_pass` blocks in the egress sampling
loop and two `B404`/`B603` `subprocess` notices. The `except Exception: pass`
blocks are deliberate: a transient sampling error must not abort a running
measurement. The subprocess notices concern calls that pass an argument list
with `shell=False` (the default), which is the recommended pattern.

**`shell=True` appears nowhere in the codebase** (verified by grep). This was a
specific release-gate requirement.

### Dependency audit

`pip-audit` reports **no known vulnerabilities**. `faraday-gate` itself is
skipped because it is not published to PyPI.

### Secret scan

Checked the working tree, all commits, and the GitHub remote refs:

```bash
git grep -nE "AKIA[0-9A-Z]{16}"        -- ':!samples' ':!tests' ':!docs'
git grep -nE "sk_live_[A-Za-z0-9]{10,}" -- ':!samples' ':!tests' ':!docs'
git grep -nE "BEGIN[A-Z ]*PRIVATE KEY"  -- ':!samples' ':!tests' ':!docs'
git --no-pager log --all -p | grep -nE "AKIA|sk_live|PRIVATE KEY"
```

**No real credentials found.** Every hit is one of:

- the fake example value `AKIAFAKEEXAMPLE12345` in samples and tests
- header-only strings such as `-----BEGIN RSA PRIVATE KEY-----` used as scanner
  test fixtures, with no key body
- the detection patterns themselves in `faraday/scanners/secrets.py`

No `.env` file has ever been committed. `.faraday/` (config, audit chain, cached
policies) is now fully gitignored.

### Behavioural gate

`./scripts/e2e.sh` asserts 20 behaviours against a throwaway hostile
repository, including that a fake secret does not survive redaction, that
injection and dangerous commands are blocked, and that a tampered audit chain
fails verification. It asserts **exact exit codes**, so a crash cannot be
mistaken for a deliberate block.

## Security-Relevant Design Decisions

- **Subprocess execution**: wrapped commands run via
  `subprocess.run(command_list, capture_output=True, text=True, check=False)`.
  No shell is involved.
- **Fail-closed configuration**: a missing, unparseable, or schema-invalid
  policy raises `ConfigError` and exits `2`. Protected operations never proceed
  on an invalid policy.
- **Exit-code contract**: `0` success, `1` policy denial, `2` configuration
  error, `3` internal security subsystem error. Denial and malfunction are
  distinguishable.
- **Audit contents**: events record metadata (rule names, hashes, counts), not
  raw matched secret values.

## Known Limitations

- Secret detection is heuristic and deterministic, not exhaustive.
- Prompt-injection detection can be bypassed by novel obfuscation.
- Egress measurement is polling-based: a connection opening and closing between
  samples can be missed. "None observed" never means "none happened".
- Egress is attributed **system-wide** by appearance, not by process ownership:
  the sampler calls `psutil.net_connections()` with no `pid`. `wrap` runs the
  command through a blocking `subprocess.run`, so the child pid is not available
  to the sampling thread. On a busy machine, unrelated ambient traffic can be
  attributed to the wrapped command. Per-process attribution via
  `psutil.Process(pid)` is roadmap work.
- Because of the point above, the suite reports **242 passed** on a quiet machine
  and **241 passed, 1 skipped** under ambient traffic: the quiet-workload egress
  test skips rather than failing when it observes unrelated system connections,
  since they are not evidence about the workload.
- Faraday does **not** enforce OS-level network isolation in this MVP. The
  `network.egress` policy is an application-level decision, reported as such.
- The bare hash chain is tamper-**evident**, not tamper-proof: it detects edits,
  insertions, and middle deletions, but not tail truncation. Detecting
  truncation requires anchoring the head hash outside the log, which is
  roadmap work.
- Local model activity is simulated and labeled as such in output.
- AST-aware redaction degrades to text-level redaction when a grammar is
  unavailable.

## Security Statement

Faraday Gate reduces accidental leakage and prompt-injection risk for developers
using AI coding agents. It is a defense-in-depth layer. It does not guarantee
perfect security, and no output should be read as claiming that it does.
