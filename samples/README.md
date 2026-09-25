# Faraday Gate Demo Samples

This directory contains a fake demo repository for Faraday Gate.

Everything inside `samples/repo` is intentionally fake.

- All credentials are fake.
- All personal data is fake.
- All attacker URLs use reserved example domains.
- The prompt-injection payload is simulated and harmless.

## Recommended demo flow

From the root of the Faraday Gate repository:

```bash
faraday init
faraday gate --mode strict-local
faraday scan samples/repo
faraday redact samples/repo/src/config.py
faraday wrap -- qwen-coder "Fix the login bug"
faraday wrap --workdir samples/repo --scan-repo -- qwen-coder "Fix the login bug and explain the auth flow"
faraday prove latest
faraday dashboard
```

## Expected story

1. Faraday initializes local policy and audit structure.
2. Faraday scans the sample repository.
3. Faraday blocks the fake `.env.fake` file by path policy.
4. Faraday detects fake credentials in source files.
5. Faraday detects fake PII in documentation.
6. Faraday detects a simulated prompt-injection payload in the sample README.
7. Faraday redacts a fake source file safely.
8. Faraday protects a wrapped CLI invocation.
9. Faraday generates a proof report.
