#!/usr/bin/env bash
#
# Faraday Gate smoke test.
#
# Fast confidence check: the CLI starts and the core commands run without
# crashing. Deeper behavioural assertions live in scripts/e2e.sh.
#
# Usage: ./scripts/smoke.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Prefer an explicit FARADAY_BIN, then `faraday` on PATH, then the local venv.
if [[ -n "${FARADAY_BIN:-}" ]]; then
  FARADAY="$FARADAY_BIN"
elif command -v faraday > /dev/null 2>&1; then
  FARADAY="faraday"
elif [[ -x "$REPO_ROOT/.venv/bin/faraday" ]]; then
  FARADAY="$REPO_ROOT/.venv/bin/faraday"
else
  echo "[FATAL] faraday CLI not found."
  echo "Install it with: pip install -e \".[dev]\""
  echo "Or point FARADAY_BIN at the executable."
  exit 1
fi

echo "=== Faraday Gate Smoke Test ==="
echo "Using CLI: $FARADAY"

echo "[1] Version"
"$FARADAY" version

echo "[2] Doctor"
"$FARADAY" doctor

echo "[3] Init temp project"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR" || exit 1

"$FARADAY" init

echo "[4] Policy validate"
"$FARADAY" policy validate

echo "[5] Safe prompt scan"
"$FARADAY" scan --prompt "safe text" --format plain

# An email is PII, so the default strict-local policy may treat this as a
# blocking finding. The point of this step is that the command runs and
# reports, not that it allows.
echo "[6] PII prompt scan (may be blocked by policy)"
"$FARADAY" scan --prompt "Contact demo@example.com" --format plain || true

echo "[7] Redact PII prompt"
"$FARADAY" redact --prompt "Contact demo@example.com"

echo "[8] Audit verify"
"$FARADAY" audit verify

echo "[9] Dashboard plain"
"$FARADAY" dashboard --format plain --no-verify

echo
echo "Smoke test complete."
