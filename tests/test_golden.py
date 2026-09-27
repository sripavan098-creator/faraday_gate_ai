"""Golden tests over the bundled sample repository.

These lock the exact detection results for `samples/repo`. If a scanner change
adds, removes, or reclassifies a detection on the demo repository, these tests
fail. That is intentional: the demo repository is what gets shown on stage, so
its behavior should change only deliberately.

The sample repo contains fake credentials only. `samples/repo/.env.fake` is a
denied path, so its contents are blocked by path rule rather than content-scanned
-- that distinction is asserted below.
"""

from __future__ import annotations

import subprocess
import sys

# (finding type, rule) -> expected count for `faraday scan samples/repo`.
EXPECTED_DETECTIONS = {
    ("path", "denied_path"): 1,
    ("pii", "account_identifier"): 1,
    ("pii", "email_address"): 1,
    ("pii", "phone_number_india"): 1,
    ("pii", "sensitive_keyword"): 1,
    ("prompt_injection", "ignore_instructions"): 1,
    ("prompt_injection", "network_exfiltration"): 1,
    ("prompt_injection", "read_env"): 1,
    ("prompt_injection", "reveal_environment_variables"): 1,
    ("secret", "database_url"): 2,
    ("secret", "stripe_secret_key"): 1,
    ("semantic_leak", "semantic_env_dump_request"): 1,
}


def _scan_json(cwd, target):
    import json

    result = subprocess.run(
        [sys.executable, "-m", "faraday.cli", "scan", str(target), "--format", "json"],
        cwd=cwd,
        capture_output=True,
        text=True,
    )

    return result, json.loads(result.stdout)


def test_sample_repo_scan_exit_code_is_blocked(sample_repo, workspace):
    result = _scan_json(workspace, sample_repo)

    # The demo repo contains fake secrets and an injection payload.
    assert result[0].returncode == 1


def test_sample_repo_matches_golden_detections(sample_repo, workspace):
    import collections

    _, payload = _scan_json(workspace, sample_repo)

    findings = payload.get("findings", payload) if isinstance(payload, dict) else payload

    actual = collections.Counter(
        (finding.get("type") or finding.get("finding_type"), finding.get("rule"))
        for finding in findings
    )

    assert dict(actual) == EXPECTED_DETECTIONS


def test_denied_env_file_is_blocked_by_path_not_content(sample_repo, workspace):
    _, payload = _scan_json(workspace, sample_repo)

    findings = payload.get("findings", payload) if isinstance(payload, dict) else payload

    path_findings = [
        f for f in findings if (f.get("type") or f.get("finding_type")) == "path"
    ]

    assert len(path_findings) == 1
    assert path_findings[0]["rule"] == "denied_path"


def test_sample_repo_has_no_real_secret_material(sample_repo):
    # Guard against a future edit pasting a real key into the demo repo.
    combined = ""

    for path in sample_repo.rglob("*"):
        if path.is_file():
            combined += path.read_text(encoding="utf-8", errors="ignore")

    lowered = combined.lower()

    for marker in ("akiaiosfodnn7example", "sk_live_", "-----begin rsa private key-----"):
        assert marker not in lowered


def test_sample_repo_uses_safe_attacker_domain(sample_repo):
    combined = ""

    for path in sample_repo.rglob("*"):
        if path.is_file():
            combined += path.read_text(encoding="utf-8", errors="ignore")

    # Any attacker host must use a reserved example domain.
    assert "attacker.example" in combined
    assert "attacker.com" not in combined
