"""Tests for the three documented gate modes.

The PRD describes three modes. These tests pin what each mode actually
changes, because a mode that silently differs from its description is worse
than no mode at all.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from faraday.core.policy import default_policy, mode_policy

MODES = ("strict-local", "sanitize-external", "observe-only")


def run_faraday(*args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "faraday.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        mode_policy("not-a-mode")


def test_strict_local_is_the_default_policy():
    assert mode_policy("strict-local").model_dump() == default_policy().model_dump()


def test_every_mode_keeps_deny_paths():
    # Path deny rules are the last line of defence. No mode may drop them.
    for mode in MODES:
        policy = mode_policy(mode)

        assert policy.paths.deny, mode
        assert ".env" in policy.paths.deny, mode


def test_sanitize_external_allows_egress_but_still_blocks_secrets():
    policy = mode_policy("sanitize-external")

    assert policy.network.egress == "allow"
    # Sanitized content should not contain secrets at all, so the block stands.
    assert policy.secrets.action == "block"


def test_observe_only_warns_on_everything_but_still_denies_egress():
    policy = mode_policy("observe-only")

    assert policy.secrets.action == "warn"
    assert policy.pii.action == "warn"
    assert policy.prompt_injection.action == "warn"
    assert policy.commands.action == "warn"
    # Observe-only changes enforcement, not connectivity.
    assert policy.network.egress == "deny"


def test_no_mode_claims_os_level_network_isolation():
    # `network.egress` is a Faraday-level policy statement. The audit policy
    # must not be used to imply OS-level isolation.
    for mode in MODES:
        policy = mode_policy(mode)

        assert policy.network.egress in ("allow", "deny")


def test_init_preset_writes_expected_mode(tmp_path):
    # `init` refuses to overwrite an existing config without --force, so each
    # mode needs its own directory.
    for mode in MODES:
        target = tmp_path / mode
        target.mkdir()

        result = run_faraday("init", "--preset", mode, cwd=target)

        assert result.returncode == 0, mode

        shown = run_faraday("gate", "--show", cwd=target)

        assert f"Mode: {mode}" in shown.stdout, mode


def test_init_preset_rejects_unknown_mode(tmp_path):
    result = run_faraday("init", "--preset", "bogus", cwd=tmp_path)

    assert result.returncode == 2
    assert not (tmp_path / ".faraday" / "config.yaml").exists()


def test_gate_switch_applies_full_preset(workspace):
    # `gate --mode` and `init --preset` must produce the same policy, otherwise
    # the two documented ways of choosing a mode disagree.
    switched = run_faraday("gate", "--mode", "observe-only", cwd=workspace)
    assert switched.returncode == 0

    shown = run_faraday("gate", "--show", cwd=workspace).stdout

    assert "Mode: observe-only" in shown
    assert "Secret action: warn" in shown
    assert "Injection action: warn" in shown


def test_gate_switch_preserves_custom_deny_paths(workspace):
    # A user's custom deny paths must survive a mode change.
    import yaml

    from faraday.config import config_path, load_policy, save_policy

    policy = load_policy()
    policy.paths.deny.append("**/custom-secret/**")
    save_policy(policy, config_path())

    run_faraday("gate", "--mode", "observe-only", cwd=workspace)

    reloaded = yaml.safe_load(config_path().read_text())

    assert "**/custom-secret/**" in reloaded["paths"]["deny"]


def test_observe_only_does_not_block_on_secrets(workspace):
    run_faraday("init", "--force", "--preset", "observe-only", cwd=workspace)

    result = run_faraday(
        "scan", "--prompt", "key sk_test_fake1234567890", cwd=workspace
    )

    # Warnings are recorded, but the operation is not blocked.
    assert result.returncode == 0


def test_strict_local_blocks_on_secrets(workspace):
    run_faraday("init", "--force", "--preset", "strict-local", cwd=workspace)

    result = run_faraday(
        "scan", "--prompt", "key sk_test_fake1234567890", cwd=workspace
    )

    assert result.returncode == 1
