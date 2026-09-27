"""Shared test fixtures.

Tests run against the real CLI and real filesystem. Where a test needs an
isolated workspace it changes into ``tmp_path`` rather than mocking the
filesystem, so the code paths exercised are the ones users actually hit.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """An isolated working directory with Faraday state initialized.

    Writes the real `.faraday/config.yaml` via the same code path as
    `faraday init`, because protected commands fail closed (exit 2) when the
    config is missing. Creating only the directories is not enough.
    """

    monkeypatch.chdir(tmp_path)

    from faraday.config import save_policy
    from faraday.core.policy import default_policy

    save_policy(default_policy())

    return tmp_path


@pytest.fixture()
def sample_repo(tmp_path):
    """A copy of the bundled fake demo repository inside tmp_path."""

    source = REPO_ROOT / "samples" / "repo"
    destination = tmp_path / "repo"

    shutil.copytree(source, destination)

    # Never let stale bytecode travel with the fixture.
    for cache in destination.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)

    return destination
