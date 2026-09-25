from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import List, Optional, Union

from faraday.scanners.base import ScanFinding


def is_denied_path(
    path: Union[str, Path],
    deny_patterns: List[str],
) -> bool:
    """Return True if a path is denied by policy.

    Supports:
        - file name patterns: .env, .env.*, *.pem
        - relative path patterns: **/secrets/**
        - home-directory patterns: ~/.ssh/**, ~/.aws/**
    """

    path_obj = Path(path)
    posix_path = path_obj.as_posix()
    name = path_obj.name

    try:
        absolute_path = path_obj.expanduser().resolve().as_posix()
    except OSError:
        absolute_path = path_obj.expanduser().as_posix()

    for pattern in deny_patterns:
        if not pattern:
            continue

        if pattern.startswith("~"):
            expanded = Path(pattern).expanduser().as_posix()

            if fnmatch.fnmatch(absolute_path, expanded):
                return True

            if absolute_path.startswith(expanded.rstrip("/*")):
                return True

            continue

        if fnmatch.fnmatch(posix_path, pattern):
            return True

        if fnmatch.fnmatch(name, pattern):
            return True

        if pattern.startswith(".env") and (name == ".env" or name.startswith(".env.")):
            return True

    return False


def scan_path_denial(
    path: Union[str, Path],
    deny_patterns: List[str],
) -> Optional[ScanFinding]:
    """Produce a path-denial finding if the path is denied by policy."""

    if not is_denied_path(path, deny_patterns):
        return None

    return ScanFinding(
        type="path",
        severity="critical",
        scanner="path_rules",
        origin=str(path),
        path=str(path),
        line=None,
        rule="denied_path",
        confidence=1.0,
        recommended_action="block",
        details="Path denied by policy",
        start=None,
        end=None,
        matched=None,
    )
