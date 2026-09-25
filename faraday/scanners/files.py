from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

from faraday.core.policy import Policy
from faraday.scanners.base import ScanFinding
from faraday.scanners.path_rules import scan_path_denial
from faraday.scanners.pipeline import scan_text

IGNORE_DIRS = {
    ".git",
    ".faraday",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

DEFAULT_MAX_FILES = 500
DEFAULT_MAX_FILE_BYTES = 1_000_000


@dataclass
class ScannedFile:
    path: str
    size: int
    content_hash: Optional[str]
    classification: str
    denied: bool


@dataclass
class PathScanResult:
    files_scanned: int
    tokens_scanned: int
    findings: List[ScanFinding] = field(default_factory=list)
    scanned_files: List[ScannedFile] = field(default_factory=list)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_files(path: Path) -> Iterator[Path]:
    """Yield candidate files for scanning, ignoring dependency/state dirs."""

    if path.is_file():
        yield path
        return

    for root, dirnames, filenames in os.walk(path):
        root_path = Path(root)

        dirnames[:] = [dirname for dirname in dirnames if dirname not in IGNORE_DIRS]

        for filename in filenames:
            yield root_path / filename


def scan_path(
    target: Path,
    policy: Policy,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> PathScanResult:
    """Scan a file or directory.

    Behavior:
        - denied paths produce path-denial findings
        - large files are skipped and classified as skipped_large
        - allowed text files are scanned by deterministic scanners
    """

    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")

    result = PathScanResult(files_scanned=0, tokens_scanned=0)

    for file_path in iter_files(target):
        if result.files_scanned >= max_files:
            break

        try:
            if target.is_dir():
                rel_path = file_path.relative_to(target)
            else:
                rel_path = Path(file_path.name)
        except ValueError:
            rel_path = Path(file_path.name)

        rel_path_str = rel_path.as_posix()

        try:
            size = file_path.stat().st_size
        except OSError:
            continue

        denial = scan_path_denial(rel_path_str, policy.paths.deny)

        if denial is not None:
            result.files_scanned += 1
            result.findings.append(denial)
            result.scanned_files.append(
                ScannedFile(
                    path=rel_path_str,
                    size=size,
                    content_hash=None,
                    classification="denied",
                    denied=True,
                )
            )
            continue

        if size > max_file_bytes:
            result.scanned_files.append(
                ScannedFile(
                    path=rel_path_str,
                    size=size,
                    content_hash=None,
                    classification="skipped_large",
                    denied=False,
                )
            )
            continue

        try:
            data = file_path.read_bytes()
        except OSError:
            continue

        content_hash = sha256_bytes(data)
        text = data.decode("utf-8", errors="ignore")

        result.files_scanned += 1
        result.tokens_scanned += len(text.split())

        file_findings = scan_text(
            text,
            origin=rel_path_str,
            path=rel_path_str,
            policy=policy,
        )

        result.findings.extend(file_findings)

        result.scanned_files.append(
            ScannedFile(
                path=rel_path_str,
                size=size,
                content_hash=content_hash,
                classification="scanned",
                denied=False,
            )
        )

    return result


def read_git_diff(diff_ref: Optional[str] = None) -> str:
    """Read a git diff as text.

    Examples:
        read_git_diff(None)     -> git diff
        read_git_diff("HEAD")   -> git diff HEAD
    """

    command = ["git", "diff"]

    if diff_ref:
        command.append(diff_ref)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is not available on this system") from exc

    if completed.returncode != 0:
        message = completed.stderr.strip() or "git diff failed"
        raise RuntimeError(message)

    return completed.stdout
