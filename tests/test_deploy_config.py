"""Guards for the static deploy configuration.

The web site is plain static files, but Vercel autodetects Python projects. A
Typer CLI in ``faraday/cli.py`` looks like an entrypoint candidate, and wiring it
up would deploy an app that raises on the first request. These tests pin the
deploy shape so that cannot happen silently.

They also pin the security headers, because the header block has to exist in two
files: Vercel applies the config at the deploy root and ignores a nested one, so
depending on the Root Directory setting either ``vercel.json`` or
``web/vercel.json`` is the one in effect.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT_CONFIG = REPO_ROOT / "vercel.json"
WEB_CONFIG = REPO_ROOT / "web" / "vercel.json"
INDEX_HTML = REPO_ROOT / "web" / "index.html"
REPORT_JS = REPO_ROOT / "web" / "report.js"

EXPECTED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _header_map(config: dict) -> dict[str, str]:
    return {
        h["key"]: h["value"]
        for rule in config.get("headers", [])
        for h in rule.get("headers", [])
    }


def test_vercel_configs_are_valid_json() -> None:
    for path in (ROOT_CONFIG, WEB_CONFIG):
        assert isinstance(_load(path), dict)


def test_no_python_entrypoint_is_declared() -> None:
    """A Python entrypoint here would deploy a CLI as a web app.

    ``faraday.cli:app`` is a Typer application: it takes no ASGI ``scope`` or
    WSGI ``environ``, so it raises TypeError on the first request. Vercel must
    serve the static site instead.
    """
    for path in (ROOT_CONFIG, WEB_CONFIG):
        config = _load(path)
        assert "entrypoint" not in config, f"{path} must not declare an entrypoint"
        assert "tool" not in config, f"{path} must not carry a [tool.vercel] block"


def test_root_config_serves_the_static_site() -> None:
    """Without this, Vercel would scan the repo root and try to build Python."""
    config = _load(ROOT_CONFIG)
    assert config["outputDirectory"] == "web"
    assert config["buildCommand"] == ""
    assert config["installCommand"] == ""
    assert config["framework"] is None


@pytest.mark.parametrize("path", [ROOT_CONFIG, WEB_CONFIG])
def test_security_headers_present(path: Path) -> None:
    headers = _header_map(_load(path))
    for key, value in EXPECTED_HEADERS.items():
        assert headers.get(key) == value, f"{key} missing or changed in {path}"


@pytest.mark.parametrize("path", [ROOT_CONFIG, WEB_CONFIG])
def test_csp_is_locked_down(path: Path) -> None:
    csp = _header_map(_load(path))["Content-Security-Policy"]

    assert csp.startswith("default-src 'none'")
    assert "connect-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'none'" in csp
    # 'unsafe-inline' would defeat the point of shipping a CSP at all.
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_header_blocks_stay_in_sync() -> None:
    """Both configs must carry identical headers.

    Vercel applies the config at the deploy root and ignores the nested one, so
    if the two drift, whichever is not in effect silently loses its headers.
    """
    assert _load(ROOT_CONFIG)["headers"] == _load(WEB_CONFIG)["headers"]


def test_index_has_no_inline_handlers_or_styles() -> None:
    """The CSP has no 'unsafe-inline', so inline handlers would be blocked."""
    html = INDEX_HTML.read_text()
    for attr in ("onclick=", "onload=", "onerror=", "onsubmit=", "style="):
        assert attr not in html, f"inline {attr} would be blocked by the CSP"


def test_index_loads_only_same_origin_scripts() -> None:
    html = INDEX_HTML.read_text()
    assert "<script" in html
    # No inline <script> blocks: every script tag must carry a src attribute.
    for chunk in html.split("<script")[1:]:
        assert "src=" in chunk.split(">")[0], "inline <script> blocked by CSP"


def test_report_viewer_never_uses_dom_injection() -> None:
    """Report fields derive from repository content and could contain markup.

    Matches real property/method use rather than the bare word, since the file's
    own comment explains that it deliberately avoids innerHTML.
    """
    code = REPORT_JS.read_text()
    for pattern in (
        r"\.innerHTML",
        r"\.outerHTML",
        r"insertAdjacentHTML",
        r"document\.write",
        r"\beval\(",
        r"new Function\(",
    ):
        assert not re.search(pattern, code), f"unsafe DOM API in report.js: {pattern}"
