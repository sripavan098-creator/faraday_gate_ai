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
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT_CONFIG = REPO_ROOT / "vercel.json"
WEB_CONFIG = REPO_ROOT / "web" / "vercel.json"
INDEX_HTML = REPO_ROOT / "web" / "index.html"
REPORT_JS = REPO_ROOT / "web" / "report.js"
LANDING_JS = REPO_ROOT / "web" / "landing.js"
LANDING_CSS = REPO_ROOT / "web" / "landing.css"
VENDOR = REPO_ROOT / "web" / "vendor"

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


def test_index_makes_no_cross_origin_requests() -> None:
    """The CSP blocks other origins, so any absolute URL would simply fail.

    The page is a statement about zero-egress tooling; it should not phone a CDN
    for a font or a script while saying so.
    """
    html = INDEX_HTML.read_text()
    for match in re.finditer(r'(?:src|href)\s*=\s*"([^"]+)"', html):
        target = match.group(1)
        if target.startswith(("http://", "https://")):
            # Documentation links are fine; subresources are not.
            assert not re.search(r'\.(js|css|woff2?|svg)$', target), (
                f"subresource loaded from another origin: {target}"
            )
        assert "//fonts.googleapis.com" not in target
        assert "//fonts.gstatic.com" not in target
        assert "//cdnjs.cloudflare.com" not in target


def test_vendored_assets_are_present() -> None:
    """Every same-origin asset the page references must actually be committed."""
    html = INDEX_HTML.read_text()
    refs = [
        m.group(1)
        for m in re.finditer(r'<(?:script|link)[^>]*?(?:src|href)="([^"]+)"', html)
    ]
    assert refs, "expected the page to reference its assets"
    for ref in refs:
        if ref.startswith(("http://", "https://", "#")):
            continue
        assert (REPO_ROOT / "web" / ref).is_file(), f"missing asset: web/{ref}"


def test_font_css_has_no_remote_sources() -> None:
    css = (VENDOR / "fonts.css").read_text()
    assert "fonts.gstatic.com" not in css
    assert "https://" not in css
    for match in re.finditer(r"url\(([^)]+)\)", css):
        target = match.group(1).strip("'\"")
        assert not target.startswith("http"), f"remote font source: {target}"
        assert (VENDOR / target).is_file(), f"missing font file: {target}"


def test_landing_js_has_no_syntax_errors() -> None:
    """An octal escape under 'use strict' silently kills the whole script.

    That is exactly what happened once: the scene never started and the page
    looked fine, because a parse error in an external script is invisible in the
    markup. Compile it here instead.
    """
    for path in (LANDING_JS, REPORT_JS):
        result = subprocess.run(
            ["node", "--check", str(path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 and "not found" in result.stderr:
            pytest.skip("node is not available to syntax-check the scripts")
        assert result.returncode == 0, f"{path.name} failed to parse:\n{result.stderr}"


def test_landing_css_and_html_agree_on_class_names() -> None:
    """Catch a stylesheet rename that leaves the markup pointing at dead classes."""
    css = LANDING_CSS.read_text()
    html = INDEX_HTML.read_text()
    # The report viewer's class names are produced by report.js, not the markup,
    # so only check the classes the page itself declares.
    for name in ("bar", "hud", "feed", "chips", "tx", "doc", "verdict"):
        assert f".{name}" in css, f".{name} missing from landing.css"
    assert 'class="feed"' in html
    assert 'class="hud"' in html

