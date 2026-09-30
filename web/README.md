# Faraday Gate web site

Static documentation and landing site for Faraday Gate.

## What this is — and is not

Faraday Gate's core value is the **local CLI security engine**. Vercel hosts only
public documentation for it.

This site must never contain:

- `.faraday/` state, audit chains, or session logs
- proof reports containing real repository paths or metadata
- real credentials
- any backend that accepts repository content for processing

The proof-report viewer in `report.js` runs entirely in the browser. It parses
JSON a user pastes and never sends it anywhere.

## Files

| File | Purpose |
|---|---|
| `index.html` | Landing page and documentation |
| `styles.css` | Styling (no remote fonts or CDNs) |
| `report.js` | Client-side proof-report viewer |
| `vercel.json` | Security headers, including a strict CSP |

## Security headers

`vercel.json` sets `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, and a `Content-Security-Policy` that
denies everything by default and allows only same-origin scripts and styles.

The CSP does **not** include `'unsafe-inline'`. That is why `index.html` has no
inline `onclick=` handlers or `style=` attributes. Do not add them; they will be
silently blocked.

`report.js` builds every node with `textContent`. Proof reports derive from
repository content, so a file path could contain markup. Never introduce
`innerHTML` for report fields.

## Local preview

```bash
cd web
python3 -m http.server 8000
# open http://localhost:8000
```

## Deploy

```bash
cd web
vercel --prod
```

Vercel settings: **Root Directory** `web`, **Framework Preset** `Other`,
**Build Command** empty, **Output Directory** `.`.

## Why there is no Python entrypoint

Vercel's project detection may report:

> No python entrypoint found in default locations, but found potential
> entrypoints: `faraday/cli.py` (variable: `app`)

**Do not add `entrypoint = "faraday.cli:app"` to `pyproject.toml`.** That would
deploy the CLI as a web application, which cannot work:

- `faraday.cli:app` is a `typer.Typer` instance. Its `__call__` takes `args` /
  `kwargs` and dispatches CLI arguments; it is neither ASGI
  (`app(scope, receive, send)`) nor WSGI (`app(environ, start_response)`).
  Calling it as either raises immediately (`TypeError: str expected, not
  function` / `AttributeError: 'function' object has no attribute 'lstrip'`).
- There is no web framework in the dependency set.
- `faraday dashboard` renders a Rich **terminal** dashboard, not HTML.

The deployable artifact is the static site in `web/`. The root `vercel.json`
pins that explicitly (`outputDirectory: "web"`, empty build and install
commands, no framework) so Vercel never falls back to Python autodetection.

Because Vercel applies the config at the deploy root and ignores a nested one,
the security headers are duplicated in both `vercel.json` and `web/vercel.json`.
A test asserts the two blocks stay identical, so whichever one is in effect
always carries the headers.

## Verify after deploy

```bash
curl -I https://your-project.vercel.app
```

Confirm the security headers are present. Then check the page renders, the
GitHub link resolves, and the report viewer handles a pasted
`faraday prove latest --format json` payload.
