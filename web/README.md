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

## Verify after deploy

```bash
curl -I https://your-project.vercel.app
```

Confirm the security headers are present. Then check the page renders, the
GitHub link resolves, and the report viewer handles a pasted
`faraday prove latest --format json` payload.
