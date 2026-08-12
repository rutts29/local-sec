# local-sec site

Static product site under `site/` — no build step, no dependencies.

| Page | File |
|------|------|
| Landing | `index.html` |
| Docs | `docs.html` |
| Roadmap | `roadmap.html` |
| Shared styles (docs/roadmap) | `site.css` |

Docs and roadmap live on the site itself so they work whether the project stays open source or not. GitHub is only used for the optional corner link and release downloads.

## Run locally

Serve `site/` so multi-page links work:

```sh
cd site && python3 -m http.server 8765
# → http://localhost:8765
```

## Deploy

`netlify.toml` publishes `site/`. On Vercel, set the root/output directory to `site`.
`vercel.json` enables clean URLs and security headers.

## Editing

Landing look-and-feel and hero terminal scenarios live in `index.html`.
Docs/roadmap chrome and prose styles live in `site.css`.
