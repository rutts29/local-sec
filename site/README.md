# local-sec landing page

A single, self-contained `index.html` (inline CSS + JS, zero dependencies) with a
dark terminal aesthetic and macOS "liquid glass" panels. No build step.

## Run locally

Open the file directly, or serve it so relative behavior matches production:

```sh
python3 -m http.server 8080
# → http://localhost:8080
```

## Deploy

The page lives in `site/`. The repo includes deploy configs at the root.

### Netlify

`netlify.toml` sets `publish = "site"`. Import the repo at
[app.netlify.com/start](https://app.netlify.com/start) — no build command needed.

### Vercel

Import the repo at [vercel.com/new](https://vercel.com/new). Under project
settings set **Root Directory** (or **Output Directory**) to `site`, then deploy.
`vercel.json` adds clean URLs and security headers.

### GitHub Pages (alternative)

Serve `site/` from a branch (e.g. move/copy `index.html` to the root of a
`gh-pages` branch, or point Pages at the `site` folder via GitHub Actions).

## Editing

All content and styling is in `index.html`. The three hero-terminal scenarios
(`trusted`, `risky`, `block`) are defined in the `<script>` near the bottom.
