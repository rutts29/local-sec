# local-sec

`local-sec` is a local-first supply-chain guard for developer package installs. It is designed to make package installs slower only when they deserve scrutiny: fresh versions, one-shot execution, source builds, install scripts, direct URLs, suspicious static findings, or known advisories.

The project is maintained as a single Go binary with no third-party Go module dependencies.

## What works now

- Pre-install guards for npm/PyPI/uv-style workflows:
  - `npm`, `npx`, `npm exec`, `npm init`
  - `pip`, `pip3`, `python -m pip`, `python3 -m pip`
  - `uv`, `uvx`, `pipx`
  - `curl`, `wget`
- Mature-version selection so `latest` does not automatically mean safest.
- Artifact staging for supported npm, pip, and downloader paths in `~/.local-sec/staging/<run-id>/`; project lockfile installs use an audited rewrite without artifact staging, while one-shot paths can defer staging for review or be blocked.
- Static artifact scanning for credential access, network behavior, obfuscation, persistence, Python startup hooks, npm lifecycle scripts, and agent/editor config paths.
- Advisory refresh through OSV, with optional Socket and Snyk enrichment when those CLIs are already installed.
- Exact package/version/hash approvals.
- JSONL and optional SQLite local history.
- Privacy-conscious, metadata-first local exposure scanning through `lsec scan`.
- Single-binary release archives with checksum verification.

## Current commands

```sh
lsec preflight npm install <package>
lsec guard npm install <package>
lsec preflight python3 -m pip install <package>
lsec guard uvx <tool>
lsec scan --profile project --root .
lsec evidence npm install <package>
lsec sandbox run --mode docker-fixture -- npm install <package>
lsec approvals list
lsec approvals suggest <run_id>
lsec inbox [limit]
lsec install-shims
lsec doctor
lsec status
```

`lsec install-shims` writes shims and prints the directory that must be added before package-manager directories in your `PATH`; make that shell change yourself, reload the shell, then run `lsec doctor`. `lsec sandbox run --mode docker-fixture` is a harmless fixture-only command, not a package detonation workflow; its optional preflight attachment runs a harmless command rather than the package.

See [docs/technical-overview.md](docs/technical-overview.md) for the full command list, scanner details, verdict policy, and release notes. Read the [threat model and limitations](docs/threat-model-and-limitations.md) before relying on a verdict, and use [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Scanner

`lsec scan` is not a generic full-disk source-code scanner. It is a privacy-conscious metadata inventory and correlation engine. It reads allowlisted metadata such as npm lockfiles, Python package metadata, Homebrew receipts, editor extension manifests, and sanitized MCP configuration. With `--network advisories`, it can query OSV with normalized ecosystem/name/version tuples and optionally run `osv-scanner`, `pip-audit`, and `grype` against accepted metadata inputs when those tools are already installed.

Canonical scan bundles are written under:

```text
~/.local-sec/scans/<run-id>/
```

## Roadmap

The phased roadmap and safety constraints live in [docs/roadmap.md](docs/roadmap.md). Keep the root README short; use that document for the remaining phase plan and host-safety guardrails.

## Release model

Build and verify locally:

```sh
make test
make release
make verify-release
```

Release archives are produced under `dist/` for macOS, Linux, and Windows. Install only a tested release artifact whose checksum matches `checksums.txt`.
