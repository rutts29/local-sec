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
- Staging into `~/.local-sec/staging/<run-id>/` before the real install.
- Static artifact scanning for credential access, network behavior, obfuscation, persistence, Python startup hooks, npm lifecycle scripts, and agent/editor config paths.
- Advisory refresh through OSV, with optional Socket and Snyk enrichment when those CLIs are already installed.
- Exact package/version/hash approvals.
- JSONL and optional SQLite local history.
- Metadata-only local exposure scanning through `lsec scan`.
- Single-binary release archives with checksum verification.

## Current commands

```sh
lsec preflight npm install <package>
lsec guard npm install <package>
lsec preflight python3 -m pip install <package>
lsec guard uvx <tool>
lsec scan --profile project --root .
lsec evidence npm install <package>
lsec approvals list
lsec approvals suggest <run_id>
lsec install-shims
lsec doctor
lsec status
```

See [docs/technical-overview.md](docs/technical-overview.md) for the full command list, scanner details, verdict policy, and release notes.

## Scanner

`lsec scan` is not a generic full-disk source-code scanner. It is a privacy-conscious metadata inventory and correlation engine. It reads allowlisted metadata such as npm lockfiles, Python package metadata, Homebrew receipts, editor extension manifests, and sanitized MCP configuration. It can match local exposure catalogs and query OSV with only normalized ecosystem/name/version tuples.

Canonical scan bundles are written under:

```text
~/.local-sec/scans/<run-id>/
```

## Roadmap

Planned next layers:

- richer local exposure catalogs and finding history
- Bumblebee/Syft/Grype/pip-audit/OSV-Scanner integrations
- container detonation for risky packages
- fake-home canaries and network sinkhole/proxy capture
- LLM evidence review that can escalate risk but cannot override deterministic blocks
- Discord approval inbox keyed by `run_id`
- macOS-specific detonation and endpoint checks

## Release model

Build and verify locally:

```sh
make test
make release
make verify-release
```

Release archives are produced under `dist/` for macOS, Linux, and Windows. Install only a tested release artifact whose checksum matches `checksums.txt`.
