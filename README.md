# local-sec

`local-sec` is a local-first supply-chain guard for developer package installs. It is designed to make package installs slower only when they deserve scrutiny: fresh versions, one-shot execution, source builds, install scripts, direct URLs, suspicious static findings, or known advisories.

Built as a single Go binary with no third-party Go module dependencies.

## What it does

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

## Build from source

Requires Go 1.25 or newer and Make.

```sh
git clone https://github.com/rutts29/local-sec.git
cd local-sec
make build
./dist/lsec
```

## Usage

Check an install without executing it. Replace `package-name` with the package you want to inspect:

```sh
./dist/lsec preflight npm install package-name
```

After reviewing the result, use `guard` to run the install through the policy checks:

```sh
./dist/lsec guard npm install package-name
```

Inspect a project's package metadata and review local approvals:

```sh
./dist/lsec scan --profile project --root .
./dist/lsec approvals list
./dist/lsec status
```

Put the binary on your `PATH` to use it as `lsec`. Optional `lsec install-shims` writes shims and prints the directory that must be added before package-manager directories in your `PATH`; make that shell change yourself, reload the shell, then run `lsec doctor`.

See [docs/technical-overview.md](docs/technical-overview.md) for the full command list, scanner details, verdict policy, and release notes. Read the [threat model and limitations](docs/threat-model-and-limitations.md) before relying on a verdict, and use [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Scanner

`lsec scan` is not a generic full-disk source-code scanner. It is a privacy-conscious metadata inventory and correlation engine. It reads allowlisted metadata such as npm lockfiles, Python package metadata, Homebrew receipts, editor extension manifests, and sanitized MCP configuration. With `--network advisories`, it can query OSV with normalized ecosystem/name/version tuples and optionally run `osv-scanner`, `pip-audit`, and `grype` against accepted metadata inputs when those tools are already installed.

Canonical scan bundles are written under:

```text
~/.local-sec/scans/<run-id>/
```

## Roadmap

The [roadmap](docs/roadmap.md) covers the remaining work and safety constraints.

## Development and release packaging

Run the tests with `make test`. To build release archives, use a clean checkout whose `HEAD` is exactly on a version tag. The output directory must not already exist:

```sh
DIST=dist-release make release
DIST=dist-release make verify-release
```

This builds archives for macOS, Linux, and Windows under `dist-release/`, including the license and documentation. Verify `checksums.txt` before installing an archive. See the [technical overview](docs/technical-overview.md) for local packaging checks and fixture-only sandbox development.

## License

[Apache License 2.0](LICENSE). Shared for others to run, study and adapt.
