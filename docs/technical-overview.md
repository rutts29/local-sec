# local-sec technical overview

This document carries the detailed behavior and implementation notes for `local-sec`. Keep the root `README.md` concise; put operational detail, policy nuance, and future-phase notes here.

## Current CLI

```sh
lsec version
lsec preflight npm install <package>
lsec evidence npm install <package>
lsec preflight npm install
lsec guard npm install <package>
lsec preflight python3 -m pip install <package>
lsec preflight python3 -m pip install -r requirements.txt
lsec guard uvx <tool>
lsec install-shims
lsec doctor
lsec status
lsec history [limit]
lsec packages [limit]
lsec show <run_id>
lsec scan --profile baseline|project|deep [--root PATH] [--network off|advisories] [--format table|json|ndjson] [--findings-only] [--redact-paths home|all|hash]
lsec sandbox run --mode docker-fixture [--docker PATH] -- <command> ...
lsec remote-sandbox prepare <run_id> [--out PATH]
lsec remote-sandbox submit-fake <run_id> [--result PATH]
lsec notify plan <run_id> [--out PATH]
lsec notify list [limit]
lsec notify mark-sent <notification_id>
lsec inbox [limit]
lsec inbox show <run_id>
lsec inbox review-llm <run_id> --model <model> [--base-url <loopback-url>] [--timeout <duration>]
lsec inbox approve-once <run_id> [reason...]
lsec inbox deny <run_id> [reason...]
lsec inbox view-later <run_id> [reason...]
lsec approvals list
lsec approvals add <ecosystem> <name> <version> <64-hex-sha256> [reason]
lsec approvals suggest <run_id>
lsec approvals revoke <ecosystem> <name> <version> [64-hex-sha256]
```

## Phase 1 behavior

- Classifies protected commands: `npm`, `npx`, `pip`, `pip3`, `python -m pip`, `python3 -m pip`, `py -m pip`, versioned `python3.x -m pip`, `uv`, `uvx`, `pipx`, `curl`, and `wget`.
- Resolves package metadata from npm or PyPI when possible.
- Prefers the newest mature version over a too-new latest version.
- Applies the same maturity gate to staged dependency artifacts and npm lockfile entries whose package/version can be identified.
- Treats npm dist-tags and ranges such as `@latest`, `@next`, and `@^1.2.3` as unresolved requests so they flow through mature-version selection.
- Maps `npm init`, `npm create`, and `npm innit` initializers to the actual `create-*` package that npm will execute, then rewrites approved runs to `npm exec <create-package>@<selected-version>`.
- For one-shot execution, reads package identity from `npx` / `npm exec` `--package` / `-p` flags, `uvx` / `uv tool run` `--from` flags, and `pipx run --spec` instead of auditing the command name.
- Stages artifacts in `~/.local-sec/staging/<run-id>/`.
- Uses recursive npm lockfile-only staging plus registry tarball downloads, or recursive wheel-only `pip download`, for pre-install artifact capture.
- Runs package-manager staging with a per-run fake `HOME`, config, and cache directories under the staging directory.
- For `python -m pip` and versioned Python interpreter shims, runs wheel-only staging through the same Python executable that the final install will use.
- Extracts and scans staged artifacts before running the real install.
- Applies embedded skillpack pattern sets from `internal/lsec/skillpacks` for credential exfiltration, network behavior, obfuscation, macOS persistence, and agent persistence without requiring external runtime files.
- Caps direct downloader payloads and extracted archive members at 128 MiB per file.
- When one top-level npm tarball or Python wheel is staged, `guard` installs that exact staged artifact instead of re-fetching the package by version; real npm installs run with `--ignore-scripts`, and single-wheel pip installs run with `--no-index --no-deps`.
- When an approved `curl` or `wget` download is staged, `guard` streams the staged bytes to stdout instead of re-running the downloader; reports and prompts go to stderr so stdout remains safe for the approved payload.
- Python wheelhouses with resolved dependency wheels are installed with `--no-index --find-links`, so pip can satisfy dependencies only from staged, scanned wheels.
- Strict pinned and SHA256-hashed Python requirements files, including pip-compile style hash continuations, are parsed, downloaded wheel-only with dependencies using `--require-hashes`, advisory-checked package-by-package and artifact-by-artifact, and installed from the staged wheelhouse with `--require-hashes --no-index --find-links`.
- Bare project `npm install` is allowed only with an auditable `package-lock.json`; exact locked packages with integrity are maturity-checked and advisory-checked, then `guard` rewrites to `npm ci --ignore-scripts`.
- Exact package specs from pinned and hashed Python requirements files and npm lockfiles are maturity-checked and advisory-checked before requirements wheel staging or npm lockfile execution continues.
- Queries OSV for the selected package/version, exact dependency versions discovered in staged metadata, and every exact package/version identified from staged npm/PyPI artifacts.
- If the newest mature candidate has an advisory and only a too-new clean candidate remains, selects the fresh clean candidate into the risky lane instead of silently holding the known-vulnerable version.
- If installed, also runs Socket package scoring for npm/PyPI top-level and discovered dependency versions, plus Snyk JSON checks for npm package versions.
- Caches advisory results in `~/.local-sec/advisory-cache.json` and fails closed when OSV refresh fails without a fresh cache.
- Writes JSONL events and, when the system `sqlite3` CLI exists, persists events, artifacts, package-version records, static findings, advisory checks, approvals, and resolution decisions.
- Summarizes local state with `lsec status`, including unique run count, package count, approval count, approved artifact count, verdict counts, and lane counts.
- Lists recent local run history with `lsec history [limit]`, including run id, event kind, verdict, lane, and command from the JSONL event log.
- Lists deduplicated staged package/artifact inventory with `lsec packages [limit]`, including ecosystem, package, version, hash, verdict, lane, approval status, and source run id.
- Prints a stored run report as JSON with `lsec show <run_id>` for local audit, approval review, and later handoff debugging.
- Generates exact package/version/hash approval commands for non-blocked runs with `lsec approvals suggest <run_id>` from stored staged artifact evidence.
- Lists local prompt/risky runs with `lsec inbox [limit]`; `show` prints a secret-free evidence bundle, `review-llm` explicitly sends redacted evidence to loopback-only Ollama with cache-backed sanitized review events, `approve-once` adds exact package/version/hash approvals for the run artifacts, and `deny` or `view-later` append local review markers.
- Emits secret-free evidence bundles with `lsec evidence <command> ...` for local inbox review and later sandbox or LLM layers, including a stable `evidence_sha256` that can key artifact-review caches.
- `doctor` verifies shim PATH order, shim existence, executable bits, and whether each shim invokes `local-sec guard <command>` instead of accepting arbitrary executable files in the shim directory. It also reports optional integrations by capability state: active scan/advisory providers, preflight advisory amplifiers, detected-only future integrations, and fixture/local-evidence helpers. On Darwin/macOS, detected-only future integration reporting includes endpoint app presence for `BlockBlock.app`, `LuLu.app`, and `KnockKnock.app`; these checks are visibility-only context and do not perform active enforcement.

## Phase 2.5 scanner

`lsec scan` is a metadata-first inventory scanner, not a generic disk or source-code scanner. Its inventory backend is built in, and it writes canonical local scan bundles under `~/.local-sec/scans/<run-id>/`:

- `inventory.ndjson`
- `findings.ndjson`
- `diagnostics.ndjson`
- `summary.json`
- `provider-snapshots.json`
- `catalog-snapshots.json`
- `report.txt`

The initial scanner supports:

- npm `package-lock.json`, `npm-shrinkwrap.json`, and `node_modules/.package-lock.json` package entries as `declared` observations.
- Python `*.dist-info/METADATA` and `*.egg-info/PKG-INFO` as `installed` observations.
- Homebrew `Cellar/<name>/<version>/INSTALL_RECEIPT.json` receipts as `installed` observations.
- VS Code-family extension manifests under extension roots as sanitized `configured` observations.
- project `.mcp.json` files as sanitized `configured` observations for recognizable npm-backed `npx` server specs.
- CycloneDX JSON SBOM files named exactly `bom.json`, `sbom.json`, or `*.cdx.json` as sanitized `configured` observations for exact npm, PyPI, and Homebrew components identified from supported package URLs.
- built-in narrow host-IOC checks for known agent/editor persistence file paths such as `.claude/setup.mjs`, `.claude/router_runtime.js`, and `.vscode/setup.mjs`.
- optional `--catalog PATH` JSON exposure catalogs with exact package/version entries and narrow `known_file_path` IOCs.
- OSV `/v1/querybatch` advisory correlation when `--network advisories` is enabled, backed by the local advisory cache.
- Optional `osv-scanner` advisory findings in `--network advisories` mode for explicit npm `package-lock.json` and `npm-shrinkwrap.json` files under the requested roots. Missing `osv-scanner` is recorded as provider `not_available` and does not make the scan fail.
- Optional `pip-audit` advisory findings in `--network advisories` mode for regular files named exactly `requirements.txt` under the requested roots when every entry is exact-pinned and hash-checked. Missing `pip-audit` is recorded as provider `not_available` and does not make the scan fail.
- Optional `grype` advisory findings in `--network advisories` mode for CycloneDX SBOM files already accepted as `cyclonedx_sbom` inventory observations. Missing `grype` is recorded as provider `not_available` and does not make the scan fail. If Grype fails after earlier SBOMs succeed, successful findings are kept and the provider snapshot records `error`.

Privacy and safety defaults:

- It reads allowlisted metadata filenames only.
- It skips symlinks and non-regular files.
- By default, `lsec scan` uses `--network advisories`; `--network off` is the no-network, no-external-scanner mode.
- CycloneDX ingestion uses only `components[].purl` for supported package identities; it does not emit SBOM properties, licenses, hashes, authors, BOM metadata, external references, or package URL qualifiers/subpaths.
- It does not read `.env`, shell history, source files, browser data, SSH keys, cloud credentials, or agent transcripts.
- MCP `env`, headers, token-like arguments, and secret values are not emitted.
- `--network off` performs local inventory and local catalog matching only.
- `--network advisories` sends only normalized ecosystem/name/version tuples to OSV. It does not send file paths or local project names to OSV. If `osv-scanner` is present, `local-sec` also invokes it only on explicit npm lockfiles, not source files or `node_modules` lockfiles. If `pip-audit` is present, `local-sec` invokes it only on safe pinned-and-hashed `requirements.txt` files and skips virtualenv, `site-packages`, `node_modules`, source, and unsafe requirements contents. If `grype` is present, `local-sec` invokes it only as `grype sbom:<path> -o json` for accepted CycloneDX SBOM inventory paths and never passes project roots, source directories, malformed or non-CycloneDX files, symlinks, non-regular files, or arbitrary files.
- Optional external scan providers run with a timeout, an isolated temporary working directory, fake `HOME` and XDG cache/config directories, a limited env allowlist (`PATH`, `NO_COLOR`, and safe proxy variables only), credentialed proxy variables dropped, and stdout/stderr captured separately and capped separately.
- `--findings-only` omits inventory observations from terminal output while keeping the canonical local bundle intact.
- `--redact-paths home|all|hash` redacts paths in terminal output and persisted scan bundles for shareable reports.

## Phase 3 Docker fixture CLI

`lsec sandbox run --mode docker-fixture [--docker PATH] -- <command> ...` runs a harmless fixture command through the existing Docker fixture sandbox and prints a redacted `SandboxResult` JSON document to stdout. The `--` separator is required before the fixture command. `--mode docker-fixture` is the only supported mode, and `--docker PATH` exists so tests and operators can point at a fake or controlled Docker executable.

This CLI is a fixture path only. It is not wired into `preflight` or `guard`, and it is not a malicious-package detonation workflow.

## Phase 4 remote sandbox control plane

`lsec remote-sandbox prepare <run_id> [--out PATH]` loads a stored run, builds a redacted `EvidenceBundle`, and emits a versioned remote-sandbox request with `run_id`, `evidence_sha256`, `created_at`, and `redacted: true`. With `--out`, parent directories are created with `0700` permissions and the JSON file is written atomically with `0600` permissions.

`lsec remote-sandbox submit-fake <run_id> [--result PATH]` uses the same redacted evidence boundary and produces a deterministic local fake result shape for tests. It does not open a network connection, start a shell, use SSH, contact a cloud provider, or run Docker. It appends only sanitized result metadata and the evidence hash as a `remote_sandbox` event; it does not persist the raw request or evidence bundle in that event.

Remote result findings can carry blocking severity for later policy wiring, but this slice does not connect remote findings to `guard`, `preflight`, approvals, or install decisions.

## Phase 6 local notification outbox

`lsec notify plan <run_id> [--out PATH]` loads a stored run and emits a versioned, redacted notification payload for human review. The payload includes `notification_id`, `run_id`, `evidence_sha256`, verdict, lane, command summary, package artifact identities, risk summaries, `created_at`, and `redacted: true`. It does not send Discord webhooks or any other network request.

With `--out`, notification payloads use the same private atomic writer and path-safety checks as remote sandbox outputs. Each planned notification appends a sanitized `notification_planned` JSONL event. `lsec notify list [limit]` shows unsent planned notifications newest first, and `lsec notify mark-sent <notification_id>` appends a local `notification_sent` bookkeeping event only.

## Default verdicts

Every decision also carries a risk lane:

- `trusted`: deterministic allow path
- `risky`: prompt/review path
- `block`: hard stop

Blocks:

- downloader output piped to shell
- plain HTTP downloader URLs before network access
- HTTPS downloader URLs that redirect to plain HTTP
- downloader commands with more than one URL; download one URL at a time so staged bytes and approvals remain unambiguous
- direct downloader payloads larger than 128 MiB
- known malware or critical advisories
- advisory refresh failures when no fresh local cache exists
- installed Socket/Snyk advisory checks that fail without parseable advisory output
- multi-package installs while the MVP only gates one selected package/version
- one-shot execution when the actual package identity cannot be determined, or when multiple packages are requested in one one-shot command
- version ranges such as npm `@^1.2.3` or PyPI `>=`, `<`, `~=`, and `!=` specs until range-aware mature-version selection is implemented
- alternate package sources such as npm `--registry`, npm `--userconfig`, pip `--index-url`, pip `--extra-index-url`, pip `--find-links`, pip `--no-index`, and pip `--trusted-host`
- pip constraint files through `-c` or `--constraint`, because they can change dependency resolution outside the audited package set
- unsafe requirements-file entries such as VCS URLs, direct URLs, options, markers, or unpinned specs
- bare npm installs without `package-lock.json`, or lockfile entries missing exact versions/integrity
- package-lock entries resolved from VCS, local paths, relative tarballs, non-HTTPS URLs, or hosts other than `registry.npmjs.org`
- npm workspace/prefix installs until scope-aware auditing is implemented
- credential-path access combined with network or process execution
- persistence write patterns such as LaunchAgents, cron, systemd, shell rc files, and agent config hooks
- Python startup persistence through executable `.pth`, `sitecustomize.py`, or `usercustomize.py` files
- obfuscation combined with network behavior
- staged scripts that download remote content and pipe it to a shell
- npm/npx VCS, direct URL, or local path specs before npm staging, because those spec types can execute package hooks during staging or one-shot execution
- pip/PyPI VCS, direct URL, bare local archive, local path, or editable specs before `pip download`, because those bypass registry maturity and advisory selection
- uv and pipx VCS or direct URL specs until their direct-artifact policy is implemented
- `uv add`, `uv pip install`, and `pipx install` until wheel-only staging and safe execution rewrites are implemented
- Python source builds or wheel-only download failure
- npm installs whose staged dependency graph contains more than one tarball, because recursive npm dependency bytes are scanned but exact-byte final install promotion is not implemented yet

Prompts:

- package/version inside the 7-day maturity window
- npm lockfile package versions or staged dependency artifact versions inside the 7-day maturity window, or versions whose publish time cannot be verified
- pinned versions when registry publish age cannot be verified or is inside the maturity window
- packages that have not appeared in local-sec's previous staged package history
- maintainers that have not appeared in local-sec's previous history for that package
- `npx`, `uvx`, `pipx run`, `npm exec`, and `npm init`
- npm lifecycle scripts
- HTTPS direct downloader URLs and global installs
- standalone credential path references, network APIs, process execution, or obfuscation

Allows:

- mature selected versions with clean staged scans, no unstaged dependency graph, and clean advisories
- exact package/version/hash entries added through `lsec approvals add`

## MVP fail-closed workarounds

Phase 1 intentionally refuses `npm install a b c` because ad hoc batch installs still need per-package staging. Bare `npm install` is allowed only as a project install backed by `package-lock.json` whose resolved tarballs point at `https://registry.npmjs.org`; the safe execution path is rewritten to `npm ci --ignore-scripts`. Python `requirements.txt` files are allowed only when every active entry is pinned with `==` and has at least one 64-hex `--hash=sha256:<digest>` value; backslash continuations are supported for hash lines. VCS URLs, direct URLs, pip options other than `--hash`, environment markers, unpinned/ranged entries, unhashed entries, and dangling continuations fail closed. Ad hoc npm/PyPI range specs also fail closed so `local-sec` never silently installs a different exact version than the requested range intended. PyPI installs now use recursive wheel-only staging and install only from the staged wheelhouse. npm installs now recursively stage and scan registry tarballs, but runs with transitive npm tarballs block until exact-byte final install promotion is implemented; this avoids falling back to unscanned registry bytes or installing transitive tarballs as direct dependencies.

Socket and Snyk are optional advisory amplifiers, not the enforcement core. When their CLIs are present, `local-sec` treats critical or malware findings as policy-blocking advisories and treats lower-severity findings as prompts. If an installed Socket or Snyk check fails without parseable advisory output, the run fails closed. Missing optional CLIs are reported by `lsec doctor`; they do not disable OSV fail-closed checks. Persistent approvals are exact package/version/hash records with lowercase 64-hex SHA256 hashes; adding the same exact record updates it instead of duplicating it. `preflight` prints staged artifact hashes so an approval cannot silently cover different bytes. `lsec approvals suggest <run_id>` refuses blocked runs, so known-malware or hard-policy failures do not produce allowlist commands. For staged installs with dependency wheels, every staged artifact must have its own exact approval before persistent approvals can turn a prompt into an allow.

## Later phases

The repo exposes secret-free evidence bundles for handoff into container detonation, canary analysis, and LLM review. Each bundle includes a stable `evidence_sha256` computed over the bundle contents, excluding the hash field itself, so later sandbox and LLM decisions can be cached against the exact evidence reviewed.

Planned layers:

- container detonation for risky packages
- fake-home canaries and network sinkhole/proxy capture
- LLM evidence review with deterministic scanners retaining final authority
- Discord notifications for local inbox events keyed by `run_id`
- broader endpoint and SBOM integrations such as Bumblebee, Syft, cargo-vet, deeper OSV-Scanner coverage beyond the current npm-lockfile advisory hook, and SBOM or endpoint workflows beyond the current optional `grype` SBOM provider and optional `pip-audit` requirements provider

## Release model

`local-sec` is maintained as a single static Go binary with no third-party Go module dependencies. Releases are built only from version tags. `scripts/build-release.sh` enforces this by default: `HEAD` must be exactly on a version tag, and the Git working tree must be clean. Setting `LSEC_RELEASE_ALLOW_UNTAGGED=1` bypasses both checks for local/test builds and uses `VERSION`, or the repository `VERSION` file when the variable is unset; this bypass is not for published release artifacts.

```sh
make test
make release
make verify-release
```

Release archives are produced under `dist/` for:

- `darwin/arm64`
- `darwin/amd64`
- `linux/arm64`
- `linux/amd64`
- `windows/amd64`

Each release directory contains exactly five `.tar.gz` archives plus `checksums.txt`, whose five entries name those archives exactly. Release scripts normalize a leading `v` tag prefix, so tag `v0.1.0` produces `lsec_0.1.0_*` archives and a `VERSION` file containing exactly `0.1.0` plus one newline. Every archive contains exactly its top-level directory, `docs/` directory, platform binary, `README.md`, `VERSION`, `docs/technical-overview.md`, and `docs/roadmap.md`; files must be regular files, and Unix binaries must have owner execute permission. Windows binaries have no Unix execute-bit requirement. `make verify-release` validates names before checksum paths are read, then checks hashes and archive structure. Install only a tested release artifact whose checksum matches.
