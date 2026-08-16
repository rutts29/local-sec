# local-sec roadmap

This roadmap keeps the remaining phases practical and safety-first. It is intentionally narrower than a product vision doc: the goal is to sequence real work without relaxing the host-safety bar.

## Safety guardrails

These constraints apply to every remaining phase:

- Never execute a malicious or suspected-malicious package on the host Mac.
- Never mount or forward a real home directory, personal files, secrets, shell history, cloud credentials, or agent transcripts into local Docker, remote sandboxes, LLM prompts, or approval messages.
- Local Docker testing stays limited to harmless fixtures unless there is later explicit approval for broader samples.
- Dynamic malicious-package testing is deferred to disposable remote, VPS, or Mac VM environments built for detonation.
- LLM review receives redacted evidence only. It may escalate risk or summarize evidence, but it cannot downgrade a deterministic block.
- Future Ollama or Gemma experiments stay local and evidence-only; no raw secrets, host paths, or live detonation data are sent to a model.

## Phase R cleanup

Status: cleanup implemented; keep this phase open only for release-check follow-through.

Goal: finish the current local-first baseline so later phases build on stable evidence, policy, and operator workflows instead of moving targets.

Completed cleanup in this pass:

- split the preflight god-file shape into focused orchestration, check, and rewrite modules
- made static scanner skillpacks embedded data rather than inert root YAML files
- separated event-log streaming from broader storage and made scan summaries visible in history/status
- fixed the declared Go version so vet and tests agree
- redacted evidence bundles before sandbox, remote, LLM, or approval handoff can consume them

Exit criteria:

- local evidence, approvals, and scan outputs are predictable enough to serve as the contract for later phases
- the project can defer dynamic execution safely without creating ambiguity about why a run was blocked or prompted

## Phase 2: local intelligence and recursive npm

Goal: improve local-only verdict quality before introducing dynamic execution.

Scope:

- implement recursive npm dependency staging, pinning, and hash-aware artifact capture so npm dependency metadata is no longer a blanket blocker
- deepen local history and exposure correlation so repeat maintainers, repeat artifacts, and known-safe local patterns reduce unnecessary prompts
- expand the scanner's local intelligence with richer catalogs and better cross-run linking while keeping collection metadata-first and privacy-conscious

Exit criteria:

- npm installs can be evaluated across the full staged dependency set, not just the top-level tarball
- local history explains why a package is new, known, or suspicious without consulting a remote model

## Phase 3: Docker detonation and canaries

Goal: add controlled dynamic analysis for risky packages without exposing the host Mac.

Scope:

- build a Linux container detonation path for harmless fixtures first
- expose harmless fixture runs through `lsec sandbox run --mode docker-fixture [--docker PATH] -- <command> ...`; this path is not wired into `preflight` or `guard`
- use fake-home canaries, sinkholed credentials, and controlled network capture to observe install-time behavior
- store dynamic findings as evidence alongside static findings, keyed to the same `run_id` and `evidence_sha256`
- keep Docker images, mounts, and environment data synthetic and minimal

Non-goals:

- no mounting of the real home directory or developer secrets
- no live testing of malicious packages on the host

Exit criteria:

- fixture detonations produce useful, reproducible evidence without touching real user data
- dynamic signals can raise confidence for prompts and blocks without weakening deterministic policy

## Phase 4: remote sandbox

Status: first safe control-plane slice implemented with a local fake backend only. No SSH, VPS, AWS, Docker, shell, or network execution exists in this phase yet.

Goal: move higher-risk detonation to disposable infrastructure.

Scope:

- package redacted evidence for handoff with `lsec remote-sandbox prepare <run_id> [--out PATH]`
- exercise result handling and event correlation through `lsec remote-sandbox submit-fake <run_id> [--result PATH]`
- run suspicious or explicitly approved dynamic samples only in throwaway remote or VPS environments
- define a strict redaction boundary between local evidence creation and remote execution requests
- return compact artifacts such as logs, file diffs, canary hits, and network summaries, not raw disk snapshots

Exit criteria:

- local-sec can request and correlate remote sandbox analysis without exporting sensitive local context
- high-risk dynamic testing no longer depends on local Docker confidence or host safety tradeoffs

## Phase 5: LLM analyst

Goal: add evidence summarization and escalation without giving the model policy authority.

Scope:

- feed the model redacted evidence bundles only
- use the model for clustering, explanation, and escalation hints across static and dynamic findings
- support local-only experiments such as Ollama or Gemma using the same redacted evidence contract

Hard rule:

- deterministic blocks remain blocks even if the model disagrees

Exit criteria:

- the analyst helps humans understand evidence faster without becoming a policy bypass
- model prompts and outputs are auditable and free of host secrets

## Phase 6: approval notifications

Status: local CLI inbox and local notification outbox exist; Discord or other notification delivery remains future work.

Goal: make human review operationally usable beyond the local terminal.

Scope:

- keep `lsec inbox` as the local source of truth for prompt/risky runs, evidence viewing, one-time approval, deny, and view-later markers
- prepare redacted local notification payloads with `lsec notify plan <run_id> [--out PATH]`, list unsent payloads with `lsec notify list [limit]`, and mark local bookkeeping completion with `lsec notify mark-sent <notification_id>`
- add Discord or another notification layer keyed by `run_id` without making chat the policy source of truth
- show redacted evidence, verdict reason, artifact identity, and recommended next action in notifications
- support approve, keep blocked, or request future remote detonation without exposing local secrets or transcripts

Exit criteria:

- an operator can notice prompts and approved follow-ups without constantly polling the shell
- approval messages never include raw secrets, host paths, or personal data

## Phase 7: endpoint and SBOM integrations

Status: partially implemented. Optional external scan provider hooks exist for narrow, accepted inputs; broader endpoint and SBOM workflows remain future work.

Goal: broaden context using deterministic external signals.

Scope:

- keep the current optional active scan providers narrow and evidence-only:
  - `osv-scanner` may add advisory findings for explicit npm `package-lock.json` and `npm-shrinkwrap.json` files under requested roots
  - `pip-audit` may add advisory findings for regular `requirements.txt` files only when every entry is exact-pinned and hash-checked
  - `grype` may add advisory findings for CycloneDX SBOM files already accepted as `cyclonedx_sbom` inventory observations
- treat Bumblebee, Syft, cargo-vet, endpoint app presence, deeper OSV-Scanner coverage, and broader SBOM or endpoint workflows as detected-only or future integrations until they have explicit evidence-producing hooks
- continue hardening optional provider status reporting so missing tools, skipped unsafe inputs, partial success, and provider errors are visible without overstating enforcement coverage
- integrate additional endpoint and package intelligence sources only where they improve evidence quality without widening what local-sec reads or sends
- keep integrations evidence-producing, cacheable, and optional rather than making local-sec dependent on a large always-on stack

Exit criteria:

- additional providers enrich the same evidence model instead of creating parallel policy systems
- failures in optional integrations do not silently weaken the core guardrail behavior

## Phase 8: macOS detonation and v1 hardening

Status: future work; macOS detonation is not implemented. Roadmap, operator documentation, and doctor capability-matrix alignment are already in scope for v1 hardening.

Goal: reach a credible v1 for Mac-heavy developer workflows without violating host safety constraints.

Scope:

- add disposable macOS VM detonation for the cases Linux containers cannot represent well
- validate endpoint-specific behaviors, persistence paths, and tooling interactions relevant to macOS
- keep roadmap, operator documentation, and doctor capability-matrix status aligned with implemented behavior as part of v1 hardening
- harden release, upgrade, evidence retention, and operator documentation for a v1 launch

Exit criteria:

- risky macOS-specific behaviors can be observed in an isolated Mac environment rather than on the host
- v1 ships with a documented safety envelope, stable evidence contract, and clear operator approvals flow
