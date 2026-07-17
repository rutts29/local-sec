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

## Phase coding status (implementation complete; outside testing remains)

| Phase | Coding | Outside testing still needed |
|-------|--------|------------------------------|
| R cleanup | **Done** | release/race on clean tree, commit/publish |
| 1 install guard | **Done** | real-world multi-manager installs |
| 2 recursive npm + intel | **Done** (install + one-shot/create offline promotion) | real npm cache offline installs on host npm versions |
| 2.5 metadata scan | **Done** (scoped providers) | real osv-scanner/pip-audit/grype/syft/cargo-vet installs |
| 3 Docker fixture | **Done** (CLI + optional preflight via `LSEC_DOCKER_FIXTURE_PREFLIGHT=1`) | docker daemon matrix, image build |
| 4 remote sandbox | **Done** (prepare/submit-fake/submit + `run-local` worker using docker fixture) | real VPS/SSH worker transport |
| 5 LLM analyst | **Done** (Ollama + skillpack context + escalate-only + cache) | real model quality on operator machines |
| 6 notifications | **Done** (inbox + plan/list/mark-sent + Discord webhook) | live Discord webhook ops |
| 7 endpoint/SBOM | **Done** as optional hooks (osv-scanner, pip-audit, grype, syft, cargo-vet, bumblebee probe) | tool installs + richer endpoint product config |
| 8 macOS detonation | **Done** as fixture contract + CLI (`prepare-fixture`, `run-local-fixture`, `validate-result`, `run-external`) | real disposable VM runner via `LSEC_MACOS_DETONATION_RUNNER` |

## Phase R cleanup

Status: **implemented**.

## Phase 2: local intelligence and recursive npm

Status: **implemented** for install and one-shot/create promotion via offline npm cache. Local history/reputation integrated.

## Phase 3: Docker detonation and canaries

Status: **implemented** for fixture sandbox. Enable preflight attach with `LSEC_DOCKER_FIXTURE_PREFLIGHT=1`.

## Phase 4: remote sandbox

Status: **implemented** control plane + local worker (`remote-sandbox run-local`). Real remote transport is outside testing.

## Phase 5: LLM analyst

Status: **implemented** (redacted evidence, skillpack analyst context, escalate-only, Ollama, cache, inbox review-llm).

## Phase 6: approval notifications

Status: **implemented** (local inbox/outbox + Discord `send-discord` with webhook allowlist).

## Phase 7: endpoint and SBOM integrations

Status: **implemented** as optional evidence providers. Missing tools report `not_available` without weakening core policy.

## Phase 8: macOS detonation and v1 hardening

Status: **implemented** fixture job/result contract and local fixture runner CLI. Real VM execution uses external runner env `LSEC_MACOS_DETONATION_RUNNER` (outside testing). Release scripts remain the release path.

## Outside testing checklist

1. Host npm offline install with multi-dep staged cache on real npm versions
2. Docker fixture image/daemon on clean machines
3. Optional scan tools: osv-scanner, pip-audit, grype, syft, cargo+vet, bumblebee
4. Ollama models for review quality
5. Discord webhook delivery
6. External macOS VM runner script consuming job JSON and emitting result JSON
7. Full race/release packaging on a clean git commit
