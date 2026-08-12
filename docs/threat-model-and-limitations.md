# Threat model and limitations

`local-sec` aims to reduce accidental exposure to risky developer package installs. It stages supported artifacts, checks explicit policy signals and advisories, and records redacted local evidence before allowing, prompting, or blocking a supported command.

## Intended protection

- Known advisories, unusually fresh releases, unsafe package specifications, and selected static signals such as credential access combined with network or execution behavior.
- Supported npm, Python, uv-style, and downloader command forms whose package identity and staged artifact can be determined exactly.
- Accidental disclosure from scan and evidence output through metadata allowlists, redaction, and local-first storage.

## Trust boundaries

- Package registries and advisory providers are external inputs. `--network off` avoids advisory requests; advisory mode sends normalized package identities as documented.
- Optional command-line providers are evidence sources, not policy authorities. They run with constrained environments, but their installation and output remain outside this repository's control.
- LLM review receives redacted evidence and can escalate risk only. It cannot clear a deterministic block.
- Docker and macOS detonation paths in this repository are fixture contracts. They are not proof that a real malicious artifact is safely detonated or contained.

## Limitations

- A trusted verdict is not a malware-free guarantee. Static patterns and advisory data can miss novel, delayed, environment-specific, or supply-chain attacks.
- Unsupported commands, alternate registries, ambiguous package identities, and unsafe dependency specifications are intentionally refused or remain outside the stated protection boundary.
- Local storage, operator approvals, and any future remote runner require host-level access controls and review. Do not place secrets, personal files, shell history, or agent transcripts into evidence, fixtures, or external systems.
- Test fixtures and local demonstrations are not substitutes for clean-host, real-provider, race, and release validation.

Use the tool only on systems and package sources you are authorized to assess. Keep independent backups, verify release checksums and archive structure, and review risky decisions before executing an install.
