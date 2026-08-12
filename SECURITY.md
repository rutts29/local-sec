# Security policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting when it is enabled for this repository. If it is unavailable, contact the repository owner privately through GitHub and do not include exploit details in a public issue.

Include the affected version or commit, impact, a minimal reproduction, and any constraints needed to assess the report. Do not attach real credentials, private package artifacts, personal paths, or host data.

## Scope and response

Reports about command parsing, staging, policy decisions, evidence redaction, local storage, release artifacts, and optional-provider isolation are in scope. The project makes no response-time commitment. Do not test reports against systems, packages, accounts, or networks you do not own or have permission to use.

## Operational safety

Treat `lsec` as a decision-support and install-gating tool, not a guarantee that an artifact is safe. Follow the [threat model and limitations](docs/threat-model-and-limitations.md), especially for external providers, sandbox-related features, and any future remote runner.
