# Security policy

AgentGate is a demonstration execution boundary with fake tools. See the [threat model](docs/THREAT_MODEL.md) for the exact scope and residual risks.

## Reporting

Do not publish credentials, personal data, or exploit details against another person's deployment. Once the personal GitHub repository is available, use its private vulnerability reporting channel if enabled. Until a private channel is configured, request one from the maintainer without including sensitive details. No response-time commitment is currently offered.

Include the affected revision, configuration with secrets removed, minimal reproduction, expected boundary, observed outcome, and redacted trace identifiers. Distinguish a detector miss from an unauthorized side effect.

## Supported use

Only the current reviewed release is intended for this demonstration. Public mode must remain synthetic. Run operator mode behind authenticated access and TLS; arbitrary untrusted code requires isolation outside this Python process.
