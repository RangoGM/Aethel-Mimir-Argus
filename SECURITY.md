# Security Policy

## Scope

This repository contains research code for local AI-assisted network orchestration and monitoring on legacy Cisco switching platforms.

Security-sensitive areas include:

- credential handling and deployment configuration
- command-validation logic in MIMIR
- SSH, VPN, and report-delivery paths
- ARGUS automation behavior, especially any action that could modify device state

## Supported Versions

The current public release is the only supported version.

## Reporting a Vulnerability

Please do not open a public issue for vulnerabilities that could expose credentials, bypass safety checks, or cause unintended device changes.

Report security concerns privately to the repository maintainer with:

- a short description of the issue
- affected file or component
- reproduction steps when possible
- any relevant logs or screenshots with secrets removed

The maintainer will review reports as time permits and may ask for additional details before confirming impact.

## Deployment Guidance

- Never commit real credentials, IP addresses, tokens, or production configuration files.
- Start from the example config files and keep private deployment configs outside version control.
- Validate command paths in a lab before use on live infrastructure.
- Keep autonomous shutdown behavior disabled unless the threat-confirmation policy is strong enough to justify false-positive risk.
- Treat this repository as a research prototype, not as a drop-in production security product.
