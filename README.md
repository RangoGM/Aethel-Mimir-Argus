# VCRIS MIMIR-ARGUS

Local AI orchestration and security monitoring for legacy Cisco Catalyst 2960 switches.

MIMIR and ARGUS are two complementary agents built for environments where modern programmable interfaces are limited and operational work still depends on SSH, CLI, syslog, and SNMP. The project combines local LLM inference, live command validation, Layer 2 security workflows, and observability tooling for legacy infrastructure.

## Components

### MIMIR

MIMIR is an interactive network administration assistant for Cisco IOS. It converts authenticated administrator requests into CLI actions while applying a three-layer Verified Intent Execution (VIE) framework:

- static security-policy validation
- human-reviewed multi-step orchestration plans
- live pre-execution audits against current switch state

Key protections include trunk-port invariants, tiered security-removal controls, blast-radius checks, state-drift detection, and cross-step exclusion of unsafe ports.

### ARGUS

ARGUS is a 24/7 security auditor. It monitors Loki syslog streams, queries hardware counters over SSH, and correlates rate-limited events with switch-side counters to detect sustained attacks that syslog alone would under-represent.

ARGUS also:

- initializes RA Guard baselines at startup
- tracks cumulative counter deltas during sustained events
- performs periodic RA Guard policy-drift rescans
- sends AI-generated summaries to the observability pipeline
- coordinates with MIMIR through a shared maintenance whitelist

## Why This Project Exists

Legacy Catalyst platforms remain common in small and medium networks, but they do not offer the same automation surface as modern IOS-XE or NX-OS systems. This project explores a practical middle path:

- keep inference local
- preserve human control over risky changes
- use hardware-enforced security features already available on the switch
- recover observability when syslog visibility is degraded by rate limiting

## Cost Profile

The reference deployment is designed for zero additional software-license fees. The recurring stack uses open-source or community-licensed components such as Grafana, Loki, Prometheus, and local Llama-family inference, so the practical costs are the existing network devices, Ubuntu monitoring server, local GPU host, electricity, storage, and normal maintenance.

No-fee software is not license-free software: each component still has its own license terms and must be used in compliance with them.

## Evaluated Results

### MIMIR fine-tuning evaluation

The frozen 150-case comparison is stored in `results/enhanced_results_extended.json`.

| Metric | Prompt-engineered baseline | QLoRA fine-tuned MIMIR |
| --- | ---: | ---: |
| Strict accuracy | 46.7% | 73.3% |
| Weighted accuracy | 51.7% | 82.0% |
| Safety category | 0.0% | 100.0% |
| Orchestration category | 100.0% | 100.0% |

The fine-tuned model improves safety and workflow adherence substantially, but it is not perfect. Residual weaknesses remain in context-sensitive reasoning and deep-clean command synthesis; raw evaluation outputs are included for transparency.

### ARGUS hardware validation

ARGUS was evaluated on physical hardware across 24 attack windows over approximately 28 hours:

- approximately 12,600 injected attack packets
- 174 observable syslog events
- 1.38% syslog observability ratio under rate limiting
- 100% hardware-drop reconciliation through cumulative counter deltas
- bimodal propagation latency:
  - Mode A: 1,009 +/- 5 ms queue-drain behavior
  - Mode B: 17 +/- 30 ms burst-flush behavior

## Repository Layout

```text
vcris-mimir-argus/
|-- README.md
|-- LICENSE
|-- docs/
|-- mimir/
|   |-- MIMIR.py
|   |-- Modelfile.mimir
|   `-- Modelfile.planner
|-- argus/
|   |-- ARGUS.py
|   |-- Modelfile.argus
|   `-- Modelfile.report
|-- finetune/
|   |-- admin_dataset.json
|   |-- dataset_unsloth.json
|   |-- finetune_mimir.py
|   |-- export_mimir.py
|   |-- test_comparison.py
|   `-- netconf_style.py
|-- pipeline/
|   |-- grafana-setup.sh
|   `-- grafana-uninstall.sh
|-- results/
|   |-- enhanced_results_extended.json
|   `-- ieee_mimir_150_cumulative.png
`-- configs/
    |-- config.mimir.example.py
    `-- config.argus.example.py
```

## Configuration

The repository contains only public-safe example files:

```text
configs/config.mimir.example.py
configs/config.argus.example.py
```

Copy them locally, replace placeholders with private values, and keep real deployment configs out of version control.

ARGUS requires additional local settings for:

- Loki query endpoint
- Prometheus query endpoint
- Loki `device_source` label
- Prometheus `instance` label
- Ubuntu report host and report-log path

Older Cisco devices may require legacy SSH compatibility options. Leave `SSH_LEGACY = None` for modern devices and set it only when older equipment requires it.

## Models

The repository provides Ollama Modelfiles but does not include GGUF weights.

- `Modelfile.mimir` - normal MIMIR assistant model
- `Modelfile.planner` - JSON orchestration planner model
- `Modelfile.argus` - incident-analysis model
- `Modelfile.report` - concise report-generation model

Model weights are excluded because they are large artifacts and may have separate distribution requirements.

## Reproducibility Notes

- `admin_dataset.json` is the raw interaction dataset.
- `dataset_unsloth.json` is the Alpaca-format training dataset used for the frozen MIMIR release.
- `finetune_mimir.py` performs QLoRA training.
- `export_mimir.py` exports an existing checkpoint to GGUF when standalone export is needed.
- `test_comparison.py` reproduces the prompt-engineered versus fine-tuned evaluation.
- `netconf_style.py` generates the cumulative evaluation figure.

## Safety Notice

This is a research prototype for controlled environments and legacy-switch experimentation.

- Review every deployment-specific command path before use.
- Do not expose real credentials in the repository.
- Do not enable autonomous shutdown behavior unless the threat-confirmation policy is strong enough to justify false-positive risk.
- Validate behavior in a lab before considering production use.

## Research Status

This repository accompanies ongoing academic work on AI safety and observability for legacy switching platforms. A formal paper citation or DOI can be added after publication rights permit public linking.

## License

See `LICENSE`.
