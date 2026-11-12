# Changelog

## 2.0.0 - unreleased

Rewrite from a local Python script into a team triage toolkit.

### Added
- `collector/Invoke-IRTriage.ps1`: headless PowerShell 5.1 collector with 31 collectors across network, sessions, accounts,
  processes, persistence, event logs, Defender and extended artifacts; quick/standard/full profiles; per-file SHA-256 manifest;
  hashed zip output; `IRTRIAGE_RESULT` line for orchestration.
- `build.ps1`: single-file build for EDR script libraries, with optional Authenticode signing.
- `analyst/`: HTML report with heuristic leads, baseline diff, IOC sweep, Defender for Endpoint live response fleet runner.
- Docs: EDR deployment (MDE, CrowdStrike, SentinelOne, WinRM), artifact reference with ATT&CK mapping, analyst playbook.
- Pester tests and GitHub Actions CI (PSScriptAnalyzer, tests, build artifact).

### Removed
- `cmdinfo.py` and the `pyuac` dependency. Its commands are covered by `network_config`, `network_connections`,
  `smb_sessions` and `smb_outbound`.
