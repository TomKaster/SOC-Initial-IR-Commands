# Changelog

## 2.1.0 - unreleased

### Added
- The collector writes the HTML report itself: `report.html` inside the collection and `<OutputPath>-report.html` next to the zip.
  New switches `-NoReport` and `-OpenReport`; `IRTRIAGE_RESULT` now includes `reportPath`.
- `Invoke-FleetTriage.ps1` writes `<host>-report.html` for each downloaded collection.
- Host IP addresses in the manifest (`host.primaryIPv4`, `host.ipAddresses`), shown under the host name in the report.
  Older collections fall back to the `network_config` collector.
- `ConvertTo-TriageReport.ps1 -Open`.

### Changed
- Redesigned report in the Meadow palette (light and dark): larger type, host masthead, summary tiles, sticky section nav,
  severity filter and search for leads.
- Report tables work like a spreadsheet: drag a column edge to resize, double-click it to fit the column on one line.
- Lead heuristics and the report renderer moved to `shared/` so the collector and analyst scripts use the same code.

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
