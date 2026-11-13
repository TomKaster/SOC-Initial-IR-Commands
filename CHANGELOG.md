# Changelog

## 2.1.1 - unreleased

### Fixed
- Registry values that are just a pair of quotes (LSA `Security Packages` defaults to `""`) were treated as file paths,
  so `Test-Path` printed "Illegal characters in path" when signatures were checked (standard/full profiles).
- PowerShell script blocks with only low-signal patterns (e.g. `-ExecutionPolicy Bypass`) were dropped from the leads instead of shown as review.
- Script block text was cut at 8 KB per event; 4104 events now keep their full text.
- IRTriage's own code, logged by script block logging when it runs, was flagged as high. It is now recognised and reported once as info, with its script paths.

### Added
- Event collectors record each log's real coverage (oldest event, size, full/circular, event cap hit) in the manifest.
  The report raises a review lead when a log does not reach back to the lookback start, e.g. a full 15 MB PowerShell log.
- Identical script blocks are grouped into one lead with a run count; chunks of one block are reassembled before matching.

### Changed
- `base64 decode` alone is graded review; combined with download/IEX patterns it is still high.

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
