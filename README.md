# SOC Initial IR Triage

Initial incident-response triage for Windows endpoints, built for a SOC team rather than a single analyst.

- **One script, nothing installed.** `Invoke-IRTriage.ps1` uses only built-in Windows PowerShell 5.1 cmdlets, so no Python, agents or binaries go onto the suspect host.
- **Remote by design.** It runs headless as SYSTEM through EDR live response (Defender for Endpoint, CrowdStrike RTR, SentinelOne RemoteOps), with a bulk runner for the MDE API.
- **Structured, comparable output.** Each collector writes JSON (and CSV), so you can diff, search and report on it instead of scrolling console output.
- **Chain of custody.** `manifest.json` records the case ID, analyst, run-as account, tool version and build hash, and a SHA-256 for every file. The zip is hashed as well.
- **Analyst toolkit.** It includes an HTML report with heuristic leads, a baseline diff, an IOC sweep across many hosts, and an MDE fleet runner.

> v2 replaces the original `cmdinfo.py` (Python + `pyuac`, which ran `ipconfig /all`, `net view`, `net session` and `netstat -naob` interactively).
> Those commands map to `network_config`, `smb_outbound`, `smb_sessions` and `network_connections`, which now return
> objects with process path and hash. `net view` (slow, broadcast-based) was dropped.

## Quick start

**On a host, locally** (elevated PowerShell):
```powershell
.\collector\Invoke-IRTriage.ps1 -CaseId INC-1042 -Analyst jdoe            # quick profile, < 60 s
.\collector\Invoke-IRTriage.ps1 -CaseId INC-1042 -Profile standard          # + event logs, Defender, signers
```
Output: `C:\ProgramData\IRTriage\INC-1042_<HOST>_<utc>.zip` + `.sha256`.

**Remotely through EDR**: build once, upload `dist\Invoke-IRTriage.ps1` to the EDR script library, then e.g. in MDE:
```
run Invoke-IRTriage.ps1 -parameters "-CaseId INC-1042 -Analyst jdoe -OutputPath C:\ProgramData\IRTriage\INC-1042_fleet -Force"
getfile "C:\ProgramData\IRTriage\INC-1042_fleet.zip"
```
See **[docs/EDR-DEPLOY.md](docs/EDR-DEPLOY.md)** for MDE, CrowdStrike, SentinelOne and WinRM.

**Many hosts at once** (MDE API):
```powershell
.\analyst\Invoke-FleetTriage.ps1 -ComputerName ws-0193, ws-0201 -CaseId INC-1042 -TenantId $t -ClientId $c -ClientSecret $s -WhatIf
```

**Analyse** (on your analyst workstation):
```powershell
.\analyst\ConvertTo-TriageReport.ps1 -Path .\cases\INC-1042\ws-0193.zip -BaselinePath .\baselines\win11.zip -IocFile .\cases\INC-1042\iocs.csv
.\analyst\Compare-Triage.ps1 -Baseline .\baselines\win11.zip -Suspect .\cases\INC-1042\ws-0193.zip -Change Added
.\analyst\Find-IOC.ps1 -Path .\cases\INC-1042\*.zip -Indicator 203.0.113.50, evil-cdn.example
```

## Profiles

| Profile | Time budget | Adds | Use when |
|---|---|---|---|
| `quick` | 60 s | network, sessions, users/admins, processes (+hash), registry autoruns, tasks, services, WMI, startup folders | first response on any alert |
| `standard` | 5 min | Authenticode signers, installed software, Defender state/exclusions/detections, Security/System/PowerShell/RDP/Sysmon events (72 h) | host looks suspicious |
| `full` | 15 min | prefetch, recently written executables in user-writable paths, browser extensions, USB history (7-day events) | confirmed incident, before escalation to forensics |

Profiles live in `profiles/*.json` (collectors, lookback, event caps, signer checks). Every collector is documented,
with ATT&CK mapping, in **[docs/ARTIFACTS.md](docs/ARTIFACTS.md)**. The analyst workflow is in **[docs/PLAYBOOK.md](docs/PLAYBOOK.md)**.

## Collector options

| Parameter | Purpose |
|---|---|
| `-CaseId` | Ticket ID (letters, digits, `. _ -`), used in paths and the manifest |
| `-Profile` | `quick` (default), `standard`, `full` |
| `-Analyst` | Who requested it (under EDR the run-as account is SYSTEM, so pass this) |
| `-OutputPath` | Fixed output folder; zip is `<OutputPath>.zip` (use for scripted retrieval) |
| `-Collectors` | Run only the named collectors |
| `-LookbackHours` | Override event-log window |
| `-SkipSlow` | Skip slow collectors (`recent_executables`) |
| `-NoZip` / `-KeepFolder` | Keep raw output instead of / as well as the zip |
| `-Force` | Overwrite a previous IRTriage output for the same path (refuses folders without `manifest.json`) |

Without elevation the collector still runs, records `elevated: false`, and marks admin-only collectors `skipped_not_elevated`.
The last line of output is `IRTRIAGE_RESULT {json}` with the zip path and SHA-256 for orchestration tools.

## Output layout

```
INC-1042_WS-0193_20261112T200310Z.zip
├── manifest.json            # case, host, tool build, per-collector status/duration, SHA-256 of every file
├── network_connections.json / .csv
├── processes.json / .csv
├── services.json / .csv
└── ...
INC-1042_WS-0193_20261112T200310Z.zip.sha256
```

## Repository layout

```
collector/Invoke-IRTriage.ps1   entry point (runs from source; dot-sources modules + profiles)
collector/modules/*.ps1         collectors, one function each; Registry.ps1 lists them
profiles/*.json                 quick / standard / full
build.ps1                       inlines modules + profiles -> dist/Invoke-IRTriage.ps1 (+ optional Authenticode signing)
analyst/                        report, baseline diff, IOC sweep, MDE fleet runner
docs/                           EDR deployment, artifact reference, analyst playbook
tests/                          Pester 5 tests (unit + integration run of the quick profile)
```

## Development

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path collector, analyst, build.ps1 -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester .\tests
.\build.ps1
```

- Target **Windows PowerShell 5.1**: no `??`, ternaries or other PS7-only syntax in `collector/`. Keep source files ASCII.
- Collectors must stay read-only and dependency-free. See the design rules at the bottom of `docs/ARTIFACTS.md`.
- Changes go through a PR. CI (GitHub Actions on `windows-latest`, PS 5.1) lints, tests and builds. Only CI-built or signed
  builds of `main` go into the EDR library. Record the `.sha256` of the uploaded build.
- Bump `$script:IRToolVersion` in `collector/Invoke-IRTriage.ps1` and add a `CHANGELOG.md` entry for each release.

## Roadmap

- SIEM/SOAR integration: ship manifest + leads to Sentinel / Splunk HEC, and trigger quick triage from a SOAR playbook on high-severity alerts.
- CrowdStrike and SentinelOne fleet runners (PSFalcon / S1 API) alongside the MDE one.
- Raw-hive artifacts (Amcache, ShimCache, SRUM) via VSS for the `full` profile.
- Remediation is out of scope by design: this tool only collects.
