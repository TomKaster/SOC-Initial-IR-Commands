# Running IRTriage on remote endpoints through EDR live response

The collector is one self-contained PowerShell 5.1 script with no dependencies, so any EDR that can
"put a script, run it as SYSTEM, get a file back" can drive it. That avoids opening WinRM/SMB to
endpoints and reuses the EDR's existing authentication, RBAC and audit trail.

```
analyst ──EDR console/API──▶ EDR agent (SYSTEM) ──▶ Invoke-IRTriage.ps1 ──▶ C:\ProgramData\IRTriage\<case>_fleet.zip
        ◀───────────── getfile / fetch ─────────────────────────────────────┘   + IRTRIAGE_RESULT {zip sha256}
```

## 1. Build (and sign) the script

```powershell
.\build.ps1                                            # unsigned -> dist\Invoke-IRTriage.ps1
.\build.ps1 -CertificateThumbprint <code-signing-thumbprint>   # signed (recommended)
```

`dist\Invoke-IRTriage.ps1.sha256` records the hash of what you upload. Record it in your change ticket.
Only upload builds produced by CI from `main` (the `Invoke-IRTriage-unsigned` artifact) or signed from it.

### Conventions all EDRs share

| Item | Value |
|---|---|
| Arguments | `-CaseId <ticket> -Profile quick|standard|full -Analyst <you>` |
| Predictable output (for scripted retrieval) | add `-OutputPath C:\ProgramData\IRTriage\<ticket>_fleet -Force` → zip is `C:\ProgramData\IRTriage\<ticket>_fleet.zip` |
| Default output (interactive) | `C:\ProgramData\IRTriage\<ticket>_<HOST>_<utc>.zip`, path printed in output |
| Proof of integrity | last stdout line `IRTRIAGE_RESULT {"zipSha256": ...}`, plus `<zip>.sha256` beside the zip |
| Runtime | quick ≈ 20–60 s, standard ≈ 1–3 min, full ≈ 3–10 min (`-SkipSlow` drops `recent_executables`) |
| Report | `report.html` is inside the zip. A copy is written beside it as `<OutputPath>-report.html` if you only want to `getfile` the report. |
| Cleanup | the script leaves only the zip, `.sha256` and `-report.html`. Delete them after retrieval if policy requires. |

## 2. Microsoft Defender for Endpoint

**One-time setup**
1. Settings → Endpoints → Advanced features: enable **Live Response**, **Live Response for Servers**.
   If you don't sign the script, also enable **Live Response unsigned script execution** (signing is preferred).
2. Open a live response session on any device → *Upload file to library* → `dist\Invoke-IRTriage.ps1`.
3. RBAC: analysts need the "Advanced live response" permission to run library scripts.

**Interactive (one host)**
```
run Invoke-IRTriage.ps1 -parameters "-CaseId INC-1042 -Profile quick -Analyst jdoe -OutputPath C:\ProgramData\IRTriage\INC-1042_fleet -Force"
getfile "C:\ProgramData\IRTriage\INC-1042_fleet.zip"
```
Compare the downloaded zip's hash to the `IRTRIAGE_RESULT` line shown in the console.

**Where the output lands.** `run` executes the script on the device as `NT AUTHORITY\SYSTEM` (Windows PowerShell 5.1, elevated,
no desktop, so `-OpenReport` does nothing). Only the console text comes back to the portal. The evidence stays on the device:
without `-OutputPath` it is `C:\ProgramData\IRTriage\<CaseId>_<HOST>_<yyyyMMddTHHmmssZ>.zip` (+ `.zip.sha256`) and
`...-report.html` beside it. The last console lines print ready-to-paste `getfile "..."` commands for both. `getfile`
downloads through the portal to your browser's download folder.
Live response commands time out after 10 minutes. For `full`, either add `-SkipSlow` or run with `&` (background) and `getfile` later.

**Many hosts (API)** — `analyst\Invoke-FleetTriage.ps1`
1. Entra ID → App registrations → new app → API permissions → *APIs my organization uses* →
   **WindowsDefenderATP** → Application permissions **Machine.Read.All**, **Machine.LiveResponse** → grant admin consent.
2. Store the client secret in your vault. Pass it as a SecureString; the script never writes it anywhere.

```powershell
$secret = Read-Host -AsSecureString 'MDE app secret'
.\analyst\Invoke-FleetTriage.ps1 -ComputerName (Get-Content .\scope.txt) -CaseId INC-1042 -Profile quick `
    -TenantId $tenant -ClientId $appId -ClientSecret $secret -Analyst jdoe -WhatIf   # review, then drop -WhatIf
```
Output: `cases\INC-1042\<host>.zip` (+ `.sha256`, `-script-output.txt`, `-report.html`) and `fleet-summary.csv` with
`Status`, `HashMatch` and errors per host. It runs up to `-MaxConcurrent` (default 10) sessions at once and retries 429/5xx.

> MDE limits concurrent live response sessions per tenant (25 at time of writing). Keep `-MaxConcurrent` below that if
> other analysts are using live response at the same time.

## 3. CrowdStrike Falcon Real Time Response

**One-time setup**: Host setup and management → Response scripts & files → *Put files* or *Custom scripts* →
upload `dist\Invoke-IRTriage.ps1` as a **custom script** named `Invoke-IRTriage` (permission: RTR Active Responder or Admin).

**Interactive**
```
runscript -CloudFile="Invoke-IRTriage" -CommandLine="-CaseId INC-1042 -Profile quick -Analyst jdoe -OutputPath C:\ProgramData\IRTriage\INC-1042_fleet -Force" -Timeout=600
get C:\ProgramData\IRTriage\INC-1042_fleet.zip
```
RTR delivers `get` files inside a password-protected 7z (password `infected`); the zip inside is the collector's zip.

**Many hosts** — PSFalcon (`Install-Module PSFalcon`):
```powershell
Request-FalconToken -ClientId $id -ClientSecret $secret
$ids = Get-FalconHost -Filter "hostname:['ws-0193','ws-0201']"
Invoke-FalconRtr -Command runscript -Argument '-CloudFile="Invoke-IRTriage" -CommandLine="-CaseId INC-1042 -OutputPath C:\ProgramData\IRTriage\INC-1042_fleet -Force"' -HostId $ids -Timeout 600
Invoke-FalconRtr -Command get -Argument 'C:\ProgramData\IRTriage\INC-1042_fleet.zip' -HostId $ids
# then Receive-FalconGetFile for each session/sha256
```

## 4. SentinelOne

1. Sentinels → **RemoteOps** → Script Library → Upload → `dist\Invoke-IRTriage.ps1`, OS Windows, type *Data Collection*.
2. Input parameters: `-CaseId INC-1042 -Profile quick -Analyst jdoe -OutputPath C:\ProgramData\IRTriage\INC-1042_fleet -Force`.
3. Enable **Output destination → SentinelOne Cloud**, or follow with **Fetch Files** for `C:\ProgramData\IRTriage\INC-1042_fleet.zip`.
   S1 delivers fetched files in a password-protected zip (password set in the fetch dialog).

## 5. Without an EDR (fallback)

The same script works over PowerShell Remoting where WinRM is permitted:
```powershell
$s = New-PSSession -ComputerName ws-0193
Invoke-Command -Session $s -FilePath .\dist\Invoke-IRTriage.ps1 -ArgumentList ...   # or copy and run with named params
Copy-Item -FromSession $s 'C:\ProgramData\IRTriage\INC-1042_fleet.zip' -Destination .\cases\INC-1042\
```
Avoid interactive RDP to a suspect host to run it. That exposes privileged credentials to a possibly compromised machine.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `skipped_not_elevated` on many collectors | Not running as SYSTEM/admin. EDR live response is elevated; local runs need "Run as administrator". |
| Script blocked: "not digitally signed" | Sign with `build.ps1 -CertificateThumbprint`, or enable unsigned script execution in the EDR. |
| `skipped_time_budget` | Profile budget reached (quick = 60 s). Use `-Collectors` to target what you need, or a larger profile. |
| `OutputPath ... exists` | Previous run for the same case. Add `-Force` (only overwrites folders containing `manifest.json`). |
| "... only reaches back to ..." lead | The event log is full and circular, so it overwrote the older events. Collect it sooner, or raise the log size (see PLAYBOOK, Event log retention). |
| Hash mismatch on download | Re-download. If it persists, treat the collection as unverified and re-collect. |
