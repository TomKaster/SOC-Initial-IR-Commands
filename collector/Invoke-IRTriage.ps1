<#
.SYNOPSIS
    Headless Windows incident-response triage collector for SOC teams.

.DESCRIPTION
    Collects volatile and persistence artifacts from a Windows endpoint using built-in cmdlets only
    (no installs, no third-party binaries). Every collector writes structured JSON (and CSV for flat
    data). A manifest records host identity, case/analyst metadata, per-collector status and a SHA-256
    of every output file. The output is then zipped and the zip itself hashed for chain of custody.

    The script is designed to be pushed through EDR live response (Microsoft Defender for Endpoint,
    CrowdStrike RTR, SentinelOne RemoteOps), where it runs as SYSTEM without a console. It never
    prompts. When not elevated it records that fact and skips privileged collectors.

    Run from source (collector\modules + profiles\ next to it) or use the single-file build in dist\
    produced by build.ps1. Upload the dist\ build to your EDR script library.

.PARAMETER CaseId
    Ticket / incident identifier. Used in the output folder name and manifest. Letters, digits, . _ - only.

.PARAMETER TriageProfile
    quick (default, <60s), standard, or full. Alias: -Profile.

.PARAMETER OutputPath
    Output folder. Default: %ProgramData%\IRTriage\<CaseId>_<HOST>_<UTC timestamp>.
    The zip is written alongside as <OutputPath>.zip.

.PARAMETER Analyst
    Name of the analyst requesting collection. Under EDR the script runs as SYSTEM, so pass this explicitly.

.PARAMETER Collectors
    Run only these collector names (overrides the profile's list, keeps the profile's options).

.PARAMETER LookbackHours
    Override the profile's event-log lookback window.

.PARAMETER SkipSlow
    Skip collectors marked slow (e.g. recent_executables).

.PARAMETER NoZip
    Leave the raw output folder and do not create a zip.

.PARAMETER KeepFolder
    Keep the raw output folder after zipping (default removes it so only the zip + .sha256 remain).

.PARAMETER NoReport
    Do not build the HTML report. By default report.html is written inside the collection (and zip), and a copy
    is written next to the zip as <OutputPath>-report.html so it can be opened straight away.

.PARAMETER OpenReport
    Open the report in the default browser when collection finishes (interactive sessions only; ignored under SYSTEM/EDR).

.PARAMETER Force
    Overwrite an existing OutputPath, but only if it is a previous IRTriage output (contains manifest.json).

.EXAMPLE
    .\Invoke-IRTriage.ps1 -CaseId INC-1042 -Analyst jdoe

.EXAMPLE
    # Defender for Endpoint live response
    run Invoke-IRTriage.ps1 -parameters "-CaseId INC-1042 -Profile standard -Analyst jdoe"

.NOTES
    IRTRIAGE-COMPONENT collector entry point.
    Final line of output is "IRTRIAGE_RESULT {json}" so orchestration tooling can locate the zip and its hash.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$CaseId = 'NOCASE',

    [Alias('Profile')]
    [ValidateSet('quick', 'standard', 'full')]
    [string]$TriageProfile = 'quick',

    [string]$OutputPath,

    [ValidatePattern('^[^\r\n"]{0,128}$')]
    [string]$Analyst = $env:USERNAME,

    [string[]]$Collectors,

    [ValidateRange(1, 8760)]
    [int]$LookbackHours,

    [switch]$SkipSlow,
    [switch]$NoZip,
    [switch]$KeepFolder,
    [switch]$NoReport,
    [switch]$OpenReport,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'   # Progress bars slow down Compress-Archive and break headless sessions.
$script:IRToolVersion = '2.3.0'
$script:IRBuildInfo = 'source'

#region BUILD:MODULES
foreach ($moduleFile in @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'modules') -Filter '*.ps1' | Sort-Object Name)) {
    . $moduleFile.FullName
}
# Report/lead code shared with the analyst scripts.
foreach ($sharedFile in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..\shared') -Filter '*.ps1' | Sort-Object Name)) {
    . $sharedFile.FullName
}
#endregion BUILD:MODULES

#region BUILD:PROFILES
$script:IRProfileJson = @{}
foreach ($profileFile in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..\profiles') -Filter '*.json')) {
    $script:IRProfileJson[$profileFile.BaseName] = [System.IO.File]::ReadAllText($profileFile.FullName)
}
#endregion BUILD:PROFILES

function Write-IRStatus {
    param([string]$Message)
    Write-Host ("[{0}] {1}" -f (Get-Date).ToUniversalTime().ToString('HH:mm:ss'), $Message)
}

function Export-IRCollectorOutput {
    param([string]$Name, [object[]]$Records, [bool]$Tabular, [string]$Folder)
    $files = @()
    $plain = @(foreach ($r in $Records) { ConvertTo-IRPlain $r })
    $jsonPath = Join-Path $Folder "$Name.json"
    Write-IRUtf8File -Path $jsonPath -Content (ConvertTo-Json -InputObject $plain -Depth 12)
    $files += "$Name.json"
    if ($Tabular -and $plain.Count -gt 0) {
        $csvPath = Join-Path $Folder "$Name.csv"
        $flat = foreach ($p in $plain) {
            $o = [ordered]@{}
            foreach ($prop in $p.PSObject.Properties) {
                $v = $prop.Value
                if ($null -ne $v -and ($v -is [array] -or $v -is [pscustomobject])) { $v = ConvertTo-Json -InputObject $v -Depth 6 -Compress }
                $o[$prop.Name] = $v
            }
            [pscustomobject]$o
        }
        $flat | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        $files += "$Name.csv"
    }
    return $files
}

# ---------------------------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------------------------
$runStart = (Get-Date).ToUniversalTime()
$stamp = $runStart.ToString('yyyyMMddTHHmmssZ')
$elevated = Test-IRElevated
$executedAs = [Security.Principal.WindowsIdentity]::GetCurrent().Name

if (-not $script:IRProfileJson.ContainsKey($TriageProfile)) { throw "Profile '$TriageProfile' not found in embedded profiles." }
$profileDef = ConvertFrom-Json -InputObject $script:IRProfileJson[$TriageProfile]

$collectorNames = @($profileDef.collectors)
if ($Collectors) {
    $unknown = @($Collectors | Where-Object { -not $script:IRCollectors.Contains($_) })
    if ($unknown) { throw "Unknown collector(s): $($unknown -join ', '). Valid: $($script:IRCollectors.Keys -join ', ')" }
    $collectorNames = @($Collectors)
}

$opt = $profileDef.options
if ($PSBoundParameters.ContainsKey('LookbackHours')) { $lookback = $LookbackHours } else { $lookback = [int]$opt.lookbackHours }

$context = [pscustomobject]@{
    Elevated       = $elevated
    LookbackHours  = $lookback
    LookbackStart  = (Get-Date).AddHours(-1 * $lookback)
    MaxEvents      = [int]$opt.maxEventsPerCollector
    Signatures     = [bool]$opt.signatures
    RecentFileDays = [int]$opt.recentFileDays
    MaxDepth       = [int]$opt.maxDepth
    MaxFiles       = [int]$opt.maxFiles
    CollectorNote  = $null
    Coverage       = (New-Object System.Collections.ArrayList)
}

if (-not $OutputPath) {
    $OutputPath = Join-Path (Join-Path $env:ProgramData 'IRTriage') ("{0}_{1}_{2}" -f $CaseId, $env:COMPUTERNAME, $stamp)
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$zipPath = "$OutputPath.zip"

if (Test-Path -LiteralPath $OutputPath) {
    $existing = @(Get-ChildItem -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        if ($Force -and (Test-Path -LiteralPath (Join-Path $OutputPath 'manifest.json'))) {
            Remove-Item -LiteralPath $OutputPath -Recurse -Force
        } else {
            throw "OutputPath '$OutputPath' exists and is not empty. Use -Force to overwrite a previous IRTriage output (requires manifest.json in the folder)."
        }
    }
}
if (Test-Path -LiteralPath $zipPath) {
    if ($Force) { Remove-Item -LiteralPath $zipPath -Force; Remove-Item -LiteralPath "$zipPath.sha256" -Force -ErrorAction SilentlyContinue }
    else { throw "Zip '$zipPath' already exists. Use -Force to overwrite." }
}
[void](New-Item -ItemType Directory -Path $OutputPath -Force)

Write-IRStatus "IRTriage $script:IRToolVersion | case=$CaseId profile=$TriageProfile host=$env:COMPUTERNAME elevated=$elevated as=$executedAs"
Write-IRStatus "Output: $OutputPath"
if (-not $elevated) { Write-IRStatus 'WARNING: not elevated. Collectors that need admin will be skipped and others may be incomplete.' }

# ---------------------------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------------------------
$results = New-Object System.Collections.ArrayList
$budget = [int]$profileDef.timeBudgetSeconds
$clock = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($name in $collectorNames) {
    $def = $script:IRCollectors[$name]
    $entry = [ordered]@{ name = $name; status = $null; records = 0; durationMs = 0; files = @(); note = $null; error = $null }

    if (-not $def) {
        $entry.status = 'error'; $entry.error = 'unknown collector'
    } elseif ($def.RequiresAdmin -and -not $elevated) {
        $entry.status = 'skipped_not_elevated'
    } elseif ($def.Slow -and $SkipSlow) {
        $entry.status = 'skipped_slow'
    } elseif ($budget -gt 0 -and $clock.Elapsed.TotalSeconds -ge $budget) {
        $entry.status = 'skipped_time_budget'
    } else {
        $context.CollectorNote = $null
        $context.Coverage = New-Object System.Collections.ArrayList
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $records = @(& $def.Function -Context $context)
            $entry.files = @(Export-IRCollectorOutput -Name $name -Records $records -Tabular $def.Tabular -Folder $OutputPath)
            $entry.records = $records.Count
            $entry.status = 'ok'
        } catch {
            $entry.status = 'error'
            $entry.error = $_.Exception.Message
        }
        $sw.Stop()
        $entry.durationMs = [int]$sw.Elapsed.TotalMilliseconds
        $entry.note = $context.CollectorNote
        if ($context.Coverage.Count -gt 0) { $entry['logCoverage'] = @($context.Coverage.ToArray()) }
    }
    Write-IRStatus ("{0,-20} {1,-22} records={2,-6} {3}ms {4}" -f $name, $entry.status, $entry.records, $entry.durationMs, (($entry.error, $entry.note) -join ' ').Trim())
    [void]$results.Add([pscustomobject]$entry)
}

# ---------------------------------------------------------------------------------------------
# Manifest (chain of custody)
# ---------------------------------------------------------------------------------------------
$runEnd = (Get-Date).ToUniversalTime()
$fileHashes = @(Get-ChildItem -LiteralPath $OutputPath -File | Sort-Object Name | ForEach-Object {
    [pscustomobject]@{ path = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})

$scriptHash = $null
if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash }

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

# Host addresses for the report header. Primary = IPv4 on an "up" adapter that has a default gateway.
$primaryIPv4 = $null
$ipAddresses = @()
try {
    $up = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.NetAdapter.Status -eq 'Up' })
    $gw = @($up | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object { @($_.IPv4Address)[0].IPAddress } | Where-Object { $_ })
    if ($gw) { $primaryIPv4 = $gw[0] }
    $ipAddresses = @(Get-NetIPAddress -ErrorAction Stop |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127\.|169\.254\.|::1$|fe80:)' } |
        Sort-Object @{ Expression = { [string]$_.AddressFamily } }, InterfaceIndex | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
    if (-not $primaryIPv4) { $primaryIPv4 = $ipAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1 }
} catch { $ipAddresses = @() }

$manifest = [ordered]@{
    schemaVersion = 1
    tool          = [ordered]@{ name = 'IRTriage'; version = $script:IRToolVersion; build = $script:IRBuildInfo; scriptSha256 = $scriptHash; scriptPath = $PSCommandPath }
    case          = [ordered]@{ caseId = $CaseId; analyst = $Analyst; executedAs = $executedAs; elevated = $elevated }
    host          = [ordered]@{
        computerName = $env:COMPUTERNAME
        primaryIPv4  = $primaryIPv4
        ipAddresses  = @($ipAddresses)
        domain       = $cs.Domain
        osCaption    = $os.Caption
        osVersion    = $os.Version
        osBuild      = $os.BuildNumber
        timeZone     = [System.TimeZoneInfo]::Local.Id
    }
    run           = [ordered]@{
        profile           = $TriageProfile
        options           = [ordered]@{
            lookbackHours = $context.LookbackHours; maxEventsPerCollector = $context.MaxEvents; signatures = $context.Signatures
            recentFileDays = $context.RecentFileDays; skipSlow = [bool]$SkipSlow; timeBudgetSeconds = $budget
        }
        collectorOverride = [bool]$Collectors
        startUtc          = $runStart.ToString('o')
        endUtc            = $runEnd.ToString('o')
        durationSeconds   = [math]::Round(($runEnd - $runStart).TotalSeconds, 1)
    }
    collectors    = @($results)
    files         = $fileHashes
}
Write-IRUtf8File -Path (Join-Path $OutputPath 'manifest.json') -Content (ConvertTo-Json -InputObject (ConvertTo-IRPlain $manifest) -Depth 8)

# ---------------------------------------------------------------------------------------------
# Report (built from the files just written, exactly as an analyst would load them)
# ---------------------------------------------------------------------------------------------
$reportPath = $null
if (-not $NoReport) {
    try {
        $triage = Import-IRTriage -Path $OutputPath
        $inner = New-IRTriageReport -Triage $triage -OutFile (Join-Path $OutputPath 'report.html') -GeneratedBy "Invoke-IRTriage.ps1 $script:IRToolVersion on $env:COMPUTERNAME"
        $reportPath = "$OutputPath-report.html"
        Copy-Item -LiteralPath $inner -Destination $reportPath -Force
        $leadCounts = @(Get-IRTriageLeads -Triage $triage | Group-Object Severity | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
        Write-IRStatus "Report: $reportPath  ($leadCounts)"
    } catch {
        $reportPath = $null
        Write-IRStatus "WARNING: report generation failed: $($_.Exception.Message). Evidence is unaffected; rebuild it with analyst\ConvertTo-TriageReport.ps1."
    }
}

# ---------------------------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------------------------
$zipHash = $null
if (-not $NoZip) {
    Compress-Archive -Path (Join-Path $OutputPath '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    Write-IRUtf8File -Path "$zipPath.sha256" -Content ("{0}  {1}`n" -f $zipHash, (Split-Path -Leaf $zipPath))
    if (-not $KeepFolder) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
}

$errors = @($results | Where-Object { $_.status -eq 'error' }).Count
$skipped = @($results | Where-Object { $_.status -like 'skipped*' }).Count
Write-IRStatus ("Done in {0}s. collectors ok={1} error={2} skipped={3}" -f $manifest.run.durationSeconds, (@($results | Where-Object { $_.status -eq 'ok' }).Count), $errors, $skipped)
if ($zipHash) { Write-IRStatus "Zip: $zipPath  SHA256=$zipHash" }
# Paste-ready retrieval commands for EDR live response consoles (MDE getfile; CrowdStrike RTR uses 'get').
if ($zipHash) { Write-IRStatus "Retrieve evidence: getfile ""$zipPath""" }
if ($reportPath) { Write-IRStatus "Retrieve report:   getfile ""$reportPath""" }

$summary = [ordered]@{
    host = $env:COMPUTERNAME; caseId = $CaseId; profile = $TriageProfile; elevated = $elevated
    outputPath = $(if ($NoZip -or $KeepFolder) { $OutputPath } else { $null })
    zipPath = $(if ($zipHash) { $zipPath } else { $null }); zipSha256 = $zipHash
    reportPath = $reportPath
    errors = $errors; skipped = $skipped; durationSeconds = $manifest.run.durationSeconds
}

if ($OpenReport -and $reportPath) {
    $isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    if ([Environment]::UserInteractive -and -not $isSystem) { Invoke-Item -LiteralPath $reportPath }
    else { Write-IRStatus 'Not opening the report: no interactive desktop in this session.' }
}

Write-Output ('IRTRIAGE_RESULT ' + (ConvertTo-Json -InputObject ([pscustomobject]$summary) -Compress))
