# Shared analyst-side helpers. Dot-sourced by the scripts in this folder:  . "$PSScriptRoot\TriageCommon.ps1"
# Works on Windows PowerShell 5.1 and PowerShell 7+.

function ConvertFrom-IRJsonArray {
    # PS 5.1's ConvertFrom-Json emits a JSON array as ONE object; pipe through ForEach to unroll it.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    return @((ConvertFrom-Json -InputObject $Text) | ForEach-Object { $_ })
}

function Import-IRTriage {
    <#
    .SYNOPSIS
        Loads a triage collection (zip or extracted folder), verifies file hashes against the manifest.
    .OUTPUTS
        PSCustomObject: Path, Folder, Manifest, Data (hashtable collector -> records), Integrity
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExtractTo
    )
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $folder = $resolved
    $zipIntegrity = $null

    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        if ($resolved -notmatch '\.zip$') { throw "Expected a triage .zip or folder: $Path" }
        $shaFile = "$resolved.sha256"
        if (Test-Path -LiteralPath $shaFile) {
            $expected = (([System.IO.File]::ReadAllText($shaFile)).Trim() -split '\s+')[0]
            $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
            $zipIntegrity = [pscustomobject]@{ Expected = $expected; Actual = $actual; Match = ($expected -eq $actual) }
        }
        if (-not $ExtractTo) {
            $ExtractTo = Join-Path ([System.IO.Path]::GetTempPath()) ("IRTriage-" + [System.IO.Path]::GetFileNameWithoutExtension($resolved) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        }
        Expand-Archive -LiteralPath $resolved -DestinationPath $ExtractTo -Force
        $folder = $ExtractTo
    }

    $manifestPath = Join-Path $folder 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw "manifest.json not found in $folder - not an IRTriage collection?" }
    $manifest = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($manifestPath))

    $mismatches = @()
    foreach ($f in @($manifest.files)) {
        $fp = Join-Path $folder $f.path
        if (-not (Test-Path -LiteralPath $fp)) { $mismatches += [pscustomobject]@{ File = $f.path; Problem = 'missing' }; continue }
        $h = (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash
        if ($h -ne $f.sha256) { $mismatches += [pscustomobject]@{ File = $f.path; Problem = 'hash mismatch' } }
    }
    $listed = @($manifest.files | ForEach-Object { $_.path }) + 'manifest.json'
    foreach ($extra in @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $listed -notcontains $_.Name })) {
        $mismatches += [pscustomobject]@{ File = $extra.Name; Problem = 'not in manifest' }
    }

    $data = @{}
    foreach ($c in @($manifest.collectors)) {
        $jp = Join-Path $folder "$($c.name).json"
        if (Test-Path -LiteralPath $jp) { $data[$c.name] = ConvertFrom-IRJsonArray ([System.IO.File]::ReadAllText($jp)) }
    }

    $valid = ($mismatches.Count -eq 0) -and ($null -eq $zipIntegrity -or $zipIntegrity.Match)
    [pscustomobject]@{
        Path      = $resolved
        Folder    = $folder
        Host      = $manifest.host.computerName
        Manifest  = $manifest
        Data      = $data
        Integrity = [pscustomobject]@{ Valid = $valid; Zip = $zipIntegrity; Problems = $mismatches }
    }
}

function Get-IRRecords {
    param($Triage, [string]$Collector)
    if ($Triage.Data.ContainsKey($Collector)) { return @($Triage.Data[$Collector]) }
    return @()
}

$script:IRSuspiciousCommandPatterns = @(
    @{ Pattern = '(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}'; Why = 'PowerShell encoded command' },
    @{ Pattern = '(?i)(iex|invoke-expression)\s*[\(\$''"]'; Why = 'Invoke-Expression' },
    @{ Pattern = '(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr\s|invoke-restmethod|net\.webclient|start-bitstransfer)'; Why = 'download cradle' },
    @{ Pattern = '(?i)frombase64string'; Why = 'base64 decode' },
    @{ Pattern = '(?i)-(w|win|window|windowstyle)\s+h(idden)?\b'; Why = 'hidden window'; Severity = 'review' },
    @{ Pattern = '(?i)-(ep|exec|executionpolicy)\s+bypass'; Why = 'execution policy bypass'; Severity = 'review' },
    @{ Pattern = '(?i)certutil(\.exe)?\s.*(-urlcache|-decode|-split)'; Why = 'certutil download/decode' },
    @{ Pattern = '(?i)bitsadmin(\.exe)?\s.*/transfer'; Why = 'bitsadmin transfer' },
    @{ Pattern = '(?i)mshta(\.exe)?\s+["'']?(https?:|javascript:|vbscript:)'; Why = 'mshta remote/script' },
    @{ Pattern = '(?i)regsvr32(\.exe)?\s.*/i:\s*https?:'; Why = 'regsvr32 squiblydoo' },
    @{ Pattern = '(?i)rundll32(\.exe)?\s.*(javascript:|\\\\[^\\]+\\|,\s*#\d)'; Why = 'rundll32 abuse' },
    @{ Pattern = '(?i)(vssadmin|wmic)(\.exe)?\s.*shadowcopy\s+delete|vssadmin(\.exe)?\s+delete\s+shadows'; Why = 'shadow copy deletion' },
    @{ Pattern = '(?i)wevtutil(\.exe)?\s+(cl|clear-log)'; Why = 'event log clearing' },
    @{ Pattern = '(?i)(procdump|comsvcs(\.dll)?.*minidump|sekurlsa|mimikatz)'; Why = 'credential dumping' },
    @{ Pattern = '(?i)\\\\[^\\\s]+\\(admin|c|ipc)\$'; Why = 'admin share access'; Severity = 'review' }
)

function Test-IRSuspiciousCommand {
    # Returns the reasons a command line matched (empty array if none).
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    return @($script:IRSuspiciousCommandPatterns | Where-Object { $CommandLine -match $_.Pattern } | ForEach-Object { $_.Why })
}

function Get-IRCommandSeverity {
    # 'high' if any high-signal pattern matched, 'review' if only low-signal ones, $null if none.
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $hits = @($script:IRSuspiciousCommandPatterns | Where-Object { $CommandLine -match $_.Pattern })
    if ($hits.Count -eq 0) { return $null }
    if (@($hits | Where-Object { -not $_.Severity }).Count -gt 0) { return 'high' }
    return 'review'
}

function Test-IRTrustedImage {
    # True for Microsoft-signed images, and for Defender's platform folder (lives under ProgramData).
    param($Record, [string]$PathProperty = 'ImagePath')
    $path = [string]$Record.$PathProperty
    if ($path -match '(?i)\\ProgramData\\Microsoft\\Windows Defender( Advanced Threat Protection)?\\Platform\\') { return $true }
    return ([string]$Record.SignatureStatus -eq 'Valid' -and [string]$Record.Signer -match 'O=Microsoft Corporation')
}

function Test-IRUserWritablePathString {
    # Analyst-side twin of the collector's Test-IRUserWritablePath (the collector modules are not loaded here).
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path -match '(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp|Temp|PerfLogs|\$Recycle\.Bin)\\')
}

function New-IRLead {
    param([string]$Severity, [string]$Category, [string]$Title, [string]$Detail, [string]$Collector)
    [pscustomobject]@{ Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail; Collector = $Collector }
}

function Get-IRTriageLeads {
    <#
    .SYNOPSIS
        Heuristic "things to look at" from a triage collection. These are leads for an analyst, not verdicts.
        Severity: high (rarely benign), review (often benign but worth a look), info (context).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Triage)
    $leads = New-Object System.Collections.ArrayList
    $isMs = { param($r) ($r.Signer -match 'O=Microsoft Corporation') }

    foreach ($c in @($Triage.Manifest.collectors | Where-Object { $_.status -eq 'error' })) {
        [void]$leads.Add((New-IRLead 'info' 'Collection' "Collector $($c.name) failed" $c.error $c.name))
    }
    if (-not $Triage.Manifest.case.elevated) {
        [void]$leads.Add((New-IRLead 'info' 'Collection' 'Collection was not elevated' 'Admin-only collectors were skipped and owners/paths may be missing.' 'manifest'))
    }

    $procs = Get-IRRecords $Triage 'processes'
    foreach ($p in $procs) {
        $sev = Get-IRCommandSeverity $p.CommandLine
        if ($sev) {
            $why = Test-IRSuspiciousCommand $p.CommandLine
            [void]$leads.Add((New-IRLead $sev 'Process' "Suspicious command line: $($p.Name) (PID $($p.ProcessId))" ("[{0}] parent={1} owner={2} :: {3}" -f ($why -join ', '), $p.ParentName, $p.Owner, $p.CommandLine) 'processes'))
        }
        if ($p.ParentName -match '^(?i)(winword|excel|powerpnt|outlook|onenote|msaccess|mspub|acrord32|acrobat)\.exe$' -and $p.Name -match '^(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$') {
            [void]$leads.Add((New-IRLead 'high' 'Process' "Office/PDF app spawned $($p.Name)" "$($p.ParentName) -> $($p.CommandLine)" 'processes'))
        }
    }

    # One lead per unique image (not per PID) to keep browsers/Electron apps from flooding the list.
    foreach ($g in @($procs | Where-Object { $_.ExecutablePath -and $_.UserWritable -and -not (Test-IRTrustedImage $_ 'ExecutablePath') } | Group-Object { $_.ExecutablePath.ToLowerInvariant() })) {
        $p = $g.Group[0]
        $sev = 'review'
        if ($p.SignatureStatus -eq 'Valid') { $sev = 'info' }
        [void]$leads.Add((New-IRLead $sev 'Process' "Running from user-writable path: $($p.Name) x$($g.Count)" ("{0} owner={1} signer={2} SHA256={3}" -f $p.ExecutablePath, $p.Owner, $p.Signer, $p.Sha256) 'processes'))
    }
    foreach ($g in @($procs | Where-Object { $_.ExecutablePath -and $_.SignatureStatus -and $_.SignatureStatus -ne 'Valid' -and -not $_.UserWritable } | Group-Object { $_.ExecutablePath.ToLowerInvariant() })) {
        $p = $g.Group[0]
        [void]$leads.Add((New-IRLead 'review' 'Process' "Unsigned/invalid signature: $($p.Name) x$($g.Count)" "$($p.ExecutablePath) status=$($p.SignatureStatus) SHA256=$($p.Sha256)" 'processes'))
    }

    $lolbin = '^(?i)(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msbuild|installutil|curl|wget)\.exe$'
    $conns = Get-IRRecords $Triage 'network_connections'
    foreach ($c in @($conns | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Listen' -and $_.LocalAddress -notmatch '^(127\.|::1$)' })) {
        $sev = 'info'
        if ($c.ProcessName -match $lolbin -or (Test-IRUserWritablePathString $c.ProcessPath)) { $sev = 'review' }
        [void]$leads.Add((New-IRLead $sev 'Network' "Listening TCP $($c.LocalAddress):$($c.LocalPort)" "$($c.ProcessName) $($c.ProcessPath)" 'network_connections'))
    }
    # External established connections, grouped per process image.
    foreach ($g in @($conns | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Established' -and $_.IsExternal } | Group-Object { "$($_.ProcessName)|$($_.ProcessPath)" })) {
        $c = $g.Group[0]
        $sev = 'info'
        if ($c.ProcessName -match $lolbin) { $sev = 'high' }
        elseif (Test-IRUserWritablePathString $c.ProcessPath) { $sev = 'review' }
        $remotes = @($g.Group | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } | Sort-Object -Unique)
        $shown = ($remotes | Select-Object -First 15) -join ', '
        if ($remotes.Count -gt 15) { $shown += " (+$($remotes.Count - 15) more)" }
        [void]$leads.Add((New-IRLead $sev 'Network' "External connections from $($c.ProcessName): $($remotes.Count) remote(s)" "$($c.ProcessPath) -> $shown" 'network_connections'))
    }

    foreach ($s in Get-IRRecords $Triage 'services') {
        $flag = @()
        if ($s.UserWritable -and -not (Test-IRTrustedImage $s)) { $flag += 'user-writable path' }
        if ($s.SignatureStatus -and -not (& $isMs $s) -and $s.SignatureStatus -ne 'Valid') { $flag += "signature $($s.SignatureStatus)" }
        if ($s.PathName -match '(?i)(powershell|cmd\.exe\s*/c|%comspec%|mshta|rundll32)') { $flag += 'script/LOLBin service' }
        if ($flag.Count) {
            $sev = 'review'; if ($flag -contains 'script/LOLBin service') { $sev = 'high' }
            [void]$leads.Add((New-IRLead $sev 'Persistence' "Service $($s.Name) ($($flag -join ', '))" $s.PathName 'services'))
        }
    }
    foreach ($t in @(Get-IRRecords $Triage 'scheduled_tasks' | Where-Object { -not $_.IsMicrosoftPath })) {
        $why = Test-IRSuspiciousCommand $t.Actions
        $sev = 'info'
        if ($t.UserWritable) { $sev = 'review' }
        if ($why.Count) { $sev = 'high' }
        [void]$leads.Add((New-IRLead $sev 'Persistence' "Non-Microsoft scheduled task $($t.TaskPath)$($t.TaskName)" ("{0} [{1}] runAs={2}" -f $t.Actions, ($why -join ', '), $t.RunAs) 'scheduled_tasks'))
    }
    foreach ($r in Get-IRRecords $Triage 'autoruns_registry') {
        $why = Test-IRSuspiciousCommand $r.Value
        $sev = 'info'
        if ($r.UserWritable -or ($r.Name -eq 'Debugger')) { $sev = 'review' }
        if ($why.Count) { $sev = 'high' }
        [void]$leads.Add((New-IRLead $sev 'Persistence' "Autorun $($r.Hive) $($r.Name)" "$($r.Location) = $($r.Value)" 'autoruns_registry'))
    }
    foreach ($w in @(Get-IRRecords $Triage 'wmi_subscriptions' | Where-Object { $_.Type -eq 'Consumer' -and $_.Name -ne 'SCM Event Log Consumer' })) {
        [void]$leads.Add((New-IRLead 'high' 'Persistence' "WMI event consumer $($w.Name)" "$($w.Class): $($w.Detail)" 'wmi_subscriptions'))
    }
    foreach ($s in Get-IRRecords $Triage 'startup_folders') {
        [void]$leads.Add((New-IRLead 'review' 'Persistence' "Startup folder item $($s.Path)" "target=$($s.LnkTarget) $($s.LnkArguments)" 'startup_folders'))
    }

    foreach ($a in Get-IRRecords $Triage 'local_admins') {
        [void]$leads.Add((New-IRLead 'info' 'Accounts' "Local admin: $($a.Name)" "$($a.ObjectClass) $($a.PrincipalSource)" 'local_admins'))
    }
    foreach ($h in @(Get-IRRecords $Triage 'hosts_file' | Where-Object { $_.HostName -notin 'localhost' })) {
        [void]$leads.Add((New-IRLead 'review' 'Network' "hosts file entry $($h.HostName) -> $($h.IPAddress)" "line $($h.LineNumber)" 'hosts_file'))
    }

    $def = @(Get-IRRecords $Triage 'defender') | Select-Object -First 1
    if ($def) {
        if ($def.RealTimeProtectionEnabled -eq $false) { [void]$leads.Add((New-IRLead 'high' 'Defense evasion' 'Defender real-time protection is OFF' '' 'defender')) }
        foreach ($field in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
            foreach ($v in @($def.$field | Where-Object { $_ -and $_ -notmatch '^N/A' })) {
                [void]$leads.Add((New-IRLead 'review' 'Defense evasion' "Defender $field" $v 'defender'))
            }
        }
        foreach ($d in @($def.Detections)) {
            [void]$leads.Add((New-IRLead 'high' 'Malware' "Defender detection ThreatID $($d.ThreatID)" ("{0} {1} {2}" -f $d.ProcessName, $d.DomainUser, (@($d.Resources) -join '; ')) 'defender'))
        }
    }

    $sec = Get-IRRecords $Triage 'events_security'
    if ($sec.Count) {
        $fails = @($sec | Where-Object { $_.EventId -eq 4625 })
        if ($fails.Count -ge 10) {
            $top = ($fails | Group-Object { "$($_.Data.TargetUserName) from $($_.Data.IpAddress)" } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; '
            [void]$leads.Add((New-IRLead 'review' 'Accounts' "$($fails.Count) failed logons (4625)" $top 'events_security'))
        }
        foreach ($e in @($sec | Where-Object { $_.EventId -in 4720, 4728, 4732, 4756 })) {
            [void]$leads.Add((New-IRLead 'high' 'Accounts' "Account/group change event $($e.EventId)" ("{0} target={1} by={2}" -f $e.TimeCreated, $e.Data.TargetUserName, $e.Data.SubjectUserName) 'events_security'))
        }
        foreach ($e in @($sec | Where-Object { $_.EventId -eq 1102 })) { [void]$leads.Add((New-IRLead 'high' 'Defense evasion' 'Security log cleared (1102)' $e.TimeCreated 'events_security')) }
        foreach ($e in @($sec | Where-Object { $_.EventId -eq 4624 -and $_.Data.LogonType -in '3', '10' -and $_.Data.IpAddress -and $_.Data.IpAddress -notin '-', '127.0.0.1', '::1' } | Select-Object -First 25)) {
            [void]$leads.Add((New-IRLead 'info' 'Lateral movement' "Logon type $($e.Data.LogonType) from $($e.Data.IpAddress)" ("{0} {1}\{2}" -f $e.TimeCreated, $e.Data.TargetDomainName, $e.Data.TargetUserName) 'events_security'))
        }
    }
    foreach ($e in @(Get-IRRecords $Triage 'events_system' | Where-Object { $_.EventId -eq 7045 })) {
        $sev = 'review'; if ((Get-IRCommandSeverity $e.Data.ImagePath) -eq 'high') { $sev = 'high' }
        [void]$leads.Add((New-IRLead $sev 'Persistence' "Service installed: $($e.Data.ServiceName)" ("{0} {1}" -f $e.TimeCreated, $e.Data.ImagePath) 'events_system'))
    }
    foreach ($e in @(Get-IRRecords $Triage 'events_system' | Where-Object { $_.EventId -eq 104 })) { [void]$leads.Add((New-IRLead 'high' 'Defense evasion' 'Event log cleared (104)' $e.TimeCreated 'events_system')) }
    foreach ($e in @(Get-IRRecords $Triage 'events_powershell' | Where-Object { $_.EventId -eq 4104 })) {
        $why = Test-IRSuspiciousCommand (' ' + $e.Data.ScriptBlockText)
        if ($why.Count) {
            $txt = [string]$e.Data.ScriptBlockText; if ($txt.Length -gt 300) { $txt = $txt.Substring(0, 300) + '...' }
            [void]$leads.Add((New-IRLead 'high' 'Execution' "Suspicious PowerShell script block ($($why -join ', '))" ("{0} {1}" -f $e.TimeCreated, $txt) 'events_powershell'))
        }
    }
    foreach ($e in @(Get-IRRecords $Triage 'events_rdp' | Where-Object { $_.EventId -eq 1149 })) {
        [void]$leads.Add((New-IRLead 'info' 'Lateral movement' "RDP authentication from $($e.Data.Param3)" ("{0} user={1}\{2}" -f $e.TimeCreated, $e.Data.Param2, $e.Data.Param1) 'events_rdp'))
    }

    $order = @{ high = 0; review = 1; info = 2 }
    return @($leads | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Title)
}
