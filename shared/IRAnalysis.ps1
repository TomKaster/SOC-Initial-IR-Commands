# IRTRIAGE-COMPONENT shared/IRAnalysis.ps1
# Shared analysis code: load a collection, verify integrity, derive heuristic leads.
# Used by the analyst scripts (via analyst/TriageCommon.ps1) and by the collector, which builds report.html
# on the endpoint. build.ps1 inlines this folder into the single-file collector, so keep it PS 5.1 + ASCII.

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
    # report.html is derived from the evidence after the manifest is written, so it is not hashed in it.
    $listed = @($manifest.files | ForEach-Object { $_.path }) + 'manifest.json' + 'report.html'
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
    @{ Pattern = '(?i)frombase64string'; Why = 'base64 decode'; Severity = 'review' },
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

function Get-IRLogCoverageLeads {
    <#
      Event collectors record how far back each log really reaches (manifest collectors[].logCoverage).
      A log that is full and circular overwrites its oldest events, so a quiet log may just be an emptied one.
    #>
    param($Triage)
    foreach ($c in @($Triage.Manifest.collectors | Where-Object { $_.PSObject.Properties['logCoverage'] -and $_.logCoverage })) {
        foreach ($cov in @($c.logCoverage)) {
            if ($cov.oldestEventUtc -and -not $cov.coversLookback) {
                $oldest = ($cov.oldestEventUtc -replace 'T', ' ' -replace '\.\d+Z$', 'Z')
                $start = ($cov.lookbackStartUtc -replace 'T', ' ' -replace '\.\d+Z$', 'Z')
                if ($cov.isFull) {
                    $detail = "Lookback starts $start, but the log is full ($($cov.fileSizeMB) of $($cov.maxSizeMB) MB, $($cov.logMode)) and older events were overwritten. Absence of events before $oldest proves nothing. Raise this log's maximum size by GPO."
                } else {
                    $detail = "Lookback starts $start, but the oldest event in the log is $oldest and the log is not full. It may have been cleared or recreated (check Security 1102 / System 104), or the host is newer than the lookback."
                }
                New-IRLead 'review' 'Collection' "$($cov.log) only reaches back to $oldest" $detail $c.name
            }
            if ($cov.truncatedAtMaxEvents) {
                New-IRLead 'info' 'Collection' "$($cov.log): only the newest $($cov.eventsCollected) events were collected" "Matching events exceeded the profile's maxEventsPerCollector. Re-run with a larger profile or -LookbackHours to narrow the window." $c.name
            }
        }
    }
}

function Get-IRScriptBlockLeads {
    <#
      4104 script blocks: chunks of one block share a ScriptBlockId, and the same script often runs many times.
      Reassemble each block, group identical text into one lead, grade it with the command patterns, and
      recognise IRTriage's own code (which contains these very patterns) instead of flagging it.
    #>
    param($Triage)
    $events = @(Get-IRRecords $Triage 'events_powershell' | Where-Object { $_.EventId -eq 4104 })
    if ($events.Count -eq 0) { return }

    $blocks = @{}
    foreach ($e in $events) {
        $id = [string]$e.Data.ScriptBlockId
        if (-not $id) { $id = "record-$($e.RecordId)" }
        if (-not $blocks.ContainsKey($id)) { $blocks[$id] = New-Object System.Collections.ArrayList }
        [void]$blocks[$id].Add($e)
    }

    $groups = @{}
    $selfCount = 0
    $selfPaths = New-Object System.Collections.ArrayList
    foreach ($id in $blocks.Keys) {
        $parts = @($blocks[$id] | Sort-Object { [int]("0" + $_.Data.MessageNumber) })
        $text = ($parts | ForEach-Object { [string]$_.Data.ScriptBlockText }) -join ''
        if ($text -match 'IRTRIAGE-COMPONENT|\$script:IRToolVersion\s*=|function Get-IRTriageLeads\b|IRTRIAGE_RESULT') {
            $selfCount++
            $sp = [string]$parts[0].Data.Path
            if (-not $sp) { $sp = '(interactive or -Command, no script path)' }
            if (-not $selfPaths.Contains($sp)) { [void]$selfPaths.Add($sp) }
            continue
        }
        $sev = Get-IRCommandSeverity (' ' + $text)
        if (-not $sev) { continue }
        $key = "{0}|{1}" -f $text.Length, $text.Substring(0, [math]::Min(4000, $text.Length))
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [pscustomobject]@{ Text = $text; Severity = $sev; Times = (New-Object System.Collections.ArrayList); Ids = (New-Object System.Collections.ArrayList); Path = [string]$parts[0].Data.Path }
        }
        foreach ($p in $parts) { [void]$groups[$key].Times.Add([string]$p.TimeCreated) }
        [void]$groups[$key].Ids.Add($id)
    }

    foreach ($g in $groups.Values) {
        $why = Test-IRSuspiciousCommand (' ' + $g.Text)
        $times = @($g.Times | Sort-Object)
        $runs = $g.Ids.Count
        $snippet = ($g.Text -replace '\s+', ' ').Trim()
        if ($snippet.Length -gt 400) { $snippet = $snippet.Substring(0, 400) + '...' }
        $when = $times[0]
        if ($runs -gt 1) { $when = "$($times[0]) to $($times[-1])" }
        $src = ''
        if ($g.Path) { $src = " from $($g.Path)" }
        $title = "Suspicious PowerShell script block ($($why -join ', '))"
        if ($runs -gt 1) { $title += " x$runs" }
        New-IRLead $g.Severity 'Execution' $title ("{0}{1} :: {2}" -f $when, $src, $snippet) 'events_powershell'
    }
    if ($selfCount -gt 0) {
        New-IRLead 'info' 'Collection' "IRTriage's own code appears in the PowerShell log ($selfCount script blocks)" ("Expected when the collector or analyst scripts run here: they contain the detection patterns, so they are not graded. Script paths: {0}. If a path is not a copy of IRTriage you recognise, review these blocks in events_powershell.json." -f (($selfPaths | Select-Object -First 8) -join '; ')) 'events_powershell'
    }
}

function ConvertTo-IRUtcDate {
    # ISO-8601 strings from the JSON (or DateTimes) -> UTC DateTime; $null if absent or unparseable.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}

function Format-IRUtc {
    param([datetime]$Value)
    return $Value.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
}

function Get-IRHistoryTimeline {
    <#
      PSReadLine history has no timestamps. Dates each line from evidence, and says how:
        exact  - the same command text was logged as a 4104 script block by the same user (SID), in history order.
        approx - last line of the file with no 4104 match: PSReadLine saves after every command, so it ran at
                 about the file's last-write time.
        range  - between the nearest dated lines before and after it (history is in run order), or at/before
                 the file's last-write time when nothing later is dated.
      Returns the powershell_history records with RanAt (display), RanAtUtc (exact/approx time, else upper bound)
      and TimeBasis added, ordered by user, file and line.
    #>
    param($Triage)
    $hist = @(Get-IRRecords $Triage 'powershell_history')
    if ($hist.Count -eq 0) { return @() }

    # Reassemble 4104 chunks into script blocks: text -> list of { Id, Time, Sid }.
    $blocks = @{}
    foreach ($e in @(Get-IRRecords $Triage 'events_powershell' | Where-Object { $_.EventId -eq 4104 })) {
        $id = [string]$e.Data.ScriptBlockId
        if (-not $id) { $id = "record-$($e.RecordId)" }
        if (-not $blocks.ContainsKey($id)) { $blocks[$id] = New-Object System.Collections.ArrayList }
        [void]$blocks[$id].Add($e)
    }
    $byText = @{}
    foreach ($id in $blocks.Keys) {
        $parts = @($blocks[$id] | Sort-Object { [int]("0" + $_.Data.MessageNumber) })
        $text = (($parts | ForEach-Object { [string]$_.Data.ScriptBlockText }) -join '') -replace "`r`n", "`n"
        $text = $text.Trim()
        if (-not $text) { continue }
        $t = @($parts | ForEach-Object { ConvertTo-IRUtcDate $_.TimeCreated } | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
        if (-not $t) { continue }
        if (-not $byText.ContainsKey($text)) { $byText[$text] = New-Object System.Collections.ArrayList }
        [void]$byText[$text].Add([pscustomobject]@{ Id = $id; Time = $t[0]; Sid = [string]$parts[0].UserId })
    }

    $used = @{}
    $out = New-Object System.Collections.ArrayList
    foreach ($g in @($hist | Group-Object { "$($_.User)|$($_.File)" } | Sort-Object Name)) {
        $rows = @($g.Group | Sort-Object { [int]$_.LineNumber } | ForEach-Object {
            $r = $_ | Select-Object *
            $r | Add-Member -NotePropertyName RanAt -NotePropertyValue $null -Force
            $r | Add-Member -NotePropertyName RanAtUtc -NotePropertyValue $null -Force
            $r | Add-Member -NotePropertyName TimeBasis -NotePropertyValue 'unknown' -Force
            $r
        })
        $lastWrite = ConvertTo-IRUtcDate $rows[0].FileLastWriteUtc
        $sid = [string]$rows[0].UserSid

        # Pass 1: exact matches, earliest unused block at or after the previous match (history is in run order).
        $floor = $null
        foreach ($r in $rows) {
            $key = (([string]$r.Command) -replace "`r`n", "`n").Trim()
            if (-not $byText.ContainsKey($key)) { continue }
            $cand = @($byText[$key] | Where-Object {
                    -not $used.ContainsKey($_.Id) -and (-not $sid -or -not $_.Sid -or $_.Sid -eq $sid) -and ($null -eq $floor -or $_.Time -ge $floor)
                } | Sort-Object Time | Select-Object -First 1)
            if (-not $cand) { continue }
            $used[$cand[0].Id] = $true
            $floor = $cand[0].Time
            $r.RanAtUtc = $cand[0].Time
            $r.TimeBasis = 'exact'
            $r.RanAt = Format-IRUtc $cand[0].Time
        }
        # The newest line ran at about the time the file was last saved.
        $last = $rows[-1]
        if ($last.TimeBasis -ne 'exact' -and $lastWrite) {
            $last.RanAtUtc = $lastWrite
            $last.TimeBasis = 'approx'
            $last.RanAt = '~' + (Format-IRUtc $lastWrite)
        }
        # Pass 2: bound the rest by their dated neighbours.
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if ($r.TimeBasis -ne 'unknown') { continue }
            $lo = $null; $hi = $null
            for ($j = $i - 1; $j -ge 0; $j--) { if ($rows[$j].TimeBasis -in 'exact', 'approx') { $lo = $rows[$j].RanAtUtc; break } }
            for ($j = $i + 1; $j -lt $rows.Count; $j++) { if ($rows[$j].TimeBasis -in 'exact', 'approx') { $hi = $rows[$j].RanAtUtc; break } }
            if (-not $hi) { $hi = $lastWrite }
            if ($lo -and $hi) { $r.RanAt = "$(Format-IRUtc $lo) to $(Format-IRUtc $hi)"; $r.TimeBasis = 'range'; $r.RanAtUtc = $hi }
            elseif ($hi) { $r.RanAt = "at or before $(Format-IRUtc $hi)"; $r.TimeBasis = 'range'; $r.RanAtUtc = $hi }
            elseif ($lo) { $r.RanAt = "after $(Format-IRUtc $lo)"; $r.TimeBasis = 'range' }
        }
        foreach ($r in $rows) { [void]$out.Add($r) }
    }
    return $out.ToArray()
}

# Default pipe names of C2 frameworks and remote-execution tools. Operators can rename them, so absence proves nothing.
$script:IRPipePatterns = @(
    @{ Pattern = '^MSSE-\d+-server$'; Why = 'Cobalt Strike default (artifact kit)'; Severity = 'high' },
    @{ Pattern = '^msagent_[0-9a-f]{2,4}$'; Why = 'Cobalt Strike SMB beacon default'; Severity = 'high' },
    @{ Pattern = '^status_[0-9a-f]{2}$'; Why = 'Cobalt Strike default'; Severity = 'high' },
    @{ Pattern = '^postex_(ssh_)?[0-9a-f]{4}$'; Why = 'Cobalt Strike post-exploitation default'; Severity = 'high' },
    @{ Pattern = '^(gruntsvc|jaccdpqnvbrrxlaf|ntsvcs_[0-9a-f]+|scerpc_?[0-9a-f]*)$'; Why = 'Covenant/PoshC2/Metasploit default'; Severity = 'high' },
    @{ Pattern = '^RemCom_comm'; Why = 'RemCom/Impacket remote execution'; Severity = 'high' },
    @{ Pattern = '^(PSEXESVC|paexec|csexec)'; Why = 'PsExec-style remote execution (also seen when IRTriage is launched with psexec)'; Severity = 'review' }
)

function Get-IRExtendedLeads {
    <# Leads for named pipes, BITS jobs, PowerShell history and Security 4688/4698/4702/4719. #>
    param($Triage)

    foreach ($p in Get-IRRecords $Triage 'named_pipes') {
        $name = [string]$p.PipeName
        $hit = $script:IRPipePatterns | Where-Object { $name -match $_.Pattern } | Select-Object -First 1
        if ($hit) { New-IRLead $hit.Severity 'Execution' "Named pipe $name" $hit.Why 'named_pipes' }
    }

    $msHost = '(?i)^https?://([^/]+\.)?(microsoft\.com|windowsupdate\.com|windows\.com|msedge\.net|office\.net|office\.com|live\.com|bing\.com|msftconnecttest\.com|azureedge\.net)(:\d+)?/'
    foreach ($j in Get-IRRecords $Triage 'bits_jobs') {
        $remotes = @(([string]$j.RemoteNames) -split '\s*\|\s*' | Where-Object { $_ })
        $foreign = @($remotes | Where-Object { $_ -match '^(?i)(https?|smb)://|^\\\\' -and $_ -notmatch $msHost })
        $detail = "owner=$($j.Owner) state=$($j.JobState) remote=$($remotes -join ', ') local=$($j.LocalNames)"
        if ($j.NotifyCmdLine) {
            New-IRLead 'high' 'Persistence' "BITS job '$($j.DisplayName)' runs a command on completion" "$($j.NotifyCmdLine) :: $detail" 'bits_jobs'
        } elseif ($foreign.Count) {
            New-IRLead 'review' 'Execution' "BITS job '$($j.DisplayName)' downloads from a non-Microsoft host" $detail 'bits_jobs'
        }
    }

    # PowerShell history: one lead per distinct suspicious command per user.
    $seen = @{}
    foreach ($h in @(Get-IRHistoryTimeline $Triage)) {
        $cmd = [string]$h.Command
        $sev = Get-IRCommandSeverity (' ' + $cmd)
        if (-not $sev) { continue }
        $key = "$($h.User)|$cmd"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $why = Test-IRSuspiciousCommand (' ' + $cmd)
        New-IRLead $sev 'Execution' "PowerShell history of $($h.User) ($($why -join ', '))" ("ran {0} ({1}); {2} line {3} :: {4}" -f $h.RanAt, $h.TimeBasis, $h.File, $h.LineNumber, $cmd) 'powershell_history'
    }

    # 4688: grade command lines, grouped so a looping task does not produce hundreds of leads.
    $groups = @{}
    foreach ($e in Get-IRRecords $Triage 'events_process_creation') {
        $cmd = [string]$e.Data.CommandLine
        if (-not $cmd -or $cmd -match 'IRTRIAGE|Invoke-IRTriage') { continue }
        $sev = Get-IRCommandSeverity (' ' + $cmd)
        if (-not $sev) { continue }
        if (-not $groups.ContainsKey($cmd)) { $groups[$cmd] = [pscustomobject]@{ Sev = $sev; Events = (New-Object System.Collections.ArrayList) } }
        [void]$groups[$cmd].Events.Add($e)
    }
    foreach ($cmd in $groups.Keys) {
        $g = $groups[$cmd]
        $first = $g.Events[0]
        $times = @($g.Events | ForEach-Object { [string]$_.TimeCreated } | Sort-Object)
        $when = $times[0]
        if ($times.Count -gt 1) { $when = "$($times[0]) to $($times[-1]) x$($times.Count)" }
        $why = Test-IRSuspiciousCommand (' ' + $cmd)
        New-IRLead $g.Sev 'Execution' "Process created with suspicious command line ($($why -join ', '))" ("{0} {1}\{2} parent={3} :: {4}" -f $when, $first.Data.SubjectDomainName, $first.Data.SubjectUserName, $first.Data.ParentProcessName, $cmd) 'events_process_creation'
    }

    # Installed applications: remote access tools (legitimate in many shops, but a favourite of intrusions and
    # tech-support scams) and Store/MSIX packages that are sideloaded rather than Store- or enterprise-signed.
    $rmm = '(?i)\b(anydesk|teamviewer|screenconnect|connectwise control|atera|splashtop|rustdesk|netsupport|kaseya|logmein|gotoassist|goto resolve|ammyy|remote utilities|meshagent|meshcentral|tightvnc|ultravnc|realvnc|vnc server|tigervnc|zoho assist|simplehelp|action1|n-able|bomgar|beyondtrust remote|dameware|supremo|remotepc|parsec|chrome remote desktop|level\.io|tactical rmm)\b'
    $rmmSeen = @{}
    foreach ($a in Get-IRRecords $Triage 'installed_software') {
        $name = [string]$a.DisplayName
        if ($name -match $rmm -and -not $rmmSeen.ContainsKey($name)) {
            $rmmSeen[$name] = $true
            New-IRLead 'review' 'Remote access' "Remote access tool installed: $name $($a.DisplayVersion)" ("{0} scope={1} installed={2} location={3}" -f $a.Publisher, $a.Scope, $a.InstallDate, $a.InstallLocation) 'installed_software'
        }
        if ($a.Type -eq 'Store' -and [string]$a.SignatureKind -in 'Developer', 'None') {
            New-IRLead 'review' 'Execution' "Sideloaded app package: $name $($a.DisplayVersion)" ("signature={0} publisher={1} scope={2} location={3}" -f $a.SignatureKind, $a.Publisher, $a.Scope, $a.InstallLocation) 'installed_software'
        }
    }

    foreach ($e in Get-IRRecords $Triage 'events_security') {
        # Windows servicing creates and updates \Microsoft\ tasks constantly; only report the others.
        if ([int]$e.EventId -in 4698, 4702 -and [string]$e.Data.TaskName -like '\Microsoft\*') { continue }
        switch ([int]$e.EventId) {
            4698 { New-IRLead 'review' 'Persistence' "Scheduled task created: $($e.Data.TaskName)" ("{0} by {1}\{2}" -f $e.TimeCreated, $e.Data.SubjectDomainName, $e.Data.SubjectUserName) 'events_security' }
            4702 { New-IRLead 'info' 'Persistence' "Scheduled task updated: $($e.Data.TaskName)" ("{0} by {1}\{2}" -f $e.TimeCreated, $e.Data.SubjectDomainName, $e.Data.SubjectUserName) 'events_security' }
            4719 { New-IRLead 'review' 'Defense evasion' 'System audit policy changed (4719)' ("{0} by {1}\{2} subcategory={3} changes={4}" -f $e.TimeCreated, $e.Data.SubjectDomainName, $e.Data.SubjectUserName, $e.Data.SubcategoryGuid, $e.Data.AuditPolicyChanges) 'events_security' }
        }
    }
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
    foreach ($lead in @(Get-IRLogCoverageLeads $Triage)) { [void]$leads.Add($lead) }
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
    foreach ($lead in @(Get-IRScriptBlockLeads $Triage)) { [void]$leads.Add($lead) }
    foreach ($e in @(Get-IRRecords $Triage 'events_rdp' | Where-Object { $_.EventId -eq 1149 })) {
        [void]$leads.Add((New-IRLead 'info' 'Lateral movement' "RDP authentication from $($e.Data.Param3)" ("{0} user={1}\{2}" -f $e.TimeCreated, $e.Data.Param2, $e.Data.Param1) 'events_rdp'))
    }

    foreach ($lead in @(Get-IRExtendedLeads $Triage)) { [void]$leads.Add($lead) }

    $order = @{ high = 0; review = 1; info = 2 }
    return @($leads | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Title)
}
