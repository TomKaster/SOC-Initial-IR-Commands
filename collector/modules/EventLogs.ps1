# IRTRIAGE-COMPONENT modules/EventLogs.ps1
# Targeted event log extraction. Only high-signal event IDs, bounded by lookback window and max count.

function Get-IREvents {
    <#
      Returns events as flat records with the EventData fields parsed out of the XML.
      Sets $Context.CollectorNote when the log does not exist or has no matching events.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int[]]$Id,
        [Parameter(Mandatory)]$Context,
        [int]$MaxDataLength = 8192
    )
    $log = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
    if (-not $log) {
        $Context.CollectorNote = (("{0} {1}: log not present" -f $Context.CollectorNote, $LogName)).Trim()
        return
    }
    $filter = @{ LogName = $LogName; Id = $Id; StartTime = $Context.LookbackStart }
    $events = @()
    $noMatches = $false
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Context.MaxEvents -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $noMatches = $true } else { throw }
    }
    $truncated = ($events.Count -ge $Context.MaxEvents)
    if ($truncated) {
        $Context.CollectorNote = (("{0} {1}: truncated at {2} events (newest kept)" -f $Context.CollectorNote, $LogName, $Context.MaxEvents)).Trim()
    }

    # Coverage: how far back this log really reaches. A full circular log silently drops its oldest events,
    # so "no events found" may only mean "no events left". The report turns gaps into leads.
    $oldest = $null
    try { $oldest = (Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $oldest = $null }
    $maxBytes = [double]$log.MaximumSizeInBytes
    $fileBytes = [double]$log.FileSize
    [void]$Context.Coverage.Add([pscustomobject]@{
        log                  = $LogName
        oldestEventUtc       = (ConvertTo-IRIsoTime $oldest)
        lookbackStartUtc     = (ConvertTo-IRIsoTime $Context.LookbackStart)
        coversLookback       = [bool]($oldest -and $oldest -le $Context.LookbackStart)
        logMode              = [string]$log.LogMode
        maxSizeMB            = [math]::Round($maxBytes / 1MB, 1)
        fileSizeMB           = [math]::Round($fileBytes / 1MB, 1)
        isFull               = [bool]($maxBytes -gt 0 -and $fileBytes -ge 0.95 * $maxBytes)
        recordCount          = $log.RecordCount
        eventsCollected      = $events.Count
        truncatedAtMaxEvents = $truncated
    })
    if ($noMatches) { return }
    foreach ($e in $events) {
        $data = [ordered]@{}
        try {
            $xml = [xml]$e.ToXml()
            $idx = 0
            foreach ($d in @($xml.Event.EventData.Data)) {
                if ($null -eq $d) { continue }
                $name = $d.Name
                if (-not $name) { $name = "Data$idx" }
                $text = [string]$d.'#text'
                if ($text.Length -gt $MaxDataLength) { $text = $text.Substring(0, $MaxDataLength) + '...[truncated]' }
                $data[$name] = $text
                $idx++
            }
            if ($idx -eq 0 -and $xml.Event.UserData) {
                foreach ($child in @($xml.Event.UserData.ChildNodes)) {
                    foreach ($n in @($child.ChildNodes)) { $data[$n.LocalName] = [string]$n.InnerText }
                }
            }
        } catch { $data['_parseError'] = $_.Exception.Message }

        [pscustomobject]@{
            TimeCreated  = $e.TimeCreated
            LogName      = $e.LogName
            Provider     = $e.ProviderName
            EventId      = $e.Id
            Level        = $e.LevelDisplayName
            RecordId     = $e.RecordId
            ProcessId    = $e.ProcessId
            UserId       = [string]$e.UserId
            Data         = [pscustomobject]$data
        }
    }
}

function Get-IREventsSecurity {
    # 4624/4625 logon success/fail, 4648 explicit creds, 4672 admin logon, 4720 user created,
    # 4728/4732/4756 added to privileged group, 4697 service installed, 1102 audit log cleared.
    [CmdletBinding()]
    param($Context)
    Get-IREvents -LogName 'Security' -Id 4624, 4625, 4648, 4672, 4720, 4728, 4732, 4756, 4697, 1102 -Context $Context
}

function Get-IREventsSystem {
    # 7045 service installed, 7040 start type changed, 104 log cleared, 6005/6006/6008 boot/shutdown.
    [CmdletBinding()]
    param($Context)
    Get-IREvents -LogName 'System' -Id 7045, 7040, 104, 6005, 6006, 6008 -Context $Context
}

function Get-IREventsPowerShell {
    # 4104 script block logging, 4103 module logging.
    [CmdletBinding()]
    param($Context)
    # Script blocks are the evidence itself: keep their full text (Windows splits blocks into chunks of ~32K chars).
    Get-IREvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104, 4103 -Context $Context -MaxDataLength 65536
}

function Get-IREventsRdp {
    # 1149 RDP auth succeeded (network), 21/24/25 session logon/disconnect/reconnect.
    [CmdletBinding()]
    param($Context)
    Get-IREvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149 -Context $Context
    Get-IREvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Id 21, 24, 25 -Context $Context
}

function Get-IREventsSysmon {
    # 1 process create, 3 network connect, 7 image load, 8 CreateRemoteThread, 10 process access,
    # 11 file create, 13 registry value set, 22 DNS query.
    [CmdletBinding()]
    param($Context)
    Get-IREvents -LogName 'Microsoft-Windows-Sysmon/Operational' -Id 1, 3, 8, 10, 11, 13, 22 -Context $Context
}

function Get-IRDefender {
    [CmdletBinding()]
    param($Context)
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        $Context.CollectorNote = 'Defender cmdlets not available (third-party AV or Server Core without Defender)'
        return
    }
    $status = $null; $pref = $null; $threats = @()
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $status = $null }
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { $pref = $null }
    try { $threats = @(Get-MpThreatDetection -ErrorAction Stop) } catch { $threats = @() }

    $events = @(Get-IREvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Id 1006, 1007, 1116, 1117, 5001, 5007, 5010, 5012 -Context $Context)

    [pscustomobject]@{
        AMRunningMode            = $status.AMRunningMode
        AntivirusEnabled         = $status.AntivirusEnabled
        RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
        BehaviorMonitorEnabled   = $status.BehaviorMonitorEnabled
        IsTamperProtected        = $status.IsTamperProtected
        AntivirusSignatureAge    = $status.AntivirusSignatureAge
        AntivirusSignatureVersion = $status.AntivirusSignatureVersion
        QuickScanEndTime         = $status.QuickScanEndTime
        ExclusionPath            = @($pref.ExclusionPath)
        ExclusionProcess         = @($pref.ExclusionProcess)
        ExclusionExtension       = @($pref.ExclusionExtension)
        ExclusionIpAddress       = @($pref.ExclusionIpAddress)
        DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
        Detections               = @($threats | Select-Object ThreatID, ProcessName, DomainUser, InitialDetectionTime, LastThreatStatusChangeTime, Resources, ActionSuccess)
        Events                   = $events
    }
}
