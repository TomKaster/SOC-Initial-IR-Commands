<#
.SYNOPSIS
    Renders a triage collection as a single self-contained HTML report to attach to the incident ticket.

.DESCRIPTION
    Includes collection metadata and integrity status, collector status, heuristic leads (high / review / info),
    key live-state tables, and optionally a baseline diff and IOC hits. The report has no external resources,
    so it can be opened offline or inside an isolated analysis VM.

.EXAMPLE
    .\ConvertTo-TriageReport.ps1 -Path .\cases\INC-1042\WS-0193.zip

.EXAMPLE
    .\ConvertTo-TriageReport.ps1 -Path host.zip -BaselinePath gold.zip -IocFile iocs.csv -OutFile report.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutFile,
    [string]$BaselinePath,
    [string]$IocFile,
    [ValidateSet('high', 'review', 'info')][string]$MinimumSeverity = 'info'
)
. (Join-Path $PSScriptRoot 'TriageCommon.ps1')

function ConvertTo-IRHtml { param($Value) if ($null -eq $Value) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function ConvertTo-IRHtmlTable {
    param([object[]]$Rows, [string[]]$Columns, [string]$Empty = 'None.')
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class='muted'>$(ConvertTo-IRHtml $Empty)</p>" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='scroll'><table><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(ConvertTo-IRHtml $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        $cls = ''
        if ($r.PSObject.Properties['Severity']) { $cls = " class='sev-$($r.Severity)'" }
        [void]$sb.Append("<tr$cls>")
        foreach ($c in $Columns) { [void]$sb.Append("<td>$(ConvertTo-IRHtml $r.$c)</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

$tri = Import-IRTriage -Path $Path
$m = $tri.Manifest
if (-not $OutFile) {
    $base = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($tri.Path), [System.IO.Path]::GetFileNameWithoutExtension($tri.Path))
    $OutFile = "$base-report.html"
}

$sevRank = @{ high = 0; review = 1; info = 2 }
$leads = @(Get-IRTriageLeads -Triage $tri | Where-Object { $sevRank[$_.Severity] -le $sevRank[$MinimumSeverity] })
$counts = @{ high = @($leads | Where-Object Severity -eq 'high').Count; review = @($leads | Where-Object Severity -eq 'review').Count; info = @($leads | Where-Object Severity -eq 'info').Count }

$diff = $null
if ($BaselinePath) { $diff = @(& (Join-Path $PSScriptRoot 'Compare-Triage.ps1') -Baseline $BaselinePath -Suspect $Path) }
$iocHits = $null
if ($IocFile) { $iocHits = @(& (Join-Path $PSScriptRoot 'Find-IOC.ps1') -Path $tri.Path -IocFile $IocFile 6>$null) }

$conns = Get-IRRecords $tri 'network_connections'
$external = @($conns | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Established' -and $_.IsExternal } | Sort-Object ProcessName)
$listen = @($conns | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -notmatch '^(127\.|::1$)' } | Sort-Object Protocol, LocalPort)

$integrityHtml = "<span class='ok'>VERIFIED</span> - all $(@($m.files).Count) files match manifest hashes"
if ($tri.Integrity.Zip -and $tri.Integrity.Zip.Match) { $integrityHtml += '; zip matches .sha256' }
if (-not $tri.Integrity.Valid) {
    $integrityHtml = "<span class='bad'>FAILED</span> - " + (ConvertTo-IRHtml (($tri.Integrity.Problems | ForEach-Object { "$($_.File): $($_.Problem)" }) -join '; '))
    if ($tri.Integrity.Zip -and -not $tri.Integrity.Zip.Match) { $integrityHtml += ' zip hash does not match .sha256' }
}

$meta = @(
    @('Case', $m.case.caseId), @('Host', "$($m.host.computerName) ($($m.host.domain))"), @('OS', "$($m.host.osCaption) $($m.host.osVersion)"),
    @('Profile', $m.run.profile), @('Collected (UTC)', "$($m.run.startUtc) -> $($m.run.endUtc) ($($m.run.durationSeconds)s)"),
    @('Requested by', $m.case.analyst), @('Executed as', "$($m.case.executedAs) (elevated: $($m.case.elevated))"),
    @('Tool', "IRTriage $($m.tool.version) [$($m.tool.build)] script SHA256 $($m.tool.scriptSha256)")
)
$metaHtml = ($meta | ForEach-Object { "<tr><th>$(ConvertTo-IRHtml $_[0])</th><td>$(ConvertTo-IRHtml $_[1])</td></tr>" }) -join ''

$collectorRows = @($m.collectors | ForEach-Object { [pscustomobject]@{ Collector = $_.name; Status = $_.status; Records = $_.records; 'ms' = $_.durationMs; Note = (($_.error, $_.note) -join ' ').Trim() } })

$sections = New-Object System.Text.StringBuilder
[void]$sections.Append("<h2>Leads <small>$($counts.high) high &middot; $($counts.review) review &middot; $($counts.info) info</small></h2>")
[void]$sections.Append("<p class='muted'>Heuristic leads for analyst review, not verdicts. Validate against baseline, ticket context and threat intel.</p>")
[void]$sections.Append((ConvertTo-IRHtmlTable $leads @('Severity', 'Category', 'Title', 'Detail') 'No leads.'))

if ($null -ne $iocHits) {
    [void]$sections.Append("<h2>IOC hits <small>$($iocHits.Count)</small></h2>")
    [void]$sections.Append((ConvertTo-IRHtmlTable $iocHits @('IndicatorType', 'Indicator', 'Collector', 'Field', 'Value', 'Description') 'No indicator hits.'))
}
if ($null -ne $diff) {
    $added = @($diff | Where-Object Change -eq 'Added')
    [void]$sections.Append("<h2>Baseline diff <small>$($added.Count) added &middot; $(@($diff | Where-Object Change -eq 'Modified').Count) modified &middot; $(@($diff | Where-Object Change -eq 'Removed').Count) removed</small></h2>")
    [void]$sections.Append("<p class='muted'>Baseline: $(ConvertTo-IRHtml $BaselinePath)</p>")
    [void]$sections.Append((ConvertTo-IRHtmlTable @($diff | Sort-Object @{ Expression = { @{ Added = 0; Modified = 1; Removed = 2 }[$_.Change] } }, Category) @('Change', 'Category', 'Key', 'Suspect', 'Baseline') 'No differences.'))
}

[void]$sections.Append("<h2>External TCP connections <small>$($external.Count)</small></h2>")
[void]$sections.Append((ConvertTo-IRHtmlTable $external @('RemoteAddress', 'RemotePort', 'LocalPort', 'ProcessName', 'OwningProcess', 'ProcessPath', 'ProcessSha256')))
[void]$sections.Append("<h2>Listening ports <small>$($listen.Count)</small></h2>")
[void]$sections.Append((ConvertTo-IRHtmlTable $listen @('Protocol', 'LocalAddress', 'LocalPort', 'ProcessName', 'OwningProcess', 'ProcessPath')))
[void]$sections.Append('<h2>Logged-on users</h2>')
[void]$sections.Append((ConvertTo-IRHtmlTable @(Get-IRRecords $tri 'logged_on_users') @('Source', 'UserName', 'SessionName', 'SessionId', 'State', 'LogonTime')))
[void]$sections.Append('<h2>Local administrators</h2>')
[void]$sections.Append((ConvertTo-IRHtmlTable @(Get-IRRecords $tri 'local_admins') @('Name', 'ObjectClass', 'PrincipalSource', 'SID')))
[void]$sections.Append('<h2>Inbound SMB sessions</h2>')
[void]$sections.Append((ConvertTo-IRHtmlTable @(Get-IRRecords $tri 'smb_sessions') @('ClientComputerName', 'ClientUserName', 'NumOpens', 'SecondsExists')))
[void]$sections.Append('<h2>Collector status</h2>')
[void]$sections.Append((ConvertTo-IRHtmlTable $collectorRows @('Collector', 'Status', 'Records', 'ms', 'Note')))
[void]$sections.Append('<h2>Evidence files</h2>')
[void]$sections.Append((ConvertTo-IRHtmlTable @($m.files | ForEach-Object { [pscustomobject]@{ File = $_.path; Bytes = $_.bytes; SHA256 = $_.sha256 } }) @('File', 'Bytes', 'SHA256')))

$title = "IR triage - $($m.case.caseId) - $($m.host.computerName)"
$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-IRHtml $title)</title>
<style>
:root { --bg:#fff; --fg:#1b1f24; --muted:#5b6570; --line:#d9dee3; --head:#f3f5f7; --high:#fde8e8; --review:#fff6d6; --ok:#137333; --bad:#b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg:#14171a; --fg:#e6e9ec; --muted:#9aa4ae; --line:#2c3238; --head:#1d2125; --high:#4a1f1f; --review:#40391a; --ok:#6fd08c; --bad:#ff8a80; } }
body { background:var(--bg); color:var(--fg); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; margin:0; padding:24px 16px; }
main { max-width:1200px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 12px; } h2 { font-size:17px; margin:28px 0 8px; border-bottom:1px solid var(--line); padding-bottom:4px; }
h2 small { color:var(--muted); font-weight:normal; font-size:13px; margin-left:8px; }
.muted { color:var(--muted); } .ok { color:var(--ok); font-weight:600; } .bad { color:var(--bad); font-weight:600; }
.scroll { overflow-x:auto; } table { border-collapse:collapse; width:100%; font-size:12.5px; }
th, td { border:1px solid var(--line); padding:4px 6px; text-align:left; vertical-align:top; word-break:break-word; }
thead th, table.meta th { background:var(--head); } table.meta th { width:160px; white-space:nowrap; }
tr.sev-high td { background:var(--high); } tr.sev-review td { background:var(--review); }
.badges span { display:inline-block; padding:2px 10px; border-radius:12px; margin-right:6px; border:1px solid var(--line); }
</style></head><body><main>
<h1>$(ConvertTo-IRHtml $title)</h1>
<p class="badges"><span>High: $($counts.high)</span><span>Review: $($counts.review)</span><span>Info: $($counts.info)</span></p>
<table class="meta">$metaHtml<tr><th>Integrity</th><td>$integrityHtml</td></tr></table>
$($sections.ToString())
<p class="muted">Generated $(ConvertTo-IRHtml ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')))Z by ConvertTo-TriageReport.ps1 from $(ConvertTo-IRHtml (Split-Path -Leaf $tri.Path)).</p>
</main></body></html>
"@
[System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Report written: $OutFile  ($($counts.high) high, $($counts.review) review, $($counts.info) info)"
Get-Item -LiteralPath $OutFile
