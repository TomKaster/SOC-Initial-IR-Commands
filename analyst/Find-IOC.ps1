<#
.SYNOPSIS
    Searches one or more triage collections for indicators of compromise.

.DESCRIPTION
    Every string value in every collector's output is checked, so new collectors are covered automatically.
    Indicator types are auto-detected:
      ip      - exact address match (also inside command lines / URLs, with boundaries)
      hash    - MD5/SHA1/SHA256, case-insensitive exact match
      domain  - the domain or any subdomain of it
      string  - case-insensitive substring (file names, mutex names, user names, ...)

    IOC file formats:
      .csv  with columns  Type,Value[,Description]   (Type may be blank to auto-detect)
      .txt  one indicator per line, '#' comments allowed

.EXAMPLE
    .\Find-IOC.ps1 -Path .\cases\INC-1042\*.zip -IocFile .\intel\inc-1042-iocs.csv

.EXAMPLE
    .\Find-IOC.ps1 -Path host.zip -Indicator 203.0.113.50, evil-cdn.example, 'svchost32.exe'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Path,
    [string]$IocFile,
    [string[]]$Indicator,
    [string]$OutCsv
)
. (Join-Path $PSScriptRoot 'TriageCommon.ps1')

function Get-IRIndicatorType {
    param([string]$Value)
    $v = $Value.Trim()
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($v, [ref]$ip) -and ($v -match '^\d{1,3}(\.\d{1,3}){3}$' -or $v -match ':')) { return 'ip' }
    if ($v -match '^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$') { return 'hash' }
    if ($v -match '^(?=.{4,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$' -and $v -notmatch '(?i)\.(exe|dll|ps1|bat|cmd|vbs|js|lnk|sys|scr|hta|msi|zip|rar|7z|iso|txt|log)$') { return 'domain' }
    return 'string'
}

function New-IRMatcher {
    param([string]$Type, [string]$Value)
    $v = $Value.Trim()
    switch ($Type) {
        'ip'     {
            if ($v -match ':') { return New-Object regex ('(?<![\w:])' + [regex]::Escape($v) + '(?![\w:])'), 'IgnoreCase' }
            return New-Object regex ('(?<![\w.])' + [regex]::Escape($v) + '(?!\w|\.\d)'), 'IgnoreCase'
        }
        'hash'   { return New-Object regex ('^' + [regex]::Escape($v) + '$'), 'IgnoreCase' }
        'domain' { return New-Object regex ('(?<![\w-])' + [regex]::Escape($v.TrimStart('.')) + '(?![\w-])'), 'IgnoreCase' }
        default  { return New-Object regex ([regex]::Escape($v)), 'IgnoreCase' }
    }
}

# ---- Load indicators -----------------------------------------------------------------------
$iocs = New-Object System.Collections.ArrayList
if ($IocFile) {
    if ($IocFile -match '\.csv$') {
        foreach ($row in @(Import-Csv -LiteralPath $IocFile)) {
            if (-not $row.Value) { continue }
            $type = $row.Type
            if (-not $type) { $type = Get-IRIndicatorType $row.Value }
            [void]$iocs.Add([pscustomobject]@{ Type = $type.ToLowerInvariant(); Value = $row.Value.Trim(); Description = $row.Description })
        }
    } else {
        foreach ($line in [System.IO.File]::ReadAllLines((Resolve-Path -LiteralPath $IocFile).ProviderPath)) {
            $t = ($line -split '#', 2)[0].Trim()
            if ($t) { [void]$iocs.Add([pscustomobject]@{ Type = (Get-IRIndicatorType $t); Value = $t; Description = $null }) }
        }
    }
}
foreach ($i in @($Indicator)) { if ($i) { [void]$iocs.Add([pscustomobject]@{ Type = (Get-IRIndicatorType $i); Value = $i.Trim(); Description = $null }) } }
if ($iocs.Count -eq 0) { throw 'No indicators supplied. Use -IocFile and/or -Indicator.' }
foreach ($i in $iocs) { $i | Add-Member -NotePropertyName Matcher -NotePropertyValue (New-IRMatcher $i.Type $i.Value) }
Write-Verbose ("Loaded {0} indicators ({1})" -f $iocs.Count, (($iocs | Group-Object Type | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '))

# ---- Walk every string in every record --------------------------------------------------------
function Get-IRStringLeaves {
    param($Node, [string]$Prefix, [int]$Depth = 0)
    if ($null -eq $Node -or $Depth -gt 10) { return }
    if ($Node -is [string]) { if ($Node.Length -gt 0) { [pscustomobject]@{ Field = $Prefix; Value = $Node } }; return }
    if ($Node -is [ValueType]) { return }
    if ($Node -is [System.Collections.IEnumerable]) {
        $n = 0
        foreach ($x in $Node) { Get-IRStringLeaves $x "$Prefix[$n]" ($Depth + 1); $n++ }
        return
    }
    foreach ($p in $Node.PSObject.Properties) {
        $name = $p.Name
        if ($Prefix) { $name = "$Prefix.$($p.Name)" }
        Get-IRStringLeaves $p.Value $name ($Depth + 1)
    }
}

$targets = @()
foreach ($p in $Path) { $targets += @(Get-ChildItem -Path $p -ErrorAction Stop | ForEach-Object { $_.FullName }) }

$hits = New-Object System.Collections.ArrayList
foreach ($t in $targets) {
    $tri = Import-IRTriage -Path $t
    if (-not $tri.Integrity.Valid) { Write-Warning "Integrity check FAILED for $t" }
    foreach ($collector in ($tri.Data.Keys | Sort-Object)) {
        $i = 0
        foreach ($rec in $tri.Data[$collector]) {
            foreach ($leaf in @(Get-IRStringLeaves $rec '')) {
                foreach ($ioc in $iocs) {
                    if ($ioc.Matcher.IsMatch($leaf.Value)) {
                        $val = $leaf.Value
                        if ($val.Length -gt 300) { $val = $val.Substring(0, 300) + '...' }
                        [void]$hits.Add([pscustomobject]@{
                            Host          = $tri.Host
                            CaseId        = $tri.Manifest.case.caseId
                            Collector     = $collector
                            RecordIndex   = $i
                            Field         = $leaf.Field
                            Value         = $val
                            IndicatorType = $ioc.Type
                            Indicator     = $ioc.Value
                            Description   = $ioc.Description
                            Source        = $t
                        })
                    }
                }
            }
            $i++
        }
    }
}

if ($OutCsv) { $hits | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8 }
if ($hits.Count -eq 0) { Write-Host "No indicator hits across $($targets.Count) collection(s)." }
$hits
