<#
.SYNOPSIS
    Re-renders the HTML report for a triage collection, optionally adding a baseline diff and IOC hits.

.DESCRIPTION
    Every collection already contains report.html, built by the collector on the endpoint. Use this script when you
    want the extra sections that need analyst-side inputs (a baseline collection, an IOC list), or to rebuild the
    report with newer lead heuristics. The report is one self-contained HTML file with no external resources.

    By default the report is written next to the input as <name>-report.html.

.EXAMPLE
    .\ConvertTo-TriageReport.ps1 -Path .\cases\INC-1042\WS-0193.zip -Open

.EXAMPLE
    .\ConvertTo-TriageReport.ps1 -Path host.zip -BaselinePath gold.zip -IocFile iocs.csv -OutFile report.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutFile,
    [string]$BaselinePath,
    [string]$IocFile,
    [ValidateSet('high', 'review', 'info')][string]$MinimumSeverity = 'info',
    [switch]$Open
)
. (Join-Path $PSScriptRoot 'TriageCommon.ps1')

$tri = Import-IRTriage -Path $Path
if (-not $OutFile) {
    $base = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($tri.Path), [System.IO.Path]::GetFileNameWithoutExtension($tri.Path))
    $OutFile = "$base-report.html"
}
$OutFile = [System.IO.Path]::GetFullPath($OutFile)

$params = @{ Triage = $tri; OutFile = $OutFile; MinimumSeverity = $MinimumSeverity; GeneratedBy = 'ConvertTo-TriageReport.ps1' }
if ($BaselinePath) {
    $params.Diff = @(& (Join-Path $PSScriptRoot 'Compare-Triage.ps1') -Baseline $BaselinePath -Suspect $Path)
    $params.BaselineName = Split-Path -Leaf $BaselinePath
}
if ($IocFile) {
    $params.IocHits = @(& (Join-Path $PSScriptRoot 'Find-IOC.ps1') -Path $tri.Path -IocFile $IocFile 6>$null)
    $params.IncludeIocSection = $true
}
$null = New-IRTriageReport @params

Write-Host "Report written: $OutFile"
if ($Open) { Invoke-Item -LiteralPath $OutFile }
Get-Item -LiteralPath $OutFile
