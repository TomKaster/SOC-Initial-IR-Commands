<#
.SYNOPSIS
    Runs Invoke-IRTriage.ps1 on many endpoints through the Microsoft Defender for Endpoint live response API,
    downloads each collection into cases\<CaseId>\ and verifies the zip hash reported by the endpoint.

.DESCRIPTION
    Prerequisites (see docs/EDR-DEPLOY.md):
      * dist\Invoke-IRTriage.ps1 uploaded to the MDE live response library (name given by -ScriptName).
      * Live response + "live response for servers" enabled; unsigned script execution enabled OR the script signed.
      * An Entra app registration with application permissions Machine.Read.All and Machine.LiveResponse
        (admin-consented), or a delegated token for a user with live response rights.

    Flow per machine:  RunScript (collector writes C:\ProgramData\IRTriage\<CaseId>_fleet.zip)  ->  GetFile (that zip)
    -> poll the machine action -> download script output (to read the expected SHA-256) -> download the zip -> verify
    -> write <host>-report.html next to each zip.

    Secrets are only ever taken as SecureString parameters and are never written to disk or logs.

.EXAMPLE
    $secret = Read-Host -AsSecureString 'Client secret'
    .\Invoke-FleetTriage.ps1 -ComputerName ws-0193.corp.example, ws-0201.corp.example -CaseId INC-1042 `
        -TenantId <tenant-guid> -ClientId <app-guid> -ClientSecret $secret -Analyst jdoe

.EXAMPLE
    # Show what would run without calling the API
    .\Invoke-FleetTriage.ps1 -ComputerName ws-0193 -CaseId INC-1042 -AccessToken $tok -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ClientSecret')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory, ParameterSetName = 'Token')]
    [string[]]$ComputerName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$CaseId,

    [ValidateSet('quick', 'standard', 'full')]
    [string]$TriageProfile = 'quick',

    [ValidatePattern('^[^\r\n"]{0,128}$')]
    [string]$Analyst = $env:USERNAME,

    [string]$ScriptName = 'Invoke-IRTriage.ps1',

    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')][string]$TenantId,
    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')][System.Security.SecureString]$ClientSecret,
    [Parameter(Mandatory, ParameterSetName = 'Token')][System.Security.SecureString]$AccessToken,

    [string]$ApiBase = 'https://api.securitycenter.microsoft.com',
    [string]$TokenScope = 'https://api.securitycenter.microsoft.com/.default',
    [string]$OutputDirectory,
    [ValidateRange(1, 25)][int]$MaxConcurrent = 10,
    [ValidateRange(5, 120)][int]$TimeoutMinutes = 30,
    [ValidateRange(5, 300)][int]$PollSeconds = 20
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TriageCommon.ps1')
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function ConvertFrom-IRSecureString {
    param([System.Security.SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-IRMdeToken {
    if ($PSCmdlet.ParameterSetName -eq 'Token') { return (ConvertFrom-IRSecureString $AccessToken) }
    $body = @{
        client_id     = $ClientId
        client_secret = (ConvertFrom-IRSecureString $ClientSecret)
        scope         = $TokenScope
        grant_type    = 'client_credentials'
    }
    $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
    $body.client_secret = $null
    return $resp.access_token
}

function Invoke-IRMdeApi {
    param([string]$Method = 'Get', [string]$Uri, $Body)
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = "Bearer $script:token" }; ContentType = 'application/json' }
            if ($null -ne $Body) { $params.Body = (ConvertTo-Json -InputObject $Body -Depth 8) }
            return Invoke-RestMethod @params
        } catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 401 -and $attempt -le 2 -and $PSCmdlet.ParameterSetName -eq 'ClientSecret') { $script:token = Get-IRMdeToken; continue }
            if ($status -in 429, 500, 502, 503, 504 -and $attempt -le 5) {
                $wait = [math]::Min(60, [math]::Pow(2, $attempt) * 2)
                try { $ra = $_.Exception.Response.Headers['Retry-After']; if ($ra) { $wait = [int]$ra } } catch { $wait = $wait }
                Write-Verbose "HTTP $status from $Uri; retrying in ${wait}s"
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

function Resolve-IRMachine {
    param([string]$Name)
    $q = [uri]::EscapeDataString("computerDnsName eq '$($Name.ToLowerInvariant().Replace("'", "''"))'")
    $r = Invoke-IRMdeApi -Uri "$ApiBase/api/machines?`$filter=$q"
    $m = @($r.value)
    if ($m.Count -eq 0 -and $Name -notmatch '\.') {
        $q = [uri]::EscapeDataString("startswith(computerDnsName,'$($Name.ToLowerInvariant().Replace("'", "''")).')")
        $m = @((Invoke-IRMdeApi -Uri "$ApiBase/api/machines?`$filter=$q").value)
    }
    if ($m.Count -gt 1) { $m = @($m | Sort-Object lastSeen -Descending | Select-Object -First 1) }
    return ($m | Select-Object -First 1)
}

function Get-IRResultLink {
    param([string]$ActionId, [int]$Index)
    return (Invoke-IRMdeApi -Uri "$ApiBase/api/machineactions/$ActionId/GetLiveResponseResultDownloadLink(index=$Index)").value
}

if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Join-Path (Get-Location) 'cases') $CaseId }
$remoteFolder = "C:\ProgramData\IRTriage\${CaseId}_fleet"
$remoteZip = "$remoteFolder.zip"
$scriptArgs = "-CaseId $CaseId -Profile $TriageProfile -OutputPath `"$remoteFolder`" -Force -Analyst `"$Analyst`""

if (-not $PSCmdlet.ShouldProcess(("{0} endpoint(s): {1}" -f $ComputerName.Count, ($ComputerName -join ', ')), "MDE live response: run $ScriptName $scriptArgs; getfile $remoteZip")) { return }

[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$script:token = Get-IRMdeToken

$jobs = New-Object System.Collections.ArrayList
foreach ($name in $ComputerName) {
    $job = [pscustomobject]@{
        ComputerName = $name; MachineId = $null; ActionId = $null; Status = 'Pending'; Error = $null
        ZipPath = $null; ReportPath = $null; ExpectedSha256 = $null; ActualSha256 = $null; HashMatch = $null; Submitted = $null
    }
    try {
        $m = Resolve-IRMachine $name
        if (-not $m) { throw "Machine not found in MDE" }
        $job.MachineId = $m.id
        if ($m.healthStatus -and $m.healthStatus -ne 'Active') { Write-Warning "$name health status is '$($m.healthStatus)'; live response may fail." }
    } catch { $job.Status = 'Failed'; $job.Error = "resolve: $($_.Exception.Message)" }
    [void]$jobs.Add($job)
}

$queue = @($jobs | Where-Object { $_.Status -eq 'Pending' })
$active = New-Object System.Collections.ArrayList
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$i = 0
while (($i -lt $queue.Count -or $active.Count -gt 0) -and (Get-Date) -lt $deadline) {
    while ($i -lt $queue.Count -and $active.Count -lt $MaxConcurrent) {
        $job = $queue[$i]; $i++
        $body = @{
            Commands = @(
                @{ type = 'RunScript'; params = @(@{ key = 'ScriptName'; value = $ScriptName }, @{ key = 'Args'; value = $scriptArgs }) },
                @{ type = 'GetFile'; params = @(@{ key = 'Path'; value = $remoteZip }) }
            )
            Comment = "IRTriage case $CaseId requested by $Analyst"
        }
        try {
            $action = Invoke-IRMdeApi -Method Post -Uri "$ApiBase/api/machines/$($job.MachineId)/runliveresponse" -Body $body
            $job.ActionId = $action.id; $job.Status = 'Submitted'; $job.Submitted = Get-Date
            [void]$active.Add($job)
            Write-Host "[$($job.ComputerName)] submitted action $($action.id)"
        } catch { $job.Status = 'Failed'; $job.Error = "submit: $($_.Exception.Message)" }
    }

    if ($active.Count -gt 0) { Start-Sleep -Seconds $PollSeconds }
    foreach ($job in @($active)) {
        try {
            $a = Invoke-IRMdeApi -Uri "$ApiBase/api/machineactions/$($job.ActionId)"
        } catch { Write-Verbose "[$($job.ComputerName)] poll failed: $($_.Exception.Message)"; continue }
        if ($a.status -in 'Pending', 'InProgress') { continue }
        [void]$active.Remove($job)
        $job.Status = $a.status
        if ($a.status -ne 'Succeeded') {
            $job.Error = "action $($a.status): " + (@($a.commands | ForEach-Object { "$($_.command.type)=$($_.commandStatus) $(@($_.errors) -join ' ')" }) -join '; ')
            Write-Warning "[$($job.ComputerName)] $($job.Error)"
            continue
        }
        try {
            # Command 0: RunScript output. The collector's last line is "IRTRIAGE_RESULT {json}".
            $scriptResult = Invoke-RestMethod -Uri (Get-IRResultLink $job.ActionId 0)
            $line = @(([string]$scriptResult.script_output) -split "`r?`n" | Where-Object { $_ -like 'IRTRIAGE_RESULT *' }) | Select-Object -Last 1
            if ($line) { $job.ExpectedSha256 = (ConvertFrom-Json $line.Substring(16)).zipSha256 }
            [System.IO.File]::WriteAllText((Join-Path $OutputDirectory "$($job.ComputerName)-script-output.txt"), [string]$scriptResult.script_output)

            # Command 1: GetFile. Download link is a short-lived SAS URL; do not send the bearer token to it.
            $zip = Join-Path $OutputDirectory "$($job.ComputerName).zip"
            Invoke-WebRequest -Uri (Get-IRResultLink $job.ActionId 1) -OutFile $zip -UseBasicParsing
            $job.ActualSha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash

            # Some MDE tenants deliver GetFile content gzip-wrapped; unwrap if the raw hash does not match.
            if ($job.ExpectedSha256 -and $job.ActualSha256 -ne $job.ExpectedSha256) {
                $bytes = [System.IO.File]::ReadAllBytes($zip)
                if ($bytes.Length -gt 2 -and $bytes[0] -eq 0x1f -and $bytes[1] -eq 0x8b) {
                    $in = New-Object System.IO.MemoryStream(, $bytes)
                    $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
                    $outStream = [System.IO.File]::Create($zip)
                    try { $gz.CopyTo($outStream) } finally { $outStream.Dispose(); $gz.Dispose(); $in.Dispose() }
                    $job.ActualSha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
                }
            }
            $job.ZipPath = $zip
            $job.HashMatch = ($job.ExpectedSha256 -and $job.ExpectedSha256 -eq $job.ActualSha256)
            if ($job.ExpectedSha256) {
                [System.IO.File]::WriteAllText("$zip.sha256", ("{0}  {1}`n" -f $job.ExpectedSha256, (Split-Path -Leaf $zip)))
            }
            $msg = "hash MISMATCH"; if ($job.HashMatch) { $msg = 'hash verified' }; if (-not $job.ExpectedSha256) { $msg = 'no expected hash in script output' }
            Write-Host "[$($job.ComputerName)] downloaded $zip ($msg)"
            try {
                $tri = Import-IRTriage -Path $zip
                $job.ReportPath = New-IRTriageReport -Triage $tri -OutFile (Join-Path $OutputDirectory "$($job.ComputerName)-report.html") -GeneratedBy 'Invoke-FleetTriage.ps1'
                Write-Host "[$($job.ComputerName)] report $($job.ReportPath)"
            } catch { Write-Warning "[$($job.ComputerName)] report failed: $($_.Exception.Message)" }
        } catch { $job.Status = 'DownloadFailed'; $job.Error = "download: $($_.Exception.Message)"; Write-Warning "[$($job.ComputerName)] $($job.Error)" }
    }
}
foreach ($job in @($jobs | Where-Object { $_.Status -in 'Pending', 'Submitted' })) { $job.Status = 'TimedOut'; $job.Error = "no result within $TimeoutMinutes minutes" }

$script:token = $null
$summaryPath = Join-Path $OutputDirectory 'fleet-summary.csv'
$jobs | Select-Object ComputerName, MachineId, ActionId, Status, HashMatch, ExpectedSha256, ActualSha256, ZipPath, ReportPath, Error |
    Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
Write-Host "Summary: $summaryPath"
$jobs
