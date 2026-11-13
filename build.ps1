<#
.SYNOPSIS
    Builds the single-file collector for upload to an EDR live-response script library.

.DESCRIPTION
    EDR live response (MDE, CrowdStrike RTR, SentinelOne RemoteOps) uploads and runs one script file.
    This inlines collector\modules\*.ps1, shared\*.ps1 and profiles\*.json into collector\Invoke-IRTriage.ps1,
    stamps the build (version + git commit), verifies the result parses, optionally Authenticode-signs
    it, and writes dist\Invoke-IRTriage.ps1 plus a .sha256 file.

.PARAMETER CertificateThumbprint
    Thumbprint of a code-signing certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My.
    Required if endpoints enforce AllSigned or your EDR only runs signed scripts.

.EXAMPLE
    .\build.ps1
.EXAMPLE
    .\build.ps1 -CertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist'),
    [string]$CertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'

$src = Join-Path $PSScriptRoot 'collector\Invoke-IRTriage.ps1'
$moduleDir = Join-Path $PSScriptRoot 'collector\modules'
$sharedDir = Join-Path $PSScriptRoot 'shared'
$profileDir = Join-Path $PSScriptRoot 'profiles'
$text = [System.IO.File]::ReadAllText($src)

function Set-IRRegion {
    param([string]$Text, [string]$Name, [string]$Replacement)
    $pattern = "(?s)#region BUILD:$Name\r?\n.*?#endregion BUILD:$Name"
    if ($Text -notmatch $pattern) { throw "Region BUILD:$Name not found in $src" }
    $body = "#region BUILD:$Name (inlined by build.ps1)`r`n$Replacement`r`n#endregion BUILD:$Name"
    return [regex]::Replace($Text, $pattern, { param($m) $body }.GetNewClosure())
}

# Modules then shared report code, in the same order the source script dot-sources them.
$sb = New-Object System.Text.StringBuilder
$sources = @(Get-ChildItem -Path $moduleDir -Filter '*.ps1' | Sort-Object Name) + @(Get-ChildItem -Path $sharedDir -Filter '*.ps1' | Sort-Object Name)
foreach ($m in $sources) {
    [void]$sb.AppendLine("# ----- $($m.Directory.Name)/$($m.Name) -----")
    [void]$sb.AppendLine([System.IO.File]::ReadAllText($m.FullName).TrimEnd())
}
$text = Set-IRRegion -Text $text -Name 'MODULES' -Replacement $sb.ToString().TrimEnd()

# Profiles as single-quoted here-strings (validated JSON first).
$pb = New-Object System.Text.StringBuilder
[void]$pb.AppendLine('$script:IRProfileJson = @{}')
foreach ($p in @(Get-ChildItem -Path $profileDir -Filter '*.json' | Sort-Object Name)) {
    $json = [System.IO.File]::ReadAllText($p.FullName).Trim()
    $null = ConvertFrom-Json -InputObject $json
    if ($json -match "(?m)^'@") { throw "Profile $($p.Name) contains a line starting with '@ which would break the here-string." }
    [void]$pb.AppendLine("`$script:IRProfileJson['$($p.BaseName)'] = @'")
    [void]$pb.AppendLine($json)
    [void]$pb.AppendLine("'@")
}
$text = Set-IRRegion -Text $text -Name 'PROFILES' -Replacement $pb.ToString().TrimEnd()

# Build stamp.
$commit = 'unknown'
try {
    $c = (& git -C $PSScriptRoot rev-parse --short HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $c) { $commit = $c.Trim() }
    $dirty = (& git -C $PSScriptRoot status --porcelain 2>$null)
    if ($dirty) { $commit = "$commit-dirty" }
} catch { $commit = 'unknown' }
$buildInfo = "commit=$commit built=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
$text = $text.Replace("`$script:IRBuildInfo = 'source'", "`$script:IRBuildInfo = '$buildInfo'")

# Normalise line endings to CRLF (Authenticode signatures are line-ending sensitive).
$text = ($text -replace "`r`n", "`n") -replace "`n", "`r`n"

# Must parse cleanly.
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) { throw "Built script has parse errors:`n$($errors | Out-String)" }

if (-not (Test-Path -LiteralPath $OutputDirectory)) { [void](New-Item -ItemType Directory -Path $OutputDirectory) }
$out = Join-Path $OutputDirectory 'Invoke-IRTriage.ps1'
# UTF-8 with BOM: Windows PowerShell 5.1 reads BOM-less files as ANSI.
[System.IO.File]::WriteAllText($out, $text, (New-Object System.Text.UTF8Encoding($true)))

if ($CertificateThumbprint) {
    $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint", "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue |
        Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $cert) { throw "Code-signing certificate $CertificateThumbprint with a private key was not found." }
    $sig = Set-AuthenticodeSignature -FilePath $out -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($sig.Status -ne 'Valid') { throw "Signing failed: $($sig.Status) $($sig.StatusMessage)" }
    Write-Host "Signed by $($cert.Subject)"
}

$hash = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash
[System.IO.File]::WriteAllText("$out.sha256", ("{0}  Invoke-IRTriage.ps1`n" -f $hash), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Built $out"
Write-Host "  $buildInfo"
Write-Host "  SHA256 $hash"
