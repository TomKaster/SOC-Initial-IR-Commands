# IRTRIAGE-COMPONENT modules/Common.ps1
# Common helpers shared by all collectors.
# Target runtime: Windows PowerShell 5.1 (default on every supported Windows endpoint).
# Keep this file ASCII-only so it parses identically with or without a BOM.

$script:IRHashCache = @{}
$script:IRSigCache  = @{}
$script:IRProcMap   = $null

# Directories that standard users can write to. Binaries that run from here are a common lead.
$script:IRUserWritablePatterns = @(
    '\\Users\\[^\\]+\\AppData\\',
    '\\Users\\[^\\]+\\Downloads\\',
    '\\Users\\[^\\]+\\Desktop\\',
    '\\Users\\Public\\',
    '\\ProgramData\\',
    '\\Windows\\Temp\\',
    '\\Temp\\',
    '\\PerfLogs\\',
    '\\\$Recycle\.Bin\\'
)

function Test-IRElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-IRIsoTime {
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Year -lt 1601) { return $null }
        return $Value.ToUniversalTime().ToString('o')
    }
    return [string]$Value
}

function ConvertTo-IRPlain {
    <#
      Recursively converts arbitrary objects (CIM instances, enums, DateTimes, dictionaries) into
      plain PSCustomObjects/arrays/strings so that ConvertTo-Json in PS 5.1 produces stable output:
      ISO-8601 UTC timestamps instead of "\/Date()\/", enum names instead of integers.
    #>
    [CmdletBinding()]
    param($InputObject, [int]$Depth = 0)

    if ($null -eq $InputObject) { return $null }
    if ($Depth -gt 8) { return [string]$InputObject }

    if ($InputObject -is [datetime]) { return (ConvertTo-IRIsoTime $InputObject) }
    if ($InputObject -is [string])   { return $InputObject }
    if ($InputObject -is [enum])     { return $InputObject.ToString() }
    if ($InputObject -is [bool] -or $InputObject -is [char]) { return $InputObject }
    if ($InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [guid] -or $InputObject -is [version] -or $InputObject -is [ipaddress]) { return $InputObject.ToString() }
    if ($InputObject -is [timespan]) { return $InputObject.ToString() }
    if ($InputObject -is [byte[]])   { return [Convert]::ToBase64String($InputObject) }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $o[[string]$k] = ConvertTo-IRPlain $InputObject[$k] ($Depth + 1) }
        return [pscustomobject]$o
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $InputObject) { [void]$list.Add((ConvertTo-IRPlain $item ($Depth + 1))) }
        return , $list.ToArray()
    }

    $o = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) {
        if ($p.MemberType -notin 'NoteProperty', 'Property', 'AliasProperty', 'ScriptProperty') { continue }
        if ($p.Name -in 'CimClass', 'CimInstanceProperties', 'CimSystemProperties', 'PSComputerName') { continue }
        $v = $null
        try { $v = $p.Value } catch { $v = $null }
        $o[$p.Name] = ConvertTo-IRPlain $v ($Depth + 1)
    }
    return [pscustomobject]$o
}

function Write-IRUtf8File {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Resolve-IRImagePath {
    <# Extracts the executable path from a command line / service ImagePath / task action. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $s = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 1) { $s = $s.Substring(1, $end - 1) }
    } else {
        $m = [regex]::Match($s, '^(.+?\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|scr|cpl|msi))(\s|,|$)', 'IgnoreCase')
        if ($m.Success) { $s = $m.Groups[1].Value }
    }
    # Values like LSA "Security Packages" default to a literal "" - that is not a path.
    $s = $s.Trim().Trim('"').Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $s = $s -replace '^\\\?\?\\', ''
    $s = $s -replace '^(?i)\\SystemRoot\\', ($env:SystemRoot + '\')
    if ($s -match '^(?i)system32\\') { $s = Join-Path $env:SystemRoot $s }
    if ($s -notmatch '\\' -and $s -match '\.\w{2,4}$') {
        if ($s.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -lt 0) {
            $candidate = [System.IO.Path]::Combine($env:SystemRoot, 'System32', $s)
            if (Test-IRFilePath $candidate) { $s = $candidate }
        }
    }
    return $s
}

function Test-IRFilePath {
    <# True only for a syntactically valid, rooted path to an existing file. Never throws or writes errors. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) { return $false }
    try {
        if (-not [System.IO.Path]::IsPathRooted($Path)) { return $false }
        return [System.IO.File]::Exists($Path)
    } catch { return $false }
}

function Test-IRUserWritablePath {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($p in $script:IRUserWritablePatterns) { if ($Path -match $p) { return $true } }
    return $false
}

function Get-IRFileSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Path, [long]$MaxBytes = 104857600)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:IRHashCache.ContainsKey($key)) { return $script:IRHashCache[$key] }
    $hash = $null
    if (-not (Test-IRFilePath $Path)) {
        $script:IRHashCache[$key] = $null
        return $null
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -and $item.Length -le $MaxBytes) {
            $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    } catch { $hash = $null }
    $script:IRHashCache[$key] = $hash
    return $hash
}

function Get-IRSignatureInfo {
    [CmdletBinding()]
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:IRSigCache.ContainsKey($key)) { return $script:IRSigCache[$key] }
    $info = $null
    try {
        if (Test-IRFilePath $Path) {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = $null
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            $info = [pscustomobject]@{
                Status      = [string]$sig.Status
                Signer      = $signer
                IsMicrosoft = [bool]($signer -match 'O=Microsoft Corporation')
            }
        }
    } catch { $info = $null }
    $script:IRSigCache[$key] = $info
    return $info
}

function Get-IRFileFacts {
    <# Hash + (optionally) signature for a path, in a flat shape collectors can merge into records. #>
    [CmdletBinding()]
    param([string]$Path, $Context)
    $facts = [ordered]@{
        Sha256          = $null
        SignatureStatus = $null
        Signer          = $null
        UserWritable    = (Test-IRUserWritablePath $Path)
    }
    if ($Path) {
        $facts.Sha256 = Get-IRFileSha256 $Path
        if ($Context -and $Context.Signatures) {
            $sig = Get-IRSignatureInfo $Path
            if ($sig) { $facts.SignatureStatus = $sig.Status; $facts.Signer = $sig.Signer }
        }
    }
    return $facts
}

function Get-IRProcessMap {
    [CmdletBinding()]
    param()
    if ($null -ne $script:IRProcMap) { return $script:IRProcMap }
    $map = @{}
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) { $map[[int]$p.ProcessId] = $p }
    $script:IRProcMap = $map
    return $map
}

function Test-IRPrivateAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    $a = $Address.ToLowerInvariant()
    if ($a -in '0.0.0.0', '::', '::1', '*') { return $true }
    if ($a.StartsWith('::ffff:')) { $a = $a.Substring(7) }
    if ($a -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|255\.)') { return $true }
    if ($a -match '^(fe80:|fc|fd|ff)') { return $true }
    return $false
}

function Get-IRUserHives {
    <# Loaded user registry hives (HKU\S-1-5-21-*). Running as SYSTEM, HKCU is SYSTEM's own hive, so enumerate HKU. #>
    [CmdletBinding()]
    param()
    $out = @()
    foreach ($k in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -match '^S-1-5-21-[\d-]+$') {
            $name = $k.PSChildName
            try { $name = (New-Object Security.Principal.SecurityIdentifier($k.PSChildName)).Translate([Security.Principal.NTAccount]).Value } catch { $name = $k.PSChildName }
            $out += [pscustomobject]@{ Sid = $k.PSChildName; User = $name; Root = "Registry::HKEY_USERS\$($k.PSChildName)" }
        }
    }
    return $out
}

function Get-IRUserProfileDirs {
    [CmdletBinding()]
    param()
    $root = Join-Path $env:SystemDrive 'Users'
    return @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin 'All Users', 'Default User', 'Default' })
}
