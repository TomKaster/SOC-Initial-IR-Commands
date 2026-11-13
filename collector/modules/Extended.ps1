# IRTRIAGE-COMPONENT modules/Extended.ps1
# Deeper (slower) artifacts used by the "full" profile.

function Get-IRPrefetch {
    [CmdletBinding()]
    param($Context)
    $dir = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path -LiteralPath $dir)) { $Context.CollectorNote = 'Prefetch directory not present (disabled or server SKU)'; return }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.pf' -File -Force -ErrorAction Stop)) {
        $exe = $null
        if ($f.BaseName -match '^(?<exe>.+)-[0-9A-F]{8}$') { $exe = $Matches['exe'] }
        [pscustomobject]@{
            FileName         = $f.Name
            Executable       = $exe
            CreationTimeUtc  = $f.CreationTimeUtc
            LastWriteTimeUtc = $f.LastWriteTimeUtc
            Length           = $f.Length
        }
    }
}

function Get-IRRecentExecutables {
    [CmdletBinding()]
    param($Context)
    $extensions = @('.exe', '.dll', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.msi', '.lnk', '.jar', '.iso', '.img')
    $cutoff = (Get-Date).AddDays(-1 * $Context.RecentFileDays)
    $roots = @(
        (Join-Path $env:SystemDrive 'Users\Public'),
        $env:ProgramData,
        (Join-Path $env:SystemRoot 'Temp'),
        (Join-Path $env:SystemDrive 'PerfLogs')
    )
    foreach ($u in Get-IRUserProfileDirs) {
        $roots += (Join-Path $u.FullName 'AppData')
        $roots += (Join-Path $u.FullName 'Downloads')
        $roots += (Join-Path $u.FullName 'Desktop')
        $roots += (Join-Path $u.FullName 'Documents')
    }
    $count = 0
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        $files = Get-ChildItem -LiteralPath $r -Recurse -Depth $Context.MaxDepth -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff -and $extensions -contains $_.Extension.ToLowerInvariant() }
        foreach ($f in $files) {
            if ($count -ge $Context.MaxFiles) {
                $Context.CollectorNote = "truncated at $($Context.MaxFiles) files"
                return
            }
            $count++
            $facts = Get-IRFileFacts -Path $f.FullName -Context $Context
            [pscustomobject]@{
                Path             = $f.FullName
                Length           = $f.Length
                CreationTimeUtc  = $f.CreationTimeUtc
                LastWriteTimeUtc = $f.LastWriteTimeUtc
                Sha256           = $facts.Sha256
                SignatureStatus  = $facts.SignatureStatus
                Signer           = $facts.Signer
            }
        }
    }
}

function Get-IRBrowserExtensions {
    [CmdletBinding()]
    param($Context)
    $chromium = @(
        @{ Browser = 'Chrome'; Rel = 'AppData\Local\Google\Chrome\User Data' },
        @{ Browser = 'Edge';   Rel = 'AppData\Local\Microsoft\Edge\User Data' },
        @{ Browser = 'Brave';  Rel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
    )
    foreach ($u in Get-IRUserProfileDirs) {
        foreach ($b in $chromium) {
            $root = Join-Path $u.FullName $b.Rel
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($manifest in @(Get-ChildItem -Path (Join-Path $root '*\Extensions\*\*\manifest.json') -File -Force -ErrorAction SilentlyContinue)) {
                $m = $null
                try { $m = Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $m = $null }
                $verDir = $manifest.Directory
                $idDir = $verDir.Parent
                $profileDir = $idDir.Parent.Parent
                [pscustomobject]@{
                    User        = $u.Name
                    Browser     = $b.Browser
                    Profile     = $profileDir.Name
                    ExtensionId = $idDir.Name
                    Name        = $m.name
                    Version     = $m.version
                    Permissions = (@($m.permissions) -join ',')
                    InstalledUtc = $verDir.CreationTimeUtc
                }
            }
        }
        $ff = Join-Path $u.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
        foreach ($ext in @(Get-ChildItem -Path (Join-Path $ff '*\extensions.json') -File -Force -ErrorAction SilentlyContinue)) {
            $j = $null
            try { $j = Get-Content -LiteralPath $ext.FullName -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $j = $null }
            foreach ($a in @($j.addons)) {
                if (-not $a -or $a.location -eq 'app-builtin') { continue }
                [pscustomobject]@{
                    User        = $u.Name
                    Browser     = 'Firefox'
                    Profile     = $ext.Directory.Name
                    ExtensionId = $a.id
                    Name        = $a.defaultLocale.name
                    Version     = $a.version
                    Permissions = (@($a.userPermissions.permissions) -join ',')
                    InstalledUtc = $null
                }
            }
        }
    }
}

function Get-IRUsbDevices {
    [CmdletBinding()]
    param($Context)
    $root = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    foreach ($dev in @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
        foreach ($inst in @(Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $inst.PSPath -ErrorAction SilentlyContinue
            [pscustomobject]@{
                DeviceClass  = $dev.PSChildName
                SerialNumber = $inst.PSChildName
                FriendlyName = $p.FriendlyName
                Mfg          = $p.Mfg
            }
        }
    }
}
