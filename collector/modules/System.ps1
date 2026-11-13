# IRTRIAGE-COMPONENT modules/System.ps1
# Host identity and installed software.

function Get-IRSystemInfo {
    [CmdletBinding()]
    param($Context)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $tz = $null
    try { $tz = (Get-TimeZone -ErrorAction Stop).Id } catch { $tz = [System.TimeZoneInfo]::Local.Id }

    $uptime = $null
    if ($os -and $os.LastBootUpTime) { $uptime = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2) }

    $hotfixes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
        Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue |
        Select-Object -First 15 -Property HotFixID, Description, InstalledOn)

    [pscustomobject]@{
        ComputerName      = $env:COMPUTERNAME
        Domain            = $cs.Domain
        PartOfDomain      = $cs.PartOfDomain
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        SerialNumber      = $bios.SerialNumber
        OSCaption         = $os.Caption
        OSVersion         = $os.Version
        OSBuild           = $os.BuildNumber
        OSArchitecture    = $os.OSArchitecture
        InstallDate       = $os.InstallDate
        LastBootUpTime    = $os.LastBootUpTime
        UptimeHours       = $uptime
        TimeZone          = $tz
        LocalTime         = (Get-Date).ToString('o')
        ConsoleUser       = $cs.UserName
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        RecentHotfixes    = $hotfixes
    }
}

function Get-IRInstalledSoftware {
    [CmdletBinding()]
    param($Context)
    $roots = @(
        @{ Scope = 'Machine';      Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Scope = 'Machine-WOW64'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    foreach ($h in Get-IRUserHives) {
        $roots += @{ Scope = "User:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    }
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem -Path $r.Path -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not $p.DisplayName) { continue }
            # Uninstall keys store InstallDate as yyyyMMdd; show it as yyyy-MM-dd like the Store apps.
            $installDate = [string]$p.InstallDate
            if ($installDate -match '^(\d{4})(\d{2})(\d{2})$') { $installDate = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
            [pscustomobject]@{
                Type            = 'Desktop'
                Scope           = $r.Scope
                DisplayName     = $p.DisplayName
                DisplayVersion  = $p.DisplayVersion
                Publisher       = $p.Publisher
                InstallDate     = $installDate
                InstallLocation = $p.InstallLocation
                UninstallString = $p.UninstallString
                KeyName         = $k.PSChildName
                SignatureKind   = $null
            }
        }
    }
    Get-IRStoreApps -Context $Context
}

function Get-IRStoreApps {
    <#
      Microsoft Store / MSIX (AppX) packages, one record per package and user. Frameworks, resource packages and
      inbox Windows apps (SignatureKind System) are left out to keep the list readable; the count is noted.
      SignatureKind Developer/None means sideloaded, a known malware delivery route (malicious MSIX installers).
      -AllUsers needs elevation; otherwise only the current user's packages are listed.
    #>
    [CmdletBinding()]
    param($Context)
    if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
        $Context.CollectorNote = (("{0} Store apps: Appx module not available" -f $Context.CollectorNote)).Trim()
        return
    }
    $pkgs = @()
    try {
        if ($Context.Elevated) { $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction Stop) }
        else { $pkgs = @(Get-AppxPackage -ErrorAction Stop) }
    } catch {
        $Context.CollectorNote = (("{0} Store apps: {1}" -f $Context.CollectorNote, $_.Exception.Message)).Trim()
        return
    }
    $skipped = 0
    foreach ($p in $pkgs) {
        if ($p.IsFramework -or $p.IsResourcePackage -or [string]$p.SignatureKind -eq 'System') { $skipped++; continue }
        $users = @()
        if ($Context.Elevated -and $p.PackageUserInformation) {
            $users = @($p.PackageUserInformation | Where-Object { [string]$_.InstallState -eq 'Installed' } | ForEach-Object {
                $n = $_.UserSecurityId.Username
                if (-not $n) { $n = $_.UserSecurityId.Sid }
                [string]$n
            })
        }
        if (-not $Context.Elevated) { $users = @("$env:USERDOMAIN\$env:USERNAME") }
        elseif (-not $users) { $users = @('(staged, no user)') }
        $publisher = [string]$p.Publisher
        if ($publisher -match '(?:^|,\s*)CN=("[^"]+"|[^,]+)') { $publisher = $Matches[1].Trim('"') }
        $installed = $null
        try { if ($p.InstallLocation) { $installed = (Get-Item -LiteralPath $p.InstallLocation -Force -ErrorAction Stop).CreationTimeUtc.ToString('yyyy-MM-dd') } } catch { $installed = $null }
        foreach ($u in ($users | Select-Object -Unique)) {
            [pscustomobject]@{
                Type            = 'Store'
                Scope           = "User:$u"
                DisplayName     = $p.Name
                DisplayVersion  = [string]$p.Version
                Publisher       = $publisher
                InstallDate     = $installed
                InstallLocation = $p.InstallLocation
                UninstallString = $null
                KeyName         = $p.PackageFullName
                SignatureKind   = [string]$p.SignatureKind
            }
        }
    }
    $note = "Store apps: $skipped frameworks/inbox Windows packages omitted"
    if (-not $Context.Elevated) { $note += '; not elevated, current user only' }
    $Context.CollectorNote = (("{0} {1}" -f $Context.CollectorNote, $note)).Trim()
}
