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
            [pscustomobject]@{
                Scope           = $r.Scope
                DisplayName     = $p.DisplayName
                DisplayVersion  = $p.DisplayVersion
                Publisher       = $p.Publisher
                InstallDate     = $p.InstallDate
                InstallLocation = $p.InstallLocation
                UninstallString = $p.UninstallString
                KeyName         = $k.PSChildName
            }
        }
    }
}
