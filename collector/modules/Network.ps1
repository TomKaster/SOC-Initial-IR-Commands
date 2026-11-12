# Network state. Replaces the legacy `ipconfig /all` and `netstat -naob` text output with objects.

function Get-IRNetworkConnections {
    [CmdletBinding()]
    param($Context)
    $procs = Get-IRProcessMap

    $resolve = {
        param([int]$ProcessId)
        $p = $procs[$ProcessId]
        $path = $null; $name = $null
        if ($p) { $path = $p.ExecutablePath; $name = $p.Name }
        $facts = Get-IRFileFacts -Path $path -Context $Context
        [pscustomobject]@{ Name = $name; Path = $path; Facts = $facts }
    }

    foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $pi = & $resolve ([int]$c.OwningProcess)
        [pscustomobject]@{
            Protocol        = 'TCP'
            LocalAddress    = $c.LocalAddress
            LocalPort       = $c.LocalPort
            RemoteAddress   = $c.RemoteAddress
            RemotePort      = $c.RemotePort
            State           = [string]$c.State
            IsExternal      = -not (Test-IRPrivateAddress $c.RemoteAddress)
            OwningProcess   = $c.OwningProcess
            ProcessName     = $pi.Name
            ProcessPath     = $pi.Path
            ProcessSha256   = $pi.Facts.Sha256
            SignatureStatus = $pi.Facts.SignatureStatus
            Signer          = $pi.Facts.Signer
            CreationTime    = $c.CreationTime
        }
    }

    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $pi = & $resolve ([int]$u.OwningProcess)
        [pscustomobject]@{
            Protocol        = 'UDP'
            LocalAddress    = $u.LocalAddress
            LocalPort       = $u.LocalPort
            RemoteAddress   = $null
            RemotePort      = $null
            State           = 'Listen'
            IsExternal      = $false
            OwningProcess   = $u.OwningProcess
            ProcessName     = $pi.Name
            ProcessPath     = $pi.Path
            ProcessSha256   = $pi.Facts.Sha256
            SignatureStatus = $pi.Facts.SignatureStatus
            Signer          = $pi.Facts.Signer
            CreationTime    = $u.CreationTime
        }
    }
}

function Get-IRNetworkConfig {
    [CmdletBinding()]
    param($Context)
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
        Select-Object Name, InterfaceDescription, InterfaceIndex, Status, MacAddress, LinkSpeed, MediaType)
    $addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength, AddressFamily, PrefixOrigin, SuffixOrigin)
    $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses)
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in '0.0.0.0/0', '::/0' } |
        Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric)
    $suffix = @(Get-DnsClient -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionSpecificSuffix } |
        Select-Object InterfaceAlias, ConnectionSpecificSuffix)

    [pscustomobject]@{
        Adapters        = $adapters
        IPAddresses     = $addresses
        DnsServers      = $dns
        DefaultRoutes   = $routes
        DnsSuffixes     = $suffix
    }
}

function Get-IRDnsCache {
    [CmdletBinding()]
    param($Context)
    foreach ($e in @(Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            Entry      = $e.Entry
            RecordName = $e.Name
            Type       = [string]$e.Type
            Data       = $e.Data
            TimeToLive = $e.TimeToLive
            Section    = [string]$e.Section
            Status     = [string]$e.Status
        }
    }
}

function Get-IRArpCache {
    [CmdletBinding()]
    param($Context)
    foreach ($n in @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress })) {
        [pscustomobject]@{
            InterfaceAlias   = $n.InterfaceAlias
            IPAddress        = $n.IPAddress
            LinkLayerAddress = $n.LinkLayerAddress
            State            = [string]$n.State
            AddressFamily    = [string]$n.AddressFamily
        }
    }
}

function Get-IRHostsFile {
    [CmdletBinding()]
    param($Context)
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $path)) { $Context.CollectorNote = 'hosts file not present'; return }
    $i = 0
    foreach ($line in [System.IO.File]::ReadAllLines($path)) {
        $i++
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $t = ($t -split '#', 2)[0].Trim()
        $parts = $t -split '\s+'
        if ($parts.Count -lt 2) { continue }
        foreach ($hostName in $parts[1..($parts.Count - 1)]) {
            [pscustomobject]@{ LineNumber = $i; IPAddress = $parts[0]; HostName = $hostName }
        }
    }
}

function Get-IRProxySettings {
    [CmdletBinding()]
    param($Context)
    $keys = @(@{ Scope = 'Machine-Policy'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' })
    foreach ($h in Get-IRUserHives) {
        $keys += @{ Scope = "User:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings" }
    }
    foreach ($k in $keys) {
        $p = Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        [pscustomobject]@{
            Scope         = $k.Scope
            ProxyEnable   = $p.ProxyEnable
            ProxyServer   = $p.ProxyServer
            ProxyOverride = $p.ProxyOverride
            AutoConfigURL = $p.AutoConfigURL
            Raw           = $null
        }
    }
    $winhttp = $null
    try { $winhttp = (& netsh.exe winhttp show proxy 2>$null | Out-String).Trim() } catch { $winhttp = $null }
    [pscustomobject]@{
        Scope = 'WinHTTP'; ProxyEnable = $null; ProxyServer = $null; ProxyOverride = $null; AutoConfigURL = $null; Raw = $winhttp
    }
}

function Get-IRFirewallProfiles {
    [CmdletBinding()]
    param($Context)
    foreach ($f in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            Name                  = $f.Name
            Enabled               = [string]$f.Enabled
            DefaultInboundAction  = [string]$f.DefaultInboundAction
            DefaultOutboundAction = [string]$f.DefaultOutboundAction
            LogAllowed            = [string]$f.LogAllowed
            LogBlocked            = [string]$f.LogBlocked
            LogFileName           = $f.LogFileName
        }
    }
}
