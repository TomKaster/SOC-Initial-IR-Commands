# IRTRIAGE-COMPONENT modules/Sessions.ps1
# Users, sessions and SMB. Replaces the legacy `net session` / `net view` calls.

function Get-IRSmbSessions {
    [CmdletBinding()]
    param($Context)
    foreach ($s in @(Get-SmbSession -ErrorAction Stop)) {
        [pscustomobject]@{
            ClientComputerName = $s.ClientComputerName
            ClientUserName     = $s.ClientUserName
            NumOpens           = $s.NumOpens
            SecondsExists      = $s.SecondsExists
            SecondsIdle        = $s.SecondsIdle
            Dialect            = $s.Dialect
            TransportName      = $s.TransportName
        }
    }
}

function Get-IRSmbShares {
    [CmdletBinding()]
    param($Context)
    foreach ($s in @(Get-SmbShare -ErrorAction Stop)) {
        [pscustomobject]@{
            Name        = $s.Name
            Path        = $s.Path
            Description = $s.Description
            Special     = $s.Special
            ShareType   = [string]$s.ShareType
            ScopeName   = $s.ScopeName
        }
    }
}

function Get-IRSmbOutbound {
    [CmdletBinding()]
    param($Context)
    foreach ($c in @(Get-SmbConnection -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            Type       = 'Connection'
            ServerName = $c.ServerName
            ShareName  = $c.ShareName
            UserName   = $c.UserName
            Credential = $c.Credential
            Dialect    = $c.Dialect
            LocalPath  = $null
            RemotePath = $null
        }
    }
    foreach ($m in @(Get-SmbMapping -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            Type       = 'Mapping'
            ServerName = $null
            ShareName  = $null
            UserName   = $null
            Credential = $null
            Dialect    = $null
            LocalPath  = $m.LocalPath
            RemotePath = $m.RemotePath
        }
    }
}

function Get-IRLoggedOnUsers {
    [CmdletBinding()]
    param($Context)
    $found = $false
    $quser = Join-Path $env:SystemRoot 'System32\quser.exe'
    if (Test-Path -LiteralPath $quser) {
        $lines = @()
        try { $lines = @(& $quser 2>$null) } catch { $lines = @() }
        foreach ($line in ($lines | Select-Object -Skip 1)) {
            $m = [regex]::Match($line, '^\s*>?(?<user>\S+)\s+(?<session>\S*?)\s+(?<id>\d+)\s+(?<state>\S+)\s+(?<idle>\S+)\s+(?<logon>.+?)\s*$')
            if (-not $m.Success) { continue }
            $found = $true
            [pscustomobject]@{
                Source      = 'quser'
                UserName    = $m.Groups['user'].Value
                SessionName = $m.Groups['session'].Value
                SessionId   = [int]$m.Groups['id'].Value
                State       = $m.Groups['state'].Value
                IdleTime    = $m.Groups['idle'].Value
                LogonTime   = $m.Groups['logon'].Value
            }
        }
    }
    # Fallback / corroboration: owners of interactive shells.
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
        $owner = $null
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.User) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { $owner = $null }
        [pscustomobject]@{
            Source      = 'explorer.exe owner'
            UserName    = $owner
            SessionName = $null
            SessionId   = $p.SessionId
            State       = 'Active-Shell'
            IdleTime    = $null
            LogonTime   = (ConvertTo-IRIsoTime $p.CreationDate)
        }
    }
    if (-not $found) { $Context.CollectorNote = 'quser unavailable or returned no sessions; explorer owners only' }
}

function Get-IRLocalAdmins {
    [CmdletBinding()]
    param($Context)
    $ok = $false
    try {
        foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
            $ok = $true
            [pscustomobject]@{
                Name            = $m.Name
                ObjectClass     = $m.ObjectClass
                PrincipalSource = [string]$m.PrincipalSource
                SID             = [string]$m.SID
                Method          = 'Get-LocalGroupMember'
            }
        }
    } catch { $ok = $false }
    if ($ok) { return }

    # Get-LocalGroupMember throws on orphaned/unresolvable SIDs (common with AzureAD/Entra members). Fall back to ADSI.
    $Context.CollectorNote = 'Get-LocalGroupMember failed; used ADSI fallback'
    $groupName = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $group = [ADSI]"WinNT://./$groupName,group"
    foreach ($member in @($group.psbase.Invoke('Members'))) {
        $path = $member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
        $class = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
        $sidBytes = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
        $sid = $null
        try { $sid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value } catch { $sid = $null }
        [pscustomobject]@{
            Name            = ($path -replace '^WinNT://', '' -replace '/', '\')
            ObjectClass     = $class
            PrincipalSource = $null
            SID             = $sid
            Method          = 'ADSI'
        }
    }
}

function Get-IRPowerShellHistory {
    <#
      PSReadLine command history (ConsoleHost_history.txt and other hosts' *_history.txt) for every profile.
      Shows what was typed interactively, which script block logging misses when it is off. Keeps the last
      2000 lines of each file. Opened with ReadWrite sharing so a live PSReadLine session does not block it.
    #>
    [CmdletBinding()]
    param($Context)
    $maxLines = 2000
    $truncated = @()
    foreach ($u in Get-IRUserProfileDirs) {
        $dir = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*_history.txt' -File -Force -ErrorAction SilentlyContinue)) {
            $lines = New-Object System.Collections.Generic.List[string]
            $fs = $null; $sr = $null
            try {
                $fs = New-Object System.IO.FileStream($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $sr = New-Object System.IO.StreamReader($fs, $true)
                while ($null -ne ($line = $sr.ReadLine())) { $lines.Add($line) }
            } catch {
                continue
            } finally {
                if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() }
            }
            $start = 0
            if ($lines.Count -gt $maxLines) { $start = $lines.Count - $maxLines; $truncated += "$($u.Name)\$($f.Name)" }
            for ($i = $start; $i -lt $lines.Count; $i++) {
                if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }
                [pscustomobject]@{
                    User             = $u.Name
                    File             = $f.Name
                    LineNumber       = $i + 1
                    Command          = $lines[$i]
                    FileLastWriteUtc = $f.LastWriteTimeUtc
                }
            }
        }
    }
    if ($truncated) { $Context.CollectorNote = "kept last $maxLines lines of: $($truncated -join ', ')" }
}

function Get-IRLocalUsers {
    [CmdletBinding()]
    param($Context)
    foreach ($u in @(Get-LocalUser -ErrorAction Stop)) {
        [pscustomobject]@{
            Name              = $u.Name
            Enabled           = $u.Enabled
            SID               = [string]$u.SID
            LastLogon         = $u.LastLogon
            PasswordLastSet   = $u.PasswordLastSet
            PasswordRequired  = $u.PasswordRequired
            AccountExpires    = $u.AccountExpires
            Description       = $u.Description
            PrincipalSource   = [string]$u.PrincipalSource
        }
    }
}
