# IRTRIAGE-COMPONENT modules/Processes.ps1
# Running processes with lineage, owner, hash and (optionally) signature.

function Get-IRProcessOwnerMap {
    <#
      PID -> owner. Win32_Process.GetOwner costs ~60ms per process, so when elevated (the EDR/SYSTEM case)
      use Get-Process -IncludeUserName, which returns all owners in one call. When not elevated, only the
      current session's processes are resolvable anyway, so only query those.
    #>
    [CmdletBinding()]
    param($Context, $ProcessMap)
    $owners = @{}
    if ($Context.Elevated) {
        try {
            foreach ($gp in @(Get-Process -IncludeUserName -ErrorAction Stop)) { if ($gp.UserName) { $owners[[int]$gp.Id] = $gp.UserName } }
            return $owners
        } catch { $owners = @{} }
    }
    $mySession = (Get-Process -Id $PID).SessionId
    foreach ($p in $ProcessMap.Values) {
        if ($p.SessionId -ne $mySession -and -not $Context.Elevated) { continue }
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.ReturnValue -eq 0 -and $o.User) { $owners[[int]$p.ProcessId] = "$($o.Domain)\$($o.User)" }
        } catch { continue }
    }
    if (-not $Context.Elevated) { $Context.CollectorNote = 'not elevated: owners resolved for current session only' }
    return $owners
}

function Get-IRProcesses {
    [CmdletBinding()]
    param($Context)
    $map = Get-IRProcessMap
    $owners = Get-IRProcessOwnerMap -Context $Context -ProcessMap $map
    foreach ($p in ($map.Values | Sort-Object -Property ProcessId)) {
        $owner = $owners[[int]$p.ProcessId]

        $parent = $map[[int]$p.ParentProcessId]
        $parentName = $null
        # A PID can be reused; only trust the parent if it was created before the child.
        if ($parent -and $parent.CreationDate -and $p.CreationDate -and $parent.CreationDate -le $p.CreationDate) { $parentName = $parent.Name }

        $facts = Get-IRFileFacts -Path $p.ExecutablePath -Context $Context
        [pscustomobject]@{
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            ParentName      = $parentName
            Name            = $p.Name
            ExecutablePath  = $p.ExecutablePath
            CommandLine     = $p.CommandLine
            CreationDate    = $p.CreationDate
            Owner           = $owner
            SessionId       = $p.SessionId
            Sha256          = $facts.Sha256
            SignatureStatus = $facts.SignatureStatus
            Signer          = $facts.Signer
            UserWritable    = $facts.UserWritable
        }
    }
}
