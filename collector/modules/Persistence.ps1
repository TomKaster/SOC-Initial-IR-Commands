# IRTRIAGE-COMPONENT modules/Persistence.ps1
# Persistence mechanisms: registry autoruns, scheduled tasks, services, WMI subscriptions, startup folders.

function Get-IRAutorunsRegistry {
    [CmdletBinding()]
    param($Context)
    $hklm = 'Registry::HKEY_LOCAL_MACHINE'
    $locations = @(
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Values = @('Shell', 'Userinit', 'Taskman', 'AppSetup') },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Values = @('AppInit_DLLs', 'LoadAppInit_DLLs', 'Load', 'Run') },
        @{ Hive = 'HKLM'; Path = "$hklm\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"; Values = @('AppInit_DLLs', 'LoadAppInit_DLLs') },
        @{ Hive = 'HKLM'; Path = "$hklm\SYSTEM\CurrentControlSet\Control\Lsa"; Values = @('Security Packages', 'Authentication Packages', 'Notification Packages') },
        @{ Hive = 'HKLM'; Path = "$hklm\SYSTEM\CurrentControlSet\Control\Session Manager"; Values = @('BootExecute') }
    )
    foreach ($h in Get-IRUserHives) {
        $locations += @{ Hive = "HKU:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Run" }
        $locations += @{ Hive = "HKU:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
        $locations += @{ Hive = "HKU:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" }
        $locations += @{ Hive = "HKU:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"; Values = @('Shell') }
        $locations += @{ Hive = "HKU:$($h.User)"; Path = "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"; Values = @('Load', 'Run') }
    }

    foreach ($loc in $locations) {
        $key = Get-Item -Path $loc.Path -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        $names = @($key.GetValueNames())
        if ($loc.Values) { $names = @($names | Where-Object { $_ -in $loc.Values }) }
        foreach ($n in $names) {
            $raw = $key.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
            if ($raw -is [array]) { $raw = ($raw -join ';') }
            $val = [string]$raw
            $image = Resolve-IRImagePath $val
            $facts = Get-IRFileFacts -Path $image -Context $Context
            [pscustomobject]@{
                Hive            = $loc.Hive
                Location        = ($loc.Path -replace '^Registry::', '')
                Name            = $n
                Value           = $val
                ImagePath       = $image
                Sha256          = $facts.Sha256
                SignatureStatus = $facts.SignatureStatus
                Signer          = $facts.Signer
                UserWritable    = $facts.UserWritable
            }
        }
    }

    # Image File Execution Options debugger hijacks (T1546.012).
    $ifeo = "$hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    foreach ($k in @(Get-ChildItem -Path $ifeo -ErrorAction SilentlyContinue)) {
        $dbg = $k.GetValue('Debugger', $null)
        if (-not $dbg) { continue }
        $image = Resolve-IRImagePath ([string]$dbg)
        $facts = Get-IRFileFacts -Path $image -Context $Context
        [pscustomobject]@{
            Hive = 'HKLM'; Location = ($k.Name); Name = 'Debugger'; Value = [string]$dbg; ImagePath = $image
            Sha256 = $facts.Sha256; SignatureStatus = $facts.SignatureStatus; Signer = $facts.Signer; UserWritable = $facts.UserWritable
        }
    }
}

function Get-IRScheduledTasks {
    [CmdletBinding()]
    param($Context)
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $actions = @()
        $firstExec = $null
        foreach ($a in @($t.Actions)) {
            if ($a.Execute) {
                $actions += ("{0} {1}" -f $a.Execute, $a.Arguments).Trim()
                if (-not $firstExec) { $firstExec = $a.Execute }
            } elseif ($a.ClassId) {
                $actions += "COM:$($a.ClassId) $($a.Data)".Trim()
            }
        }
        $triggers = @($t.Triggers | ForEach-Object {
            if ($_) { ($_.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '') }
        })
        $image = Resolve-IRImagePath $firstExec
        $facts = Get-IRFileFacts -Path $image -Context $Context

        $lastRun = $null; $nextRun = $null; $lastResult = $null
        try {
            $info = Get-ScheduledTaskInfo -InputObject $t -ErrorAction Stop
            $lastRun = $info.LastRunTime; $nextRun = $info.NextRunTime; $lastResult = $info.LastTaskResult
        } catch { $lastRun = $null }

        [pscustomobject]@{
            TaskPath        = $t.TaskPath
            TaskName        = $t.TaskName
            State           = [string]$t.State
            Author          = $t.Author
            Description     = $t.Description
            RunAs           = $t.Principal.UserId
            RunLevel        = [string]$t.Principal.RunLevel
            Actions         = ($actions -join ' | ')
            Triggers        = ($triggers -join ',')
            Hidden          = $t.Settings.Hidden
            LastRunTime     = $lastRun
            NextRunTime     = $nextRun
            LastTaskResult  = $lastResult
            ImagePath       = $image
            Sha256          = $facts.Sha256
            SignatureStatus = $facts.SignatureStatus
            Signer          = $facts.Signer
            UserWritable    = $facts.UserWritable
            IsMicrosoftPath = [bool]($t.TaskPath -like '\Microsoft\*')
        }
    }
}

function Get-IRServices {
    [CmdletBinding()]
    param($Context)
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $image = Resolve-IRImagePath $s.PathName
        $facts = Get-IRFileFacts -Path $image -Context $Context
        $serviceDll = $null
        if ($image -match '(?i)\\svchost\.exe$') {
            $params = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" -ErrorAction SilentlyContinue
            if ($params -and $params.ServiceDll) { $serviceDll = [Environment]::ExpandEnvironmentVariables([string]$params.ServiceDll) }
        }
        [pscustomobject]@{
            Name            = $s.Name
            DisplayName     = $s.DisplayName
            State           = $s.State
            StartMode       = $s.StartMode
            StartName       = $s.StartName
            ServiceType     = $s.ServiceType
            ProcessId       = $s.ProcessId
            PathName        = $s.PathName
            ImagePath       = $image
            ServiceDll      = $serviceDll
            Sha256          = $facts.Sha256
            SignatureStatus = $facts.SignatureStatus
            Signer          = $facts.Signer
            UserWritable    = $facts.UserWritable
            Description     = $s.Description
        }
    }
}

function Get-IRWmiSubscriptions {
    [CmdletBinding()]
    param($Context)
    $ns = 'root\subscription'
    foreach ($f in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)) {
        [pscustomobject]@{ Type = 'Filter'; Name = $f.Name; Class = $f.CimClass.CimClassName; Detail = $f.Query; Consumer = $null; Filter = $null }
    }
    foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop)) {
        $detail = $null
        switch ($c.CimClass.CimClassName) {
            'CommandLineEventConsumer'  { $detail = "$($c.ExecutablePath) $($c.CommandLineTemplate)".Trim() }
            'ActiveScriptEventConsumer' { $detail = "[$($c.ScriptingEngine)] $($c.ScriptFileName) $($c.ScriptText)".Trim() }
            'NTEventLogEventConsumer'   { $detail = "EventLog: $($c.SourceName)" }
            'LogFileEventConsumer'      { $detail = "LogFile: $($c.Filename)" }
            'SMTPEventConsumer'         { $detail = "SMTP: $($c.ToLine)" }
            default                     { $detail = $c.CimClass.CimClassName }
        }
        [pscustomobject]@{ Type = 'Consumer'; Name = $c.Name; Class = $c.CimClass.CimClassName; Detail = $detail; Consumer = $null; Filter = $null }
    }
    foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)) {
        [pscustomobject]@{
            Type = 'Binding'; Name = $null; Class = '__FilterToConsumerBinding'; Detail = $null
            Consumer = [string]$b.Consumer.Name; Filter = [string]$b.Filter.Name
        }
    }
}

function Get-IRStartupFolders {
    [CmdletBinding()]
    param($Context)
    $dirs = @(@{ Scope = 'AllUsers'; Path = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp' })
    foreach ($u in Get-IRUserProfileDirs) {
        $dirs += @{ Scope = "User:$($u.Name)"; Path = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { $shell = $null }
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d.Path -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -ieq 'desktop.ini') { continue }
            $target = $null; $targetArgs = $null
            if ($shell -and $f.Extension -ieq '.lnk') {
                try { $lnk = $shell.CreateShortcut($f.FullName); $target = $lnk.TargetPath; $targetArgs = $lnk.Arguments } catch { $target = $null }
            }
            $hashPath = $f.FullName
            if ($target) { $hashPath = $target }
            $facts = Get-IRFileFacts -Path $hashPath -Context $Context
            [pscustomobject]@{
                Scope            = $d.Scope
                Path             = $f.FullName
                Length           = $f.Length
                CreationTimeUtc  = $f.CreationTimeUtc
                LastWriteTimeUtc = $f.LastWriteTimeUtc
                LnkTarget        = $target
                LnkArguments     = $targetArgs
                Sha256           = $facts.Sha256
                SignatureStatus  = $facts.SignatureStatus
                Signer           = $facts.Signer
            }
        }
    }
}
