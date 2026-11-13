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