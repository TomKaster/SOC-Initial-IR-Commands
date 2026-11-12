#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Unit tests for collector helpers, profile validation, build output, and an integration run of the
# quick profile against the machine running the tests (works elevated or not).

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    $collector = Join-Path $repo 'collector\Invoke-IRTriage.ps1'
    foreach ($m in Get-ChildItem (Join-Path $repo 'collector\modules') -Filter '*.ps1') { . $m.FullName }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("irtriage-col-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $tmp)
}

AfterAll {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}

Describe 'Resolve-IRImagePath' {
    It 'handles <cmd>' -ForEach @(
        @{ cmd = '"C:\Program Files\App\app.exe" -k foo'; expected = 'C:\Program Files\App\app.exe' }
        @{ cmd = 'C:\Program Files\App\app.exe -k foo';   expected = 'C:\Program Files\App\app.exe' }
        @{ cmd = 'C:\Windows\system32\svchost.exe -k netsvcs -p'; expected = 'C:\Windows\system32\svchost.exe' }
        @{ cmd = '\??\C:\Windows\system32\drivers\x.sys';  expected = 'C:\Windows\system32\drivers\x.sys' }
        @{ cmd = 'rundll32.exe C:\Users\Public\a.dll,Start'; expected = (Join-Path $env:SystemRoot 'System32\rundll32.exe') }
    ) {
        Resolve-IRImagePath $cmd | Should -Be $expected
    }
    It 'expands \SystemRoot\ prefixes' {
        Resolve-IRImagePath '\SystemRoot\System32\drivers\acpi.sys' | Should -Be (Join-Path $env:SystemRoot 'System32\drivers\acpi.sys')
    }
    It 'returns null for empty input' { Resolve-IRImagePath '' | Should -BeNullOrEmpty }
}

Describe 'Test-IRPrivateAddress' {
    It '<a> private=<p>' -ForEach @(
        @{ a = '10.1.2.3'; p = $true }, @{ a = '172.16.0.1'; p = $true }, @{ a = '172.32.0.1'; p = $false },
        @{ a = '192.168.1.1'; p = $true }, @{ a = '127.0.0.1'; p = $true }, @{ a = '100.64.0.1'; p = $true },
        @{ a = '8.8.8.8'; p = $false }, @{ a = '::1'; p = $true }, @{ a = 'fe80::1'; p = $true },
        @{ a = '2606:4700::1111'; p = $false }, @{ a = '::ffff:10.0.0.1'; p = $true }
    ) {
        Test-IRPrivateAddress $a | Should -Be $p
    }
}

Describe 'Test-IRUserWritablePath' {
    It 'flags AppData and Public' {
        Test-IRUserWritablePath 'C:\Users\jdoe\AppData\Roaming\x.exe' | Should -BeTrue
        Test-IRUserWritablePath 'C:\Users\Public\x.exe' | Should -BeTrue
    }
    It 'does not flag System32 or Program Files' {
        Test-IRUserWritablePath 'C:\Windows\System32\cmd.exe' | Should -BeFalse
        Test-IRUserWritablePath 'C:\Program Files\App\app.exe' | Should -BeFalse
    }
}

Describe 'ConvertTo-IRPlain' {
    It 'renders DateTime as ISO-8601 UTC and enums as names' {
        $o = ConvertTo-IRPlain ([pscustomobject]@{ When = [datetime]::new(2026, 1, 2, 3, 4, 5, [DateTimeKind]::Utc); Day = [DayOfWeek]::Monday })
        $o.When | Should -Be '2026-01-02T03:04:05.0000000Z'
        $o.Day | Should -Be 'Monday'
    }
    It 'keeps arrays as arrays (including single-element)' {
        $o = ConvertTo-IRPlain ([pscustomobject]@{ List = @('a') })
        ,$o.List | Should -BeOfType [object[]]
        (ConvertTo-Json -InputObject $o -Compress) | Should -Be '{"List":["a"]}'
    }
}

Describe 'Profiles' {
    It '<_> is valid JSON and references only known collectors' -ForEach @('quick', 'standard', 'full') {
        $p = Get-Content -Raw (Join-Path $repo "profiles\$_.json") | ConvertFrom-Json
        $p.name | Should -Be $_
        $p.timeBudgetSeconds | Should -BeGreaterThan 0
        foreach ($c in $p.collectors) { $script:IRCollectors.Contains($c) | Should -BeTrue -Because "collector '$c' must exist in Registry.ps1" }
        foreach ($k in 'lookbackHours', 'maxEventsPerCollector', 'signatures', 'recentFileDays', 'maxDepth', 'maxFiles') {
            $p.options.PSObject.Properties.Name | Should -Contain $k
        }
    }
    It 'every registered collector function exists' {
        foreach ($k in $script:IRCollectors.Keys) { Get-Command $script:IRCollectors[$k].Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because $k }
    }
    It 'every collector is used by at least the full profile' {
        $full = (Get-Content -Raw (Join-Path $repo 'profiles\full.json') | ConvertFrom-Json).collectors
        foreach ($k in $script:IRCollectors.Keys) { $full | Should -Contain $k }
    }
}

Describe 'build.ps1' {
    BeforeAll {
        $dist = Join-Path $tmp 'dist'
        & (Join-Path $repo 'build.ps1') -OutputDirectory $dist 6>$null
        $built = Join-Path $dist 'Invoke-IRTriage.ps1'
        $text = [System.IO.File]::ReadAllText($built)
    }
    It 'produces a single file with modules and profiles inlined' {
        $text | Should -Match 'inlined by build\.ps1'
        $text | Should -Not -Match "Join-Path \`$PSScriptRoot 'modules'"
        $text | Should -Match "IRProfileJson\['quick'\]"
        $text | Should -Match 'function Get-IRServices'
    }
    It 'parses without errors' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($built, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }
    It 'is written with a UTF-8 BOM and CRLF line endings' {
        $bytes = [System.IO.File]::ReadAllBytes($built)
        $bytes[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
        $text | Should -Not -Match "[^\r]\n"
    }
    It 'writes a matching .sha256' {
        $expected = ((Get-Content -Raw "$built.sha256").Trim() -split '\s+')[0]
        (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash | Should -Be $expected
    }
}

Describe 'Invoke-IRTriage.ps1 (integration, quick profile)' {
    BeforeAll {
        $out = Join-Path $tmp 'run'
        $lines = @(& $collector -CaseId 'PESTER-1' -OutputPath $out -KeepFolder -Analyst 'pester' 6>$null)
        $resultLine = $lines | Where-Object { $_ -like 'IRTRIAGE_RESULT *' } | Select-Object -Last 1
        $result = ConvertFrom-Json $resultLine.Substring(16)
        $manifest = Get-Content -Raw (Join-Path $out 'manifest.json') | ConvertFrom-Json
    }

    It 'emits a machine-readable result line' {
        $resultLine | Should -Not -BeNullOrEmpty
        $result.caseId | Should -Be 'PESTER-1'
        $result.zipSha256 | Should -Match '^[A-F0-9]{64}$'
    }
    It 'zip hash matches the .sha256 file and the result line' {
        $zipHash = (Get-FileHash -LiteralPath "$out.zip" -Algorithm SHA256).Hash
        $zipHash | Should -Be $result.zipSha256
        ((Get-Content -Raw "$out.zip.sha256").Trim() -split '\s+')[0] | Should -Be $zipHash
    }
    It 'records case metadata in the manifest' {
        $manifest.case.caseId | Should -Be 'PESTER-1'
        $manifest.case.analyst | Should -Be 'pester'
        $manifest.host.computerName | Should -Be $env:COMPUTERNAME
        $manifest.run.profile | Should -Be 'quick'
    }
    It 'every manifest file hash matches the file on disk' {
        foreach ($f in $manifest.files) {
            (Get-FileHash -LiteralPath (Join-Path $out $f.path) -Algorithm SHA256).Hash | Should -Be $f.sha256 -Because $f.path
        }
    }
    It 'every JSON output parses' {
        foreach ($f in Get-ChildItem $out -Filter '*.json') { { Get-Content -Raw $f.FullName | ConvertFrom-Json } | Should -Not -Throw -Because $f.Name }
    }
    It 'no collector errored' {
        @($manifest.collectors | Where-Object status -eq 'error' | ForEach-Object { "$($_.name): $($_.error)" }) | Should -BeNullOrEmpty
    }
    It 'skips admin-only collectors when not elevated (and runs them when elevated)' {
        $smb = $manifest.collectors | Where-Object name -eq 'smb_sessions'
        if ($manifest.case.elevated) { $smb.status | Should -Be 'ok' } else { $smb.status | Should -Be 'skipped_not_elevated' }
    }
    It 'collects core artifacts' {
        foreach ($n in 'system_info', 'network_connections', 'processes', 'services') {
            ($manifest.collectors | Where-Object name -eq $n).records | Should -BeGreaterThan 0 -Because $n
        }
    }
    It 'refuses to overwrite a non-IRTriage folder even with -Force' {
        $foreign = Join-Path $tmp 'foreign'
        [void](New-Item -ItemType Directory -Path $foreign)
        Set-Content -LiteralPath (Join-Path $foreign 'keep.txt') -Value 'do not delete'
        { & $collector -CaseId 'PESTER-2' -OutputPath $foreign -Force -Collectors system_info 6>$null } | Should -Throw
        Test-Path -LiteralPath (Join-Path $foreign 'keep.txt') | Should -BeTrue
    }
    It 'rejects unknown collectors and unsafe case IDs' {
        { & $collector -Collectors 'nope' -OutputPath (Join-Path $tmp 'x') 6>$null } | Should -Throw
        { & $collector -CaseId '..\..\evil' -OutputPath (Join-Path $tmp 'y') 6>$null } | Should -Throw
    }
}
