<#
.SYNOPSIS
    Diffs a suspect host's triage against a known-good baseline (e.g. a fresh gold-image build).

.DESCRIPTION
    Compares persistence, accounts, listeners and software between two IRTriage collections and reports
    what was Added, Removed or Modified on the suspect. Added items are where attackers usually show up.

.EXAMPLE
    .\Compare-Triage.ps1 -Baseline .\baselines\win11-gold.zip -Suspect .\cases\INC-1042\WS-0193.zip

.EXAMPLE
    .\Compare-Triage.ps1 -Baseline base.zip -Suspect host.zip -Change Added -OutCsv diff.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Baseline,
    [Parameter(Mandatory)][string]$Suspect,
    [string[]]$Category,
    [ValidateSet('Added', 'Removed', 'Modified')][string[]]$Change = @('Added', 'Removed', 'Modified'),
    [string]$OutCsv
)
. (Join-Path $PSScriptRoot 'TriageCommon.ps1')

function Get-IRDiffRules {
    # Each rule: collector, key (identity), detail (compared to detect modification), optional filter.
    @(
        @{ Category = 'services';          Collector = 'services';            Key = { $_.Name };                                   Detail = { "$($_.PathName) | start=$($_.StartMode) | as=$($_.StartName) | dll=$($_.ServiceDll)" } },
        @{ Category = 'scheduled_tasks';   Collector = 'scheduled_tasks';     Key = { "$($_.TaskPath)$($_.TaskName)" };            Detail = { "$($_.Actions) | runAs=$($_.RunAs) | $($_.State)" } },
        @{ Category = 'autoruns_registry'; Collector = 'autoruns_registry';   Key = { "$($_.Location)\$($_.Name)" };               Detail = { $_.Value } },
        @{ Category = 'startup_folders';   Collector = 'startup_folders';     Key = { "$($_.Scope)|$([System.IO.Path]::GetFileName($_.Path))" }; Detail = { "$($_.LnkTarget) $($_.LnkArguments) $($_.Sha256)" } },
        @{ Category = 'wmi_subscriptions'; Collector = 'wmi_subscriptions';   Key = { "$($_.Type)|$($_.Name)|$($_.Filter)|$($_.Consumer)" }; Detail = { $_.Detail } },
        @{ Category = 'local_admins';      Collector = 'local_admins';        Key = { ($_.Name -replace '^[^\\]+\\(?=(Administrator|Guest|DefaultAccount)$)', 'LOCAL\') }; Detail = { $_.ObjectClass } },
        @{ Category = 'local_users';       Collector = 'local_users';         Key = { $_.Name };                                   Detail = { "enabled=$($_.Enabled)" } },
        @{ Category = 'listeners';         Collector = 'network_connections'; Key = { "$($_.Protocol)/$($_.LocalPort)|$($_.ProcessName)" }; Detail = { $_.ProcessPath }; Filter = { $_.State -eq 'Listen' -and $_.LocalAddress -notmatch '^(127\.|::1$)' } },
        @{ Category = 'installed_software'; Collector = 'installed_software'; Key = { "$($_.DisplayName)" };                       Detail = { $_.DisplayVersion } },
        @{ Category = 'process_images';    Collector = 'processes';           Key = { "$($_.ExecutablePath)".ToLowerInvariant() }; Detail = { $_.Sha256 }; Filter = { $_.ExecutablePath } },
        @{ Category = 'hosts_file';        Collector = 'hosts_file';          Key = { "$($_.HostName)" };                          Detail = { $_.IPAddress } },
        @{ Category = 'smb_shares';        Collector = 'smb_shares';          Key = { $_.Name };                                   Detail = { $_.Path } },
        @{ Category = 'browser_extensions'; Collector = 'browser_extensions'; Key = { "$($_.Browser)|$($_.ExtensionId)" };         Detail = { "$($_.Name) $($_.Version)" } }
    )
}

function Invoke-IRRuleBlock {
    # Runs a rule scriptblock with $_ bound to the record.
    param([scriptblock]$Block, $Record)
    $vars = New-Object 'System.Collections.Generic.List[psvariable]'
    $vars.Add((New-Object psvariable '_', $Record))
    return @($Block.InvokeWithContext($null, $vars))[0]
}

function Get-IRIndex {
    param($Records, $Rule)
    $idx = @{}
    foreach ($r in $Records) {
        if ($Rule.Filter -and -not (Invoke-IRRuleBlock $Rule.Filter $r)) { continue }
        $k = [string](Invoke-IRRuleBlock $Rule.Key $r)
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $d = [string](Invoke-IRRuleBlock $Rule.Detail $r)
        if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object System.Collections.Generic.List[string] }
        if (-not $idx[$k].Contains($d)) { $idx[$k].Add($d) }
    }
    return $idx
}

$base = Import-IRTriage -Path $Baseline
$susp = Import-IRTriage -Path $Suspect
foreach ($t in $base, $susp) {
    if (-not $t.Integrity.Valid) { Write-Warning "Integrity check FAILED for $($t.Path): $(($t.Integrity.Problems | ForEach-Object { "$($_.File) $($_.Problem)" }) -join '; ')" }
}

$out = New-Object System.Collections.ArrayList
foreach ($rule in Get-IRDiffRules) {
    if ($Category -and $rule.Category -notin $Category) { continue }
    $bRecs = Get-IRRecords $base $rule.Collector
    $sRecs = Get-IRRecords $susp $rule.Collector
    if ($bRecs.Count -eq 0 -and $sRecs.Count -eq 0) { continue }
    if ($bRecs.Count -eq 0 -and -not $base.Data.ContainsKey($rule.Collector)) {
        Write-Verbose "Baseline has no '$($rule.Collector)' collector output; skipping $($rule.Category)."
        continue
    }
    if ($sRecs.Count -eq 0 -and -not $susp.Data.ContainsKey($rule.Collector)) {
        Write-Verbose "Suspect has no '$($rule.Collector)' collector output; skipping $($rule.Category)."
        continue
    }
    $bi = Get-IRIndex $bRecs $rule
    $si = Get-IRIndex $sRecs $rule
    foreach ($k in ($si.Keys | Sort-Object)) {
        $sd = ($si[$k] | Sort-Object) -join ' || '
        if (-not $bi.ContainsKey($k)) {
            [void]$out.Add([pscustomobject]@{ Category = $rule.Category; Change = 'Added'; Key = $k; Baseline = $null; Suspect = $sd })
        } else {
            $bd = ($bi[$k] | Sort-Object) -join ' || '
            if ($bd -ne $sd) { [void]$out.Add([pscustomobject]@{ Category = $rule.Category; Change = 'Modified'; Key = $k; Baseline = $bd; Suspect = $sd }) }
        }
    }
    foreach ($k in ($bi.Keys | Sort-Object)) {
        if (-not $si.ContainsKey($k)) {
            [void]$out.Add([pscustomobject]@{ Category = $rule.Category; Change = 'Removed'; Key = $k; Baseline = (($bi[$k] | Sort-Object) -join ' || '); Suspect = $null })
        }
    }
}

$result = @($out | Where-Object { $_.Change -in $Change })
if ($OutCsv) { $result | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8 }
$result
