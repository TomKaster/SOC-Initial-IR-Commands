# Collector registry. Profiles (profiles/*.json) reference collectors by these names.
#   Function      - function that returns records
#   RequiresAdmin - skipped (status 'skipped_not_elevated') when the script is not elevated
#   Slow          - skipped when -SkipSlow is passed
#   Tabular       - also written as CSV (flat records only)

$script:IRCollectors = [ordered]@{
    system_info         = @{ Function = 'Get-IRSystemInfo';         RequiresAdmin = $false; Slow = $false; Tabular = $false }
    network_connections = @{ Function = 'Get-IRNetworkConnections'; RequiresAdmin = $false; Slow = $false; Tabular = $true }
    network_config      = @{ Function = 'Get-IRNetworkConfig';      RequiresAdmin = $false; Slow = $false; Tabular = $false }
    dns_cache           = @{ Function = 'Get-IRDnsCache';           RequiresAdmin = $false; Slow = $false; Tabular = $true }
    arp_cache           = @{ Function = 'Get-IRArpCache';           RequiresAdmin = $false; Slow = $false; Tabular = $true }
    hosts_file          = @{ Function = 'Get-IRHostsFile';          RequiresAdmin = $false; Slow = $false; Tabular = $true }
    proxy_settings      = @{ Function = 'Get-IRProxySettings';      RequiresAdmin = $false; Slow = $false; Tabular = $true }
    firewall_profiles   = @{ Function = 'Get-IRFirewallProfiles';   RequiresAdmin = $false; Slow = $false; Tabular = $true }
    smb_sessions        = @{ Function = 'Get-IRSmbSessions';        RequiresAdmin = $true;  Slow = $false; Tabular = $true }
    smb_shares          = @{ Function = 'Get-IRSmbShares';          RequiresAdmin = $false; Slow = $false; Tabular = $true }
    smb_outbound        = @{ Function = 'Get-IRSmbOutbound';        RequiresAdmin = $false; Slow = $false; Tabular = $true }
    logged_on_users     = @{ Function = 'Get-IRLoggedOnUsers';      RequiresAdmin = $false; Slow = $false; Tabular = $true }
    local_admins        = @{ Function = 'Get-IRLocalAdmins';        RequiresAdmin = $false; Slow = $false; Tabular = $true }
    local_users         = @{ Function = 'Get-IRLocalUsers';         RequiresAdmin = $false; Slow = $false; Tabular = $true }
    processes           = @{ Function = 'Get-IRProcesses';          RequiresAdmin = $false; Slow = $false; Tabular = $true }
    autoruns_registry   = @{ Function = 'Get-IRAutorunsRegistry';   RequiresAdmin = $false; Slow = $false; Tabular = $true }
    scheduled_tasks     = @{ Function = 'Get-IRScheduledTasks';     RequiresAdmin = $false; Slow = $false; Tabular = $true }
    services            = @{ Function = 'Get-IRServices';           RequiresAdmin = $false; Slow = $false; Tabular = $true }
    wmi_subscriptions   = @{ Function = 'Get-IRWmiSubscriptions';   RequiresAdmin = $true;  Slow = $false; Tabular = $true }
    startup_folders     = @{ Function = 'Get-IRStartupFolders';     RequiresAdmin = $false; Slow = $false; Tabular = $true }
    installed_software  = @{ Function = 'Get-IRInstalledSoftware';  RequiresAdmin = $false; Slow = $false; Tabular = $true }
    defender            = @{ Function = 'Get-IRDefender';           RequiresAdmin = $false; Slow = $false; Tabular = $false }
    events_security     = @{ Function = 'Get-IREventsSecurity';     RequiresAdmin = $true;  Slow = $false; Tabular = $false }
    events_system       = @{ Function = 'Get-IREventsSystem';       RequiresAdmin = $false; Slow = $false; Tabular = $false }
    events_powershell   = @{ Function = 'Get-IREventsPowerShell';   RequiresAdmin = $false; Slow = $false; Tabular = $false }
    events_rdp          = @{ Function = 'Get-IREventsRdp';          RequiresAdmin = $false; Slow = $false; Tabular = $false }
    events_sysmon       = @{ Function = 'Get-IREventsSysmon';       RequiresAdmin = $true;  Slow = $false; Tabular = $false }
    prefetch            = @{ Function = 'Get-IRPrefetch';           RequiresAdmin = $true;  Slow = $false; Tabular = $true }
    recent_executables  = @{ Function = 'Get-IRRecentExecutables';  RequiresAdmin = $false; Slow = $true;  Tabular = $true }
    browser_extensions  = @{ Function = 'Get-IRBrowserExtensions';  RequiresAdmin = $false; Slow = $false; Tabular = $true }
    usb_devices         = @{ Function = 'Get-IRUsbDevices';         RequiresAdmin = $false; Slow = $false; Tabular = $true }
}
