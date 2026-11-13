# Artifact reference

What each collector gathers, the question it helps answer, and the related MITRE ATT&CK techniques.
**Q** = quick, **S** = standard, **F** = full profile. **Admin** = skipped when not elevated (EDR runs as SYSTEM, so it is elevated).

| Collector | Profiles | Admin | Answers | ATT&CK |
|---|---|---|---|---|
| `system_info` | Q S F | | What is this host, when did it last boot, what patches are recent? | T1082 |
| `network_connections` | Q S F | | What is talking to what right now, and which binary owns each socket (path + SHA-256)? Replaces `netstat -naob`. | T1071, T1571, T1049 |
| `network_config` | Q S F | | Adapters, IPs, DNS servers, default routes. Replaces `ipconfig /all`. | T1016 |
| `dns_cache` | Q S F | | What names has the host resolved recently (C2 / staging domains)? | T1071.004 |
| `arp_cache` | Q S F | | Which LAN neighbours has the host talked to (lateral movement)? | T1018 |
| `hosts_file` | Q S F | | Has name resolution been hijacked or security domains blackholed? | T1565.001, T1562 |
| `proxy_settings` | Q S F | | Per-user / machine / WinHTTP proxy (traffic interception, PAC abuse). | T1090 |
| `firewall_profiles` | Q S F | | Is the host firewall disabled or default-allow? | T1562.004 |
| `smb_sessions` | Q S F | yes | Who is connected *into* this host over SMB right now? Replaces `net session`. | T1021.002 |
| `smb_shares` | Q S F | | Unexpected shares (staging / exfil). | T1135 |
| `smb_outbound` | Q S F | | Which remote shares has this host connected to / mapped? | T1021.002 |
| `logged_on_users` | Q S F | | Who is logged on (console / RDP / disconnected)? | T1033 |
| `local_admins` | Q S F | | Has anyone been added to local Administrators? | T1098, T1136.001 |
| `local_users` | Q S F | | New or re-enabled local accounts. | T1136.001 |
| `processes` | Q S F | | Full process tree with command lines, owner, image hash (and signer in S/F). | T1059, T1055, T1036 |
| `named_pipes` | Q S F | | Open named pipes. Default C2 pipe names (Cobalt Strike `msagent_##`, `postex_####`, ...) and PsExec-style pipes. | T1570, T1021.002, T1071 |
| `powershell_history` | Q S F | | What was typed at PowerShell prompts (PSReadLine history per user, last 2,000 lines per file). | T1059.001 |
| `bits_jobs` | Q S F | yes | BITS jobs for all users: remote URLs, local files, notify command lines. | T1197 |
| `autoruns_registry` | Q S F | | Run/RunOnce, Winlogon, AppInit, LSA packages, IFEO debuggers (per user and machine). | T1547.001, T1547.004, T1546.010, T1546.012, T1547.002 |
| `scheduled_tasks` | Q S F | | Tasks with actions, run-as, triggers, last run time, image hash. | T1053.005 |
| `services` | Q S F | | Services with image path, ServiceDll, account, hash. | T1543.003 |
| `wmi_subscriptions` | Q S F | yes | WMI event filters / consumers / bindings. | T1546.003 |
| `startup_folders` | Q S F | | Startup folder items with resolved `.lnk` targets. | T1547.001 |
| `installed_software` | Q S F | | Installed applications with versions: desktop programs (machine and per-user Uninstall keys) and Microsoft Store/MSIX packages per user (frameworks and inbox Windows apps omitted; all users when elevated). Remote access tools (AnyDesk, ScreenConnect...) and sideloaded packages become leads. | T1219, T1204.002 |
| `defender` | S F | | RTP / tamper protection state, **exclusions**, detections, Defender event log. | T1562.001 |
| `events_security` | S F | yes | 4624/4625/4648/4672 logons, 4720 + 4728/4732/4756 account and group changes, 4697 service install, 4698/4702 scheduled task created/updated, 4719 audit policy changed, 1102 log cleared. | T1078, T1110, T1098, T1053.005, T1562.002, T1070.001 |
| `events_process_creation` | S F | yes | 4688 process creation with command line (needs "Audit Process Creation" and command-line inclusion by GPO). Own event budget. | T1059 |
| `events_system` | S F | | 7045/7040 service install/changes, 104 log cleared, boot/shutdown. | T1543.003, T1070.001 |
| `events_powershell` | S F | | 4104 script block and 4103 module logging. | T1059.001 |
| `events_rdp` | S F | | 1149 RDP auth, 21/24/25 session logon/disconnect/reconnect. | T1021.001 |
| `events_sysmon` | S F | yes | Sysmon 1/3/8/10/11/13/22 if Sysmon is deployed. | many |
| `prefetch` | F | yes | Evidence of execution (names + first/last run times). | T1059 |
| `recent_executables` | F | | Executables/scripts/LNK/ISO recently written to user-writable paths, hashed. Slow, skipped by `-SkipSlow`. | T1105, T1204 |
| `browser_extensions` | F | | Chrome/Edge/Brave/Firefox extensions per user. | T1176 |
| `usb_devices` | F | | USB mass-storage history. | T1052, T1091 |

## Design rules for new collectors

1. Built-in cmdlets/.NET only. Nothing gets installed or dropped on the endpoint.
2. Read-only. A collector may only write through the framework (its own JSON/CSV in the output folder).
3. One function per collector in `collector/modules/*.ps1`, signature `param($Context)`, returning flat `[pscustomobject]` records where possible.
4. Register it in `collector/modules/Registry.ps1` (set `RequiresAdmin`, `Slow`, `Tabular`), add it to at least `profiles/full.json`, and add a row to this table.
5. Bound the cost: honour `$Context.LookbackStart`, `MaxEvents`, `MaxFiles`, `MaxDepth`. Use `$Context.CollectorNote` to record truncation or "not present".
6. Use `Get-IRFileFacts` for anything with an image path so hashing/signing is cached and consistent.
7. Add a heuristic to `Get-IRTriageLeads` (shared/IRAnalysis.ps1) and a diff rule to `Compare-Triage.ps1` if the artifact is persistence or accounts.
