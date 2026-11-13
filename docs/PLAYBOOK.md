# Analyst playbook: suspected compromised Windows endpoint

A shared, repeatable first hour so every analyst collects the same evidence the same way.

## 0. Before touching the host
- Open or attach to the incident ticket. Its ID is the `-CaseId` for everything below.
- Decide **contain first or collect first**. If there is active C2 or spread, isolate through the EDR first. Live response
  still works on isolated hosts in MDE, CrowdStrike and S1, and network collectors still show the connections that were open.
- Don't log on interactively to the suspect host with privileged credentials.

## 1. Quick triage (minutes)
1. Run the **quick** profile through EDR live response ([EDR-DEPLOY.md](EDR-DEPLOY.md)).
2. Retrieve the zip into `cases\<CaseId>\` and check its hash against the `IRTRIAGE_RESULT` line.
3. Open `report.html` from the zip (or `<name>-report.html` beside it). To add the baseline diff, rebuild it:
   ```powershell
   .\analyst\ConvertTo-TriageReport.ps1 -Path .\cases\INC-1042\WS-0193.zip -BaselinePath .\baselines\win11-23h2.zip -Open
   ```
   In the report's tables, drag a column edge to resize it, and double-click the edge to fit the column on one line (double-click again to wrap).
4. Work the **High** leads first, then **Review**. Leads are prompts, not verdicts: confirm each with the raw JSON/CSV,
   EDR telemetry and the user's context.

## 2. Scope (tens of minutes)
- Pivot on what you found across the fleet:
  ```powershell
  .\analyst\Find-IOC.ps1 -Path .\cases\INC-1042\*.zip -IocFile .\cases\INC-1042\iocs.csv
  ```
- Run the quick profile on related hosts (same user, same subnet, hosts it connected to over SMB/RDP) with
  `Invoke-FleetTriage.ps1`. Add every confirmed indicator to `iocs.csv` (`Type,Value,Description`).

## 3. Deepen (confirmed suspicious host)
- Run **standard** for event logs, Defender state/exclusions and signer checks, or **full** for prefetch,
  recently written executables and browser extensions.
- Compare with the baseline again. Persistence that is *Added* relative to the gold image is the shortlist.

## 4. Evidence handling
- Keep the original zips and `.sha256` files read-only in the case folder. Work on extracted copies (the analyst
  scripts extract to a temp folder automatically and never modify the zip).
- The `manifest.json` in each zip records who requested the collection, the account it ran as, the tool version and
  build hash, and a SHA-256 for every file. Put the zip hash in the ticket.
- Triage is *not* a forensic image. If the case may go to legal or HR, escalate to full disk/memory acquisition per policy
  **before** remediation changes the host.

## 5. Event log retention
Windows defaults are small: PowerShell/Operational is 15 MB, which large scripts can fill within hours. A full circular log overwrites its oldest
events, so a quiet log may only be an emptied one. The report raises a review lead whenever a log does not reach back to the lookback
start. Fix it at the source with GPO (*Computer Configuration > Administrative Templates > Windows Components > Event Log Service*
for Security/System, and `wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:<bytes>` or your EDR/SIEM policy for PowerShell):
size Security, System and PowerShell/Operational in the hundreds of MB, and forward them to the SIEM so retention does not depend on the endpoint.

## 6. Baselines
Keep a known-good collection for each standard build (`baselines\<build>.zip`), collected with the same profile from a
freshly imaged machine that has the standard agent stack. Refresh it after each image or feature update. Without
a baseline the diff is noise; with one, it is usually a short list.

## Severity guide for leads
| Severity | Meaning | Examples |
|---|---|---|
| **high** | Rarely benign. Investigate now. | Encoded/download-cradle command lines, Office spawning a shell, LOLBin with external connections, WMI consumers, Defender RTP off, log cleared, account added to admin group |
| **review** | Often benign, but attackers use it too. | Binaries in user-writable paths, unsigned services, non-Microsoft tasks, Defender exclusions, hosts-file entries, burst of failed logons |
| **info** | Context. | Listening ports, local admins, remote logons, external connections from normal apps |
