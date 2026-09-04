# Lab Setup

Notes for rebuilding the lab from scratch. This is not a click-by-click Azure tutorial;
it's the set of decisions and settings that matter for the detections and the case to
work. Where a portal step is obvious I've left it out.

## 1. Workspace and Sentinel

1. Create a Log Analytics workspace `law-soc-lab` (pick the region closest to you; a lab
   can sit on the pay-as-you-go tier and stay near-free at this volume).
2. Enable Microsoft Sentinel on the workspace.
3. Set the workspace data retention to 90 days so historical hunting queries have
   something to hit. Interactive retention of 30 days is fine if cost is a concern.

## 2. Endpoints

Three VMs, all with the Azure Monitor Agent installed and associated to the DCRs below.

- `DC01` — Windows Server, AD DS, one domain `CORP`.
- `FIN-WKS-04` — Windows 11, domain-joined, a standard user `CORP\a.patel` who is a local
  admin on their own workstation (common in the wild, and the reason the post-access
  PowerShell runs without a UAC fight).
- `WEB-SRV-02` — Ubuntu 22.04, OpenSSH server, nginx. Password auth left enabled for the
  pivot test.

Create the service account `CORP\svc_backup` so the brute force has a realistic
service-account target to spray, and leave it non-privileged.

## 3. Windows audit policy

The detections depend on logon and process auditing being on. On the workstation (via GPO
in a domain, or `auditpol` locally for the lab):

```
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

Enable command-line auditing so 4688 carries the full command line (Sysmon also captures
this, but having both is useful for cross-checking):

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

## 4. Sysmon

Install Sysmon on both Windows hosts with the config in
[`../lab/sysmon/sysmon-config.xml`](../lab/sysmon/sysmon-config.xml):

```
sysmon64.exe -accepteula -i sysmon-config.xml
```

The config is a trimmed SwiftOnSecurity base, kept to the event types this case uses:
process creation (1), network connect (3), file create (11), and DNS query (22). Confirm
events are flowing:

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize count() by EventID
| order by EventID asc
```

## 5. Data Collection Rules

**`dcr-win-security`** — Windows Event Logs data source, Security channel, with an XPath
filter so only the event IDs used here are ingested:

```
Security!*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688)]]
```

**`dcr-win-sysmon`** — Windows Event Logs data source, custom channel
`Microsoft-Windows-Sysmon/Operational`, no XPath filter (the Sysmon config already scopes
it). Lands in `Event`.

**`dcr-linux-syslog`** — Linux Syslog data source, facilities `auth` and `authpriv` at
`LOG_INFO` and above. Lands in `Syslog`.

Associate all three to the appropriate VMs. Give it ~15 minutes and verify each table has
rows plus a recent `Heartbeat` from every host.

## 6. Analytics rules

Import the four rules from [`../detections/`](../detections). Each `.kql` file is the rule
query; the rule metadata (schedule, threshold, entity mapping) is documented in
[`../detections/README.md`](../detections/README.md). The one that raises the incident for
this case is `02-bruteforce-then-success.kql`, run on a 5-minute schedule over a
1-hour lookback.

## 7. Run the simulation

From an isolated lab jump box (or the firewall's allowed test source), run the scripts in
[`../lab/attack-simulation/`](../lab/attack-simulation) in order. Read that folder's README
first — the scripts are safe stand-ins, but you should understand what they touch before
running them. After the second script, an incident should appear in Sentinel within one
rule interval.

## Teardown

Deallocate the VMs when you're done, and remove the internet-facing RDP rule immediately
after the test regardless of whether you tear down the rest. Leaving 3389 open to the
internet is the whole point of the scenario and not something to forget running.
