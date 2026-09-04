# Detections

Four scheduled analytics rules. Each `.kql` file is the query you paste into the rule;
the table below is the rule config I used in the lab. Entity mapping is what lets Sentinel
build the incident graph and correlate the alerts into one incident.

| File | Rule name | Schedule | Lookback | Severity | Threshold | ATT&CK |
|---|---|---|---|---|---|---|
| `01-rdp-bruteforce.kql` | RDP Brute Force from Single Source | 15m | 1h | Medium | ≥15 failed 4625 (LogonType 10) per IP+host | T1110.001 |
| `02-bruteforce-then-success.kql` | Brute Force Followed by Successful Interactive Logon | 5m | 1h | High | ≥15 fails then a 4624 success, same IP+host | T1110.001, T1078 |
| `03-suspicious-powershell.kql` | Suspicious PowerShell Command Line | 15m | 1h | Medium | any match on encoded/download-cradle flags | T1059.001, T1027, T1105 |
| `04-c2-beaconing.kql` | Regular Outbound Beaconing | 1h | 4h | High | ≥10 connections, interval regularity < 0.25 | T1071.001 |

## Entity mapping (per rule, in the Sentinel rule wizard)

- **Rule 01 / 02** - Host: `Computer`; IP: `IpAddress`; Account: the compromised account
  column (rule 02 maps `CompromisedAccount`). Grouping these lets the brute-force alert and
  the success alert land in the same incident.
- **Rule 03** - Host: `Computer`; Account: `User`; Process: `Image`.
- **Rule 04** - Host: `Computer`; IP: `DestinationIp`.

Incident grouping is set to group alerts sharing the same Host entity within a
4-hour window, so the four alerts on `FIN-WKS-04` roll up into one incident instead of
paging four times for one intrusion.

## Design choices worth calling out

- **Rule 02 is the one that matters.** Rule 01 alone would fire constantly on internet
  background noise. The correlation in rule 02 - fail storm *then* success from the same
  source - is what turns "someone's knocking" into "someone got in", and it's the alert
  that opened the real investigation. This is the detection-engineering point of the whole
  lab: correlate, don't just count.
- **Beacon detection by interval regularity, not by IOC.** Rule 04 doesn't need to know
  the C2 address in advance. It finds the behavior (low variance connection interval to one
  destination), which means it would catch a beacon to an address not on any blocklist.
  The trade-off is tuning: `Regularity < 0.25` and `minConnections` need adjusting per
  environment, and long-lived legitimate connections (update pollers, telemetry agents)
  are the usual false positives to allowlist.
- **Sysmon parsing.** Rules 03 and 04 parse fields out of the `Event` table's `EventData`
  XML with `parse ... with`. If you collect Sysmon into a custom table or via MDE
  (`DeviceProcessEvents` / `DeviceNetworkEvents`) instead, swap the source and field names;
  the logic is the same.

## Known false-positive sources

- Rule 01/02: legitimate users failing RDP repeatedly then getting in (fat fingered
  password). Mitigated in rule 02 by the source-IP correlation and by reviewing whether the
  source is external.
- Rule 03: admin and CI tooling that legitimately uses `-nop`/`Invoke-WebRequest`.
  Allowlist by `ParentImage`/`User` for known automation.
- Rule 04: telemetry/update agents that poll on a fixed interval. Allowlist known
  destinations.
