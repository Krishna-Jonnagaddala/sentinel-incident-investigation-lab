# MITRE ATT&CK Mapping: INC-2024-0417

Techniques observed in this incident, each tied to the specific evidence that supports it.
I only map techniques I can point at evidence for; anything inferred but not observed is
called out as such so the mapping stays honest.

| Tactic | Technique | ID | Evidence in this case |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | 214× `4625` (LogonType 10) from `45.155.205.233`, 02:14–02:48, `SubStatus 0xC000006A` against `administrator`, `svc_backup`, `a.patel` |
| Initial Access | Valid Accounts | T1078 | `4624` LogonType 10 as `CORP\a.patel` from the same source IP at 02:49:11, immediately after the brute force stopped |
| Initial Access / Lateral Movement | Remote Services: RDP | T1021.001 | Logon via `LogonType 10` (RemoteInteractive) on an internet-exposed 3389 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Sysmon 1: `powershell.exe -nop -w hidden -enc <base64>`, parent `explorer.exe`, 02:52:18 |
| Defense Evasion | Obfuscated/Encoded Command | T1027 / T1140 | `-enc` base64 command line; decoded to an `IEX (New-Object Net.WebClient).DownloadString(...)` cradle |
| Command and Control | Ingress Tool Transfer | T1105 | Sysmon 3: `powershell.exe` → `185.220.101.47:80`; Sysmon 11: `...\Temp\update.ps1` written 02:52:55 |
| Command and Control | Application Layer Protocol: Web | T1071.001 | Sysmon 22 DNS `cdn-telemetry.net`; Sysmon 3 repeating → `185.220.101.47:443` at ~60s interval |
| Lateral Movement | Remote Services: SSH | T1021.004 | Syslog on `WEB-SRV-02`: `Failed password` from `10.10.20.45` at 03:05:44 (attempt failed) |

## Notes on the mapping

- **T1078 vs an exploit.** Access was gained with a guessed-then-valid credential, not a
  vulnerability. That's why this maps to Valid Accounts and not Exploit Public-Facing
  Application. It matters for response: the fix is credential and exposure hygiene, not a
  patch.
- **Masquerading (T1036).** The staged file is `update.ps1` and the beacon domain is
  `cdn-telemetry[.]net` — both chosen to blend in. I'd note this as *weakly observed*: the
  naming is suggestive but I didn't confirm intent, so I'm not asserting T1036 as
  confirmed.
- **Beaconing regularity.** The ~60s fixed interval to a single destination (T1071.001) is
  the network behavior that most cleanly separates this from benign PowerShell. It's the
  strongest single indicator of C2 in the dataset.
- **What I did not observe.** No persistence mechanism (no run key, scheduled task, or
  service creation appeared in Sysmon/4688 within the window), no privilege escalation
  beyond the user's existing local-admin rights, and no data staging or exfiltration. The
  SSH pivot failed, so no lateral movement completed. These gaps are stated in the incident
  report rather than papered over.

## Detection coverage

Each detection in [`../detections/`](../detections) maps to one or more of the above:

- `01-rdp-bruteforce.kql` → T1110.001
- `02-bruteforce-then-success.kql` → T1110.001 + T1078 (the correlation is the value)
- `03-suspicious-powershell.kql` → T1059.001, T1027, T1105
- `04-c2-beaconing.kql` → T1071.001
