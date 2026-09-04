# Data Sources

The tables and fields the investigation relies on, and how to read the ones that aren't
self explanatory. Written so someone picking up the case can follow the KQL without
guessing what a column means.

## SecurityEvent

Windows Security log. The case uses four event IDs.

| EventID | Meaning | Key fields |
|---|---|---|
| 4625 | Failed logon | `Account`, `TargetUserName`, `IpAddress`, `LogonType`, `Computer`, `SubStatus` |
| 4624 | Successful logon | `Account`, `TargetUserName`, `IpAddress`, `LogonType`, `LogonProcessName` |
| 4672 | Special privileges assigned to new logon | `Account`, `PrivilegeList` |
| 4688 | Process creation | `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName` |

**LogonType** is the field that carries most of the meaning here:

- `2` - interactive (at the console)
- `3` - network (SMB, etc.)
- `10` - RemoteInteractive (**RDP**) ← the one in this case
- `5` - service

A brute force over RDP shows up as repeated `4625` with `LogonType == 10`. If you see the
same pattern with `LogonType == 3`, you're looking at network logons (often SMB or
WinRM), which changes the story.

**SubStatus** on 4625 tells you *why* it failed. `0xC000006A` is bad password (account
exists), `0xC0000064` is bad username (account doesn't exist). A run of `0xC000006A`
against one account means someone knows the account is real and is guessing its password.

## Event (Sysmon)

Sysmon writes to the generic `Event` table. Filter with
`Source == "Microsoft-Windows-Sysmon"` and the fields live inside the `EventData` XML
blob, which I parse out with `parse ... with`.

| EventID | Meaning | Parsed fields used |
|---|---|---|
| 1 | Process create | `Image`, `CommandLine`, `ParentImage`, `User`, `Hashes` |
| 3 | Network connect | `Image`, `DestinationIp`, `DestinationPort`, `Protocol` |
| 11 | File create | `Image`, `TargetFilename` |
| 22 | DNS query | `Image`, `QueryName`, `QueryResults` |

Why Sysmon on top of 4688: Sysmon 1 carries the parent process image and file hashes,
which 4688 doesn't give you cleanly, and Sysmon 3/22 give network and DNS visibility the
Security log has no equivalent for. The download and beacon in this case are only visible
because of Sysmon 3 and 22.

Example of pulling command lines out of Sysmon 1:

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| parse EventData with * '<Data Name="CommandLine">' CommandLine '</Data>' *
| parse EventData with * '<Data Name="ParentImage">' ParentImage '</Data>' *
| project TimeGenerated, Computer, Image, CommandLine, ParentImage
```

## Syslog

Linux `auth`/`authpriv`. Used for the SSH pivot.

| Field | Use |
|---|---|
| `Facility` | `auth` / `authpriv` |
| `SyslogMessage` | full message text; grep for `Failed password`, `Accepted password`, `Invalid user` |
| `HostName` | source host (`WEB-SRV-02`) |

SSH failures look like:
`Failed password for a.patel from 10.10.20.45 port 51824 ssh2`. The important part for
the case is the source IP `10.10.20.45` - that's `FIN-WKS-04`, so the pivot is coming
*from* the compromised workstation.

## Heartbeat

Used only to confirm every host is actually reporting during the incident window, so I
don't mistake a silent host for a clean one. A gap in `Heartbeat` for a host means missing
telemetry, not absence of activity.

```kusto
Heartbeat
| where TimeGenerated between (datetime(2024-04-17 02:00) .. datetime(2024-04-17 04:00))
| summarize LastSeen = max(TimeGenerated) by Computer
```
