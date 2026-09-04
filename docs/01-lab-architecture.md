# Lab Architecture

## Goal

Reproduce the telemetry a small enterprise would generate around an RDP-based intrusion,
and pipe it into Microsoft Sentinel so I can build detections against it and practice the
full investigation. Two endpoints is enough to cover identity, endpoint, and network
signal, plus one lateral-movement hop.

## Topology

```
                          Internet
                             │
                     (NAT / test rule)
                             │
                    ┌────────┴─────────┐
                    │   Lab firewall   │   RDP 3389 → FIN-WKS-04 (test only)
                    └────────┬─────────┘
                             │
        10.10.20.0/24  ──────┼───────────────────────────────
             │               │                 │
        ┌────┴────┐     ┌─────┴──────┐    ┌─────┴──────┐
        │  DC01   │     │ FIN-WKS-04 │    │ WEB-SRV-02 │
        │ .10     │     │ .45        │    │ .60        │
        │ AD DS   │     │ Win 11     │    │ Ubuntu 22  │
        └────┬────┘     └─────┬──────┘    └─────┬──────┘
             │                │                 │
             └────────────────┼─────────────────┘
                              │  Azure Monitor Agent + DCRs
                              ▼
                    ┌───────────────────────┐
                    │  Log Analytics         │
                    │  workspace law-soc-lab │
                    │  ├ SecurityEvent       │
                    │  ├ Event (Sysmon)      │
                    │  ├ Syslog              │
                    │  └ Heartbeat           │
                    └───────────┬───────────┘
                                ▼
                     ┌────────────────────┐
                     │ Microsoft Sentinel │
                     │ analytics rules,   │
                     │ incidents, hunting │
                     └────────────────────┘
```

RDP is exposed to the internet **only** for the duration of the test, behind a firewall
rule scoped to the simulation source. This is deliberately the bad configuration the
scenario is about; it is not how the lab sits at rest.

## Data flow

| Source | Agent | DCR | Destination table |
|---|---|---|---|
| Windows Security log | AMA | `dcr-win-security` | `SecurityEvent` |
| Sysmon (`Microsoft-Windows-Sysmon/Operational`) | AMA | `dcr-win-sysmon` | `Event` |
| Linux auth (`auth`, `authpriv`) | AMA | `dcr-linux-syslog` | `Syslog` |
| Agent health | AMA | (built-in) | `Heartbeat` |

Windows Security auditing is filtered at the DCR to the event IDs the detections need
(4624, 4625, 4672, 4688) rather than shipping the whole log; this keeps ingest cost sane
in a lab and still covers logon and process-creation auditing. Sysmon is collected whole
because the config file already scopes what gets recorded on the endpoint.

## What each host contributes

- **DC01** — Kerberos/NTLM authentication context and account state. In this case the
  brute force is a local RDP logon rather than domain auth, so DC01 is mostly used to
  confirm the account is a normal domain user and to check for follow-on domain activity.
- **FIN-WKS-04** — the compromised host. Primary source of evidence: logon events,
  process creation (Sysmon + 4688), file writes, DNS, and network connections.
- **WEB-SRV-02** — the lateral-movement target. Contributes SSH auth failures that let me
  confirm the pivot attempt and that it did not succeed.

## Threat model for the scenario

A single external actor with no prior foothold, targeting an internet-reachable RDP
service. Objective: interactive access, then tooling download and C2. The scenario
intentionally uses valid-credential access (not an exploit) because that's the common,
noisy-then-quiet pattern SOCs actually see, and it forces the investigation to reason
about "is this the real user or not?" rather than relying on a malware signature.

Out of scope for this lab: persistence mechanisms beyond the initial session, privilege
escalation, and data exfiltration. Those are natural next iterations and are noted in the
incident report under follow-ups.
