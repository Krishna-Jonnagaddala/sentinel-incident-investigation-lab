# Incident Report: INC-2024-0417

| | |
|---|---|
| **Incident ID** | INC-2024-0417 (Sentinel incident 2417) |
| **Title** | Interactive compromise of FIN-WKS-04 via RDP brute force |
| **Severity** | High |
| **Classification** | True positive — confirmed intrusion |
| **Detected** | 2024-04-17 02:49 UTC |
| **Contained** | 2024-04-17 03:20 UTC |
| **Report author** | K. Jonnagaddala (SOC) |
| **Status** | Contained; follow-ups open |

## Executive summary

An external actor brute-forced Remote Desktop on an internet-exposed finance workstation
(`FIN-WKS-04`) and logged in with a guessed but valid credential for the user `a.patel`.
Within four minutes the actor ran an encoded PowerShell download cradle that pulled a
second-stage script from an external host and established a regular HTTPS beacon to a
command-and-control domain. The actor then attempted to move laterally to a Linux server
over SSH; that attempt failed. The workstation was isolated and the account disabled
approximately 31 minutes after detection.

Root cause was an internet-reachable RDP service protected only by a password. No exploit
or malware vulnerability was involved this was valid-credential access enabled by an
exposure and weak authentication.

## Impact

- One workstation (`FIN-WKS-04`) confirmed compromised for the duration of the session
  (02:49–03:20 UTC).
- One finance user credential (`CORP\a.patel`) compromised.
- Data and cached credentials on the workstation considered exposed for the session window.
- No confirmed spread: the SSH pivot to `WEB-SRV-02` failed, and no persistence, privilege
  escalation, or data exfiltration was observed within available telemetry.

## Timeline (UTC)

| Time | Event |
|---|---|
| 02:14:07 | Brute force begins — first failed RDP logon from `45.155.205.233`. |
| 02:14–02:48 | 214 failed RDP logons across `administrator`, `svc_backup`, `a.patel`. |
| 02:48:53 | Failed attempts stop. |
| 02:49:11 | Successful RDP logon as `CORP\a.patel` from `45.155.205.233`. |
| 02:52:18 | Encoded PowerShell executed (parent `explorer.exe`). |
| 02:52:41 | Outbound download connection to `185.220.101.47:80`. |
| 02:52:55 | Payload staged: `...\Temp\update.ps1`. |
| 02:53:20 | DNS query for `cdn-telemetry.net` → `185.220.101.47`. |
| 02:53:22+ | HTTPS beacon to `185.220.101.47:443`, ~60s interval. |
| 02:54 | Sentinel incident raised; analyst engaged. |
| 03:05:44 | Failed SSH logons on `WEB-SRV-02` from `10.10.20.45` (pivot attempt). |
| 03:20 | `FIN-WKS-04` isolated; `a.patel` disabled. |

## Detection

Raised by the scheduled analytics rule *Brute Force Followed by Successful Interactive
Logon*, which correlates a failed-RDP storm with a subsequent successful logon from the
same source IP against the same host. A standalone brute-force rule and a suspicious
PowerShell rule also fired and grouped onto the same host entity, corroborating the
incident. The correlation rule — not the raw brute-force count is what escalated this to
a page.

## Investigation summary

Full working notes, including every query, are in
[`../investigation/case-INC-2024-0417.md`](../investigation/case-INC-2024-0417.md).

1. **Authentication.** The successful logon came from the same external IP as the brute
   force, was an RDP (LogonType 10) logon with no precedent for this account, and did not
   match `a.patel`'s 30-day logon baseline. Assessed as attacker, not the legitimate user.
2. **Endpoint.** Post-logon, `explorer.exe` spawned hidden encoded PowerShell decoding to a
   `DownloadString` cradle; a second stage was written to the user's Temp directory.
3. **Network.** PowerShell downloaded from `185.220.101.47:80`, then beaconed to the same
   host on 443 at a low variance ~60s interval a command-and-control signature.
4. **Lateral movement.** Failed SSH password attempts on `WEB-SRV-02` originated from the
   compromised workstation; the pivot did not succeed.

## MITRE ATT&CK

T1110.001 → T1078 / T1021.001 → T1059.001 + T1027 → T1105 → T1071.001 → attempted
T1021.004. Evidence mapping in
[`../docs/mitre-attack-mapping.md`](../docs/mitre-attack-mapping.md).

## Indicators

See [`../investigation/iocs.md`](../investigation/iocs.md). Key: `45.155.205.233`,
`185.220.101.47`, `cdn-telemetry[.]net`, `...\Temp\update.ps1`.

## Response actions

**Taken during containment**

- Isolated `FIN-WKS-04` from the network (preserved for forensics, not powered off).
- Disabled `CORP\a.patel` and initiated a forced credential reset.
- Blocked `45.155.205.233` and `185.220.101.47` at the perimeter; denied `cdn-telemetry[.]net`.

**Recommended / follow-up**

- Remove internet-facing RDP from `FIN-WKS-04` and audit the estate for other exposed 3389.
- Full forensic review of the isolated host to confirm no persistence was established.
- Reset `svc_backup` as a precaution (brute-force target).
- Confirm `WEB-SRV-02` was not otherwise accessed; disable SSH password authentication.
- Enforce MFA and require RDP via a bastion; direct internet RDP should not be possible.
- Review the process that allowed a finance workstation to be internet-exposed.

## Lessons / detection improvements

- The correlation rule worked as intended and is the reason this was caught early. The
  standalone beacon rule (interval regularity) independently detects the C2 and should be
  kept as defense-in-depth against a slower brute force that stays under the correlation
  threshold.
- The single biggest risk reduction here is not a detection at all it's removing the RDP
  exposure and requiring MFA. Detection caught the intrusion in minutes; prevention would
  have stopped it entirely.

## Appendix

- Investigation case file: [`../investigation/case-INC-2024-0417.md`](../investigation/case-INC-2024-0417.md)
- Hunting queries: [`../investigation/hunting-queries.kql`](../investigation/hunting-queries.kql)
- Analytics rules: [`../detections/`](../detections)
- Representative raw events: [`../evidence/sample-events/`](../evidence/sample-events)
