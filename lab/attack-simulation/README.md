# Attack Simulation

These scripts generate the telemetry the investigation is built on. They reproduce the
*technique* — and therefore the log events — of the intrusion, without doing anything
actually malicious. Read this before you run any of them.

## What's real and what's a stand-in

| Step | Real technique | What the script actually does |
|---|---|---|
| RDP brute force | Repeated failed RDP logons | Real failed logons against a lab account you set up; generates genuine `4625` events. No exploit, no cracking of a real credential — you tell it a wrong password on purpose, then the known good one. |
| Post-access PowerShell | Encoded download cradle + beacon | Runs a real encoded PowerShell command so Sysmon 1 records it, but it downloads a **benign** text file from a host you control and "beacons" to a listener you run. No malware. |
| SSH pivot | SSH lateral movement | Real SSH connection attempts from the workstation to the Linux host with a wrong password; generates genuine `Failed password` Syslog entries. |

The point is that the detections and the investigation should not be able to tell the
difference at the log level — the events are indistinguishable from the real thing, which
is exactly what makes them useful for practicing detection and triage. The payload and C2
are declawed so nothing dangerous runs.

## Safety rules

- **Lab only.** Run these against machines you own in an isolated network. Never point the
  brute-force or SSH scripts at anything you don't control.
- The "C2" destination (`185.220.101.47`) and domain (`cdn-telemetry.net`) are placeholders
  used in the docs. In your run, replace them with a listener/host you control (e.g. a lab
  VM running a simple HTTPS listener) or a DNS sinkhole you own. Don't send lab traffic to
  a stranger's IP just because it's written here.
- Remove the internet-facing RDP rule as soon as the brute-force step is done.

## Run order

1. `01-rdp-bruteforce.ps1` — from the "attacker" source, against `FIN-WKS-04`. Produces the
   `4625` storm and one `4624` success.
2. `02-post-access.ps1` — on `FIN-WKS-04`, in the session opened by step 1. Produces the
   PowerShell execution, download, file write, DNS, and beacon events.
3. `03-ssh-pivot.sh` — from `FIN-WKS-04` toward `WEB-SRV-02`. Produces the failed SSH
   Syslog entries.

Give Sentinel one rule interval after step 1–2 and the *Brute Force Followed by Successful
Interactive Logon* incident should appear.
