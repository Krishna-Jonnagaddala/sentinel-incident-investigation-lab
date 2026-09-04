# Sample Events

A few representative raw records from the incident window, so the queries in this repo have
something concrete to map to. These are trimmed to the fields that matter and are lab data
(the "malicious" traffic is from the simulation scripts). Not a full export — just enough to
show the shape of what the detections parse.

- `4625-failed-rdp-logon.json` — one of the 214 failed RDP logons.
- `4624-successful-rdp-logon.json` — the successful logon that landed.
- `sysmon-1-powershell.xml` — the encoded PowerShell process-create event.
- `sysmon-3-beacon.xml` — one of the C2 beacon network-connect events.
- `syslog-ssh-failed.log` — the failed SSH pivot attempts on WEB-SRV-02.
