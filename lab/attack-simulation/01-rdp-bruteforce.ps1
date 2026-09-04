<#
    01-rdp-bruteforce.ps1
    Generates a run of failed RDP logons followed by one success, so the lab's
    "Brute Force Followed by Successful Interactive Logon" rule has something to fire on.

    LAB ONLY. Run from the attacker source against a workstation you own. This does not
    crack anything: you supply the wrong passwords and the one correct password. It just
    drives real logon attempts so the Security log records genuine 4625/4624 events.

    Uses the credential-validation path (LogonUser via the RDP service is simulated here
    by repeated authenticated connection attempts). For a true LogonType 10 trail, drive
    an actual mstsc/xfreerdp session; this script's purpose is to produce the event volume
    and pattern.
#>

param(
    [string] $Target       = "10.10.20.45",     # FIN-WKS-04
    [string] $Domain       = "CORP",
    [string[]] $Accounts   = @("administrator", "svc_backup", "a.patel"),
    [int]    $Attempts     = 214,
    [string] $GoodUser     = "a.patel",
    [string] $GoodPassword = ""                  # supply the real lab password to land the success
)

Write-Host "[*] Starting brute-force simulation against $Target" -ForegroundColor Cyan
Write-Host "[*] This generates FAILED logons on purpose. Lab use only." -ForegroundColor Yellow

$rng = New-Object System.Random
1..$Attempts | ForEach-Object {
    $user = $Accounts[$rng.Next(0, $Accounts.Count)]
    $wrongPassword = "Winter2024!$($rng.Next(1000,9999))"
    try {
        # Attempt a network authentication with a deliberately wrong password.
        $cred = New-Object System.Management.Automation.PSCredential(
            "$Domain\$user",
            (ConvertTo-SecureString $wrongPassword -AsPlainText -Force))
        # A failed authentication here produces a 4625 on the target.
        Invoke-Command -ComputerName $Target -Credential $cred -ScriptBlock { $true } -ErrorAction Stop | Out-Null
    } catch {
        # Expected: authentication failure. Keep going.
    }
    if ($_ % 25 -eq 0) { Write-Host "    ...$_ attempts" -ForegroundColor DarkGray }
    Start-Sleep -Milliseconds ($rng.Next(80, 220))
}

Write-Host "[*] Failed-attempt phase complete ($Attempts attempts)." -ForegroundColor Cyan

if ($GoodPassword) {
    Write-Host "[*] Attempting the 'landed' logon as $Domain\$GoodUser" -ForegroundColor Cyan
    $good = New-Object System.Management.Automation.PSCredential(
        "$Domain\$GoodUser",
        (ConvertTo-SecureString $GoodPassword -AsPlainText -Force))
    try {
        Invoke-Command -ComputerName $Target -Credential $good -ScriptBlock {
            Write-Output "session established on $env:COMPUTERNAME"
        } -ErrorAction Stop
        Write-Host "[+] Success logon generated (4624)." -ForegroundColor Green
    } catch {
        Write-Host "[!] Success logon failed - check the lab password / connectivity." -ForegroundColor Red
    }
} else {
    Write-Host "[i] No GoodPassword supplied; skipping the success step." -ForegroundColor DarkYellow
    Write-Host "[i] Re-run with -GoodPassword '<lab password>' to land the 4624." -ForegroundColor DarkYellow
}
