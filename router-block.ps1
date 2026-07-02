<#
.SYNOPSIS
    Semi-automatic device blocking for a ZTE ZXHN H188A (Vodafone) router.

.DESCRIPTION
    Logs into the router, prints the current connected-device list (highlighting
    the device you intend to block so you can confirm its exact MAC), then opens
    the router's web UI in your default browser and shows the exact click-path to
    the WLAN MAC-filter / Access-Control page where you press "Block".

    Blocking itself is done by you in the browser (one click) -- this avoids the
    router's fragile encrypted-write API while still doing all the tedious parts
    (login, finding the device, opening the page) for you.

    Password is NEVER stored here (see router-devices.ps1 for the -Password /
    -CredFile / secure-prompt options; the same rules apply).

.EXAMPLE
    ./router-block.ps1                                   # list devices, open router
    ./router-block.ps1 -Target e2:bc:36:01:47:de         # highlight this MAC
    ./router-block.ps1 -Target realme                    # highlight by name match
#>

param(
    [string]$Router   = "192.168.1.1",
    [string]$User     = "vodafone",
    [string]$Password,
    [string]$CredFile = "$HOME\.zte-router.cred",
    # MAC (any separator) or a substring of the device name to highlight as the block target.
    [string]$Target
)

function Get-Sha256Hex([string]$s) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
}
function Normalize-Mac([string]$m) { ($m -replace '[^0-9a-fA-F]','').ToLower() }

# --- Resolve password without hardcoding -----------------------------------
if (-not $Password) {
    if (Test-Path $CredFile) {
        try { $Password = [System.Net.NetworkCredential]::new('', (Import-Clixml $CredFile)).Password } catch {}
    }
    if (-not $Password) {
        $sec = Read-Host "Router password for '$User'" -AsSecureString
        $Password = [System.Net.NetworkCredential]::new('', $sec).Password
    }
}

$base = "http://$Router"; $req = @{ SkipCertificateCheck = $true; TimeoutSec = 12 }

# --- Login ------------------------------------------------------------------
try {
    $r1 = Invoke-WebRequest "$base/?_type=loginData&_tag=login_entry" -SessionVariable S @req
    $sess = ($r1.Content | ConvertFrom-Json).sess_token
    $r2 = Invoke-WebRequest "$base/?_type=loginData&_tag=login_token" -WebSession $S @req
    $token = ([regex]::Match($r2.Content, '>([^<]+)<')).Groups[1].Value
    $body = @{ Username = $User; Password = (Get-Sha256Hex($Password + $token)); _sessionTOKEN = $sess; action = "login" }
    $login = (Invoke-WebRequest "$base/?_type=loginData&_tag=login_entry" -Method POST -Body $body -WebSession $S @req).Content | ConvertFrom-Json
} catch { Write-Error "Cannot reach router at $base ($($_.Exception.Message))."; return }
if (-not $login.login_need_refresh) { Write-Error "Login failed - check username/password."; return }

# --- Read device list (Wi-Fi + wired) --------------------------------------
$hdr = @{ Referer = "$base/" }
Invoke-WebRequest "$base/" -WebSession $S @req | Out-Null
Invoke-WebRequest "$base/?_type=menuView&_tag=localNetStatus&Menu3Location=0" -WebSession $S -Headers $hdr @req | Out-Null
function Get-DeviceTable([string]$tag) {
    $r = Invoke-WebRequest "$base/?_type=menuData&_tag=$tag" -WebSession $S -Headers $hdr @req
    foreach ($inst in [regex]::Matches($r.Content, '<Instance>(.*?)</Instance>', 'Singleline')) {
        $names  = [regex]::Matches($inst.Groups[1].Value, '<ParaName>(.*?)</ParaName>')
        $values = [regex]::Matches($inst.Groups[1].Value, '<ParaValue>(.*?)</ParaValue>')
        $h = @{}; for ($i=0; $i -lt $names.Count; $i++) { $h[$names[$i].Groups[1].Value] = $values[$i].Groups[1].Value }
        [PSCustomObject]@{ Name=$h.HostName; IP=$h.IPAddress; MAC=$h.MACAddress; Conn=if($h.AliasName){"Wi-Fi ($($h.AliasName))"}else{"Wired"} }
    }
}
$devs = @(Get-DeviceTable "accessdev_ssiddev_lua.lua") + @(Get-DeviceTable "accessdev_landevs_lua.lua")
$devs = $devs | Where-Object { $_.MAC -match '[0-9a-fA-F]' } | Sort-Object { [int](($_.IP -split '\.')[-1]) }

# --- Display, highlight the target -----------------------------------------
$tgtNorm = if ($Target) { Normalize-Mac $Target } else { $null }
Write-Host "`nConnected devices:" -ForegroundColor Cyan
$i = 0
foreach ($d in $devs) {
    $i++
    $isTarget = $Target -and ( (Normalize-Mac $d.MAC) -eq $tgtNorm -or $d.Name -like "*$Target*" )
    $line = "{0,2}. {1,-18} {2,-14} {3,-18} {4}" -f $i, $d.Name, $d.IP, $d.MAC, $d.Conn
    if ($isTarget) { Write-Host "  >> $line   <-- BLOCK THIS" -ForegroundColor Yellow }
    else           { Write-Host "     $line" -ForegroundColor Gray }
}

if ($Target) {
    $match = $devs | Where-Object { (Normalize-Mac $_.MAC) -eq $tgtNorm -or $_.Name -like "*$Target*" } | Select-Object -First 1
    if ($match) {
        Write-Host ("`nTarget: {0}  ({1})  MAC {2}" -f $match.Name, $match.IP, $match.MAC) -ForegroundColor Yellow
    } else {
        Write-Host "`nNote: '$Target' is not in the current list (device may be offline; you can still add its MAC manually)." -ForegroundColor DarkYellow
    }
}

# --- Open router UI + print the click-path ---------------------------------
Write-Host "`nOpening the router in your browser..." -ForegroundColor Cyan
Start-Process $base

Write-Host @"

To BLOCK the device (one-time setup, then it's remembered):

  1. Log in  (user: $User)
  2. Go to:  Local Network  ->  WLAN  ->  Access Control  (a.k.a. "MAC Filter")
  3. Set the mode to:  Blacklist / Deny  (block listed MACs)
  4. Click Add, then either pick the device from the list or paste its MAC:
$(if($Target -and $match){"         $($match.MAC)   ($($match.Name))"}else{"         <the MAC from the list above>"})
  5. Apply / Save.  The device drops off Wi-Fi within a few seconds.

To UN-block later: remove that MAC from the same list (or switch mode back to Off).

Tip: to LIMIT speed instead of block, look under  Local Network -> WLAN -> QoS /
Bandwidth Control  (if your firmware exposes it) and add a rate cap for that MAC.
"@ -ForegroundColor Gray

# Warn if the target uses a randomized MAC (2nd hex digit is 2/6/A/E) -> block can be bypassed
if ($match) {
    $second = (Normalize-Mac $match.MAC).Substring(1,1)
    if ('2','6','a','e' -contains $second) {
        Write-Host @"

WARNING: $($match.Name)'s MAC ($($match.MAC)) is a RANDOMIZED / private MAC.
Blocking it works only until the phone rotates its MAC (e.g. toggling Wi-Fi).
For a durable block, on that phone turn OFF "Private/Random Wi-Fi address" for
this network first, then block its real (hardware) MAC.
"@ -ForegroundColor Red
    }
}
