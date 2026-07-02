<#
.SYNOPSIS
    Log into a ZTE ZXHN H188A (Vodafone) router and list connected devices
    WITH their real names (HostName), IP, MAC, band and link speed.

.DESCRIPTION
    Reproduces the router's web-login handshake:
      1. GET  /?_type=loginData&_tag=login_entry   -> sess_token (+ SID cookie)
      2. GET  /?_type=loginData&_tag=login_token   -> one-time token
      3. POST /?_type=loginData&_tag=login_entry    with SHA256(password + token)
    then loads the Local-Network status view (to set page context) and reads the
    attached-device tables (Wi-Fi + wired).

    The password is NEVER stored in this file. Provide it with -Password, or via
    a local credential file (see -CredFile), or you'll be prompted securely.

    Use only on a network/router you own or are authorized to administer.

.EXAMPLE
    ./router-devices.ps1                       # prompts for password securely
    ./router-devices.ps1 -Password 'mypass'    # non-interactive
    ./router-devices.ps1 -SaveCred             # save an encrypted cred for next time
#>

param(
    [string]$Router   = "192.168.1.1",
    [string]$User     = "vodafone",
    [string]$Password,
    # DPAPI-encrypted credential file (user+machine bound). Default lives in your profile, NOT the repo.
    [string]$CredFile = "$HOME\.zte-router.cred",
    # Save the supplied/prompted password to $CredFile (encrypted) and exit-friendly for reuse.
    [switch]$SaveCred
)

# ---------------------------------------------------------------------------
function Get-Sha256Hex([string]$s) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
}

# --- Resolve the password without ever hardcoding it -----------------------
if (-not $Password) {
    if (Test-Path $CredFile) {
        try {
            $sec = Import-Clixml $CredFile
            $Password = [System.Net.NetworkCredential]::new('', $sec).Password
            Write-Host "Using saved credential ($CredFile)" -ForegroundColor DarkGray
        } catch { Write-Warning "Could not read $CredFile ($($_.Exception.Message))." }
    }
    if (-not $Password) {
        $sec = Read-Host "Router password for '$User'" -AsSecureString
        $Password = [System.Net.NetworkCredential]::new('', $sec).Password
    }
}
if ($SaveCred) {
    ($Password | ConvertTo-SecureString -AsPlainText -Force) | Export-Clixml $CredFile
    Write-Host "Saved encrypted credential to $CredFile (only your Windows account can read it)." -ForegroundColor Green
}

$base = "http://$Router"
$req  = @{ SkipCertificateCheck = $true; TimeoutSec = 12 }

# --- 1. Login handshake ----------------------------------------------------
try {
    $r1 = Invoke-WebRequest "$base/?_type=loginData&_tag=login_entry" -SessionVariable S @req
    $sess = ($r1.Content | ConvertFrom-Json).sess_token
    $r2 = Invoke-WebRequest "$base/?_type=loginData&_tag=login_token" -WebSession $S @req
    $token = ([regex]::Match($r2.Content, '>([^<]+)<')).Groups[1].Value
    $body = @{ Username = $User; Password = (Get-Sha256Hex($Password + $token)); _sessionTOKEN = $sess; action = "login" }
    $r3 = Invoke-WebRequest "$base/?_type=loginData&_tag=login_entry" -Method POST -Body $body -WebSession $S @req
    $login = $r3.Content | ConvertFrom-Json
} catch {
    Write-Error "Could not reach the router at $base ($($_.Exception.Message)). Check -Router."
    return
}
if (-not $login.login_need_refresh) {
    Write-Error "Login failed - wrong username/password (or the account is temporarily locked after retries)."
    return
}
Write-Host "Logged in to $Router as '$User'." -ForegroundColor Green

# --- 2. Establish page context, then read device tables --------------------
$hdr = @{ Referer = "$base/" }
Invoke-WebRequest "$base/" -WebSession $S @req | Out-Null
Invoke-WebRequest "$base/?_type=menuView&_tag=localNetStatus&Menu3Location=0" -WebSession $S -Headers $hdr @req | Out-Null

function Get-DeviceTable([string]$tag) {
    $r = Invoke-WebRequest "$base/?_type=menuData&_tag=$tag" -WebSession $S -Headers $hdr @req
    $devices = @()
    foreach ($inst in [regex]::Matches($r.Content, '<Instance>(.*?)</Instance>', 'Singleline')) {
        $names  = [regex]::Matches($inst.Groups[1].Value, '<ParaName>(.*?)</ParaName>')
        $values = [regex]::Matches($inst.Groups[1].Value, '<ParaValue>(.*?)</ParaValue>')
        $h = @{}
        for ($i = 0; $i -lt $names.Count; $i++) { $h[$names[$i].Groups[1].Value] = $values[$i].Groups[1].Value }
        $devices += [PSCustomObject]$h
    }
    $devices
}

$wifi  = Get-DeviceTable "accessdev_ssiddev_lua.lua"   # wireless clients
$wired = Get-DeviceTable "accessdev_landevs_lua.lua"   # ethernet clients

# --- 3. Normalise + display ------------------------------------------------
$all = @()
$all += $wifi  | ForEach-Object { [PSCustomObject]@{
    Name  = $_.HostName; IP = $_.IPAddress; MAC = $_.MACAddress
    Conn  = "Wi-Fi ($($_.AliasName))"; SpeedMbps = if ($_.AssocRate) { [int]$_.AssocRate / 1000 } else { $null } } }
$all += $wired | ForEach-Object { [PSCustomObject]@{
    Name  = $_.HostName; IP = $_.IPAddress; MAC = $_.MACAddress
    Conn  = "Wired"; SpeedMbps = $null } }

# Drop empty slots the router pads its tables with (no MAC = not a real client)
$all = $all | Where-Object { $_.MAC -match '[0-9a-fA-F]' }
if (-not $all) { Write-Host "No connected devices reported." -ForegroundColor Yellow; return }

$all | Sort-Object { [int](($_.IP -split '\.')[-1]) } |
    Format-Table Name, IP, MAC, Conn, SpeedMbps -AutoSize

Write-Host ("`n{0} device(s) connected." -f $all.Count) -ForegroundColor Green
Write-Host "Tip: recognise each Name. Unknown ones = guests/intruders -> change Wi-Fi password in the router." -ForegroundColor DarkGray
