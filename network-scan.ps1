<#
.SYNOPSIS
    Scan your local network and list every connected device.
.DESCRIPTION
    Auto-detects your subnet, ping-sweeps all 254 hosts in parallel, then reads
    the ARP table to collect IP + MAC + hostname for each device that responded.
    Use only on networks you own or are authorized to scan.
.EXAMPLE
    ./network-scan.ps1
    ./network-scan.ps1 -Subnet 192.168.0
#>

param(
    # First three octets of your network, e.g. "192.168.1". Auto-detected if omitted.
    [string]$Subnet,
    # Milliseconds to wait for each ping reply.
    [int]$TimeoutMs = 300
)

# --- 1. Figure out which subnet to scan ---------------------------------------
if (-not $Subnet) {
    $gw = (Get-NetIPConfiguration |
           Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
           Select-Object -First 1).IPv4DefaultGateway.NextHop
    if (-not $gw) {
        Write-Error "Could not auto-detect your gateway. Pass -Subnet manually, e.g. -Subnet 192.168.1"
        return
    }
    $Subnet = ($gw -split '\.')[0..2] -join '.'
    Write-Host "Detected gateway $gw -> scanning $Subnet.0/24" -ForegroundColor Cyan
} else {
    Write-Host "Scanning $Subnet.0/24" -ForegroundColor Cyan
}

# --- 2. Ping-sweep all 254 addresses in parallel ------------------------------
Write-Host "Pinging 254 hosts (timeout ${TimeoutMs}ms)..." -ForegroundColor Cyan
$ping = New-Object System.Net.NetworkInformation.Ping
$jobs = 1..254 | ForEach-Object {
    (New-Object System.Net.NetworkInformation.Ping).SendPingAsync("$Subnet.$_", $TimeoutMs)
}
[System.Threading.Tasks.Task]::WaitAll($jobs)

# --- 2b. Offline MAC -> vendor table (common home-device makers) --------------
# Keyed by the first 3 octets of the MAC (the OUI). Extend freely.
$Vendors = @{
    'D8-E8-44'='Router/ISP'; '00-1A-11'='Google'; '00-1D-D8'='Microsoft';
    'FC-FB-FB'='Apple'; '00-03-93'='Apple'; 'A4-83-E7'='Apple'; 'F0-18-98'='Apple';
    '3C-5A-B4'='Google'; 'DA-A1-19'='Google'; '00-1A-79'='TP-Link'; '50-C7-BF'='TP-Link';
    'B0-BE-76'='TP-Link'; 'AC-84-C6'='TP-Link'; '00-12-FB'='Samsung'; '00-15-99'='Samsung';
    '5C-0A-5B'='Samsung'; '78-BD-BC'='Samsung'; '00-24-E4'='Withings'; 'DC-A6-32'='RaspberryPi';
    'B8-27-EB'='RaspberryPi'; 'E4-5F-01'='RaspberryPi'; '00-50-56'='VMware'; '08-00-27'='VirtualBox';
    '00-1C-42'='Parallels'; 'AC-DE-48'='Apple'; 'F4-F5-D8'='Google'; '18-B4-30'='Nest';
    '00-17-88'='Philips-Hue'; 'EC-FA-BC'='Espressif-IoT'; '24-0A-C4'='Espressif-IoT';
    '00-1E-C2'='Apple'; '68-D9-3C'='Apple'; '8C-85-90'='Apple'; 'D0-03-4B'='Apple';
    '00-0C-29'='VMware'; '52-54-00'='QEMU-VM'
}
function Get-Vendor([string]$mac) {
    $oui = ($mac -split '-')[0..2] -join '-'
    if ($Vendors.ContainsKey($oui)) { $Vendors[$oui] } else { 'Unknown' }
}

# --- 2c. NetBIOS name lookup (catches Windows PCs, some phones) ----------------
function Get-NbName([string]$ip) {
    try {
        $out = nbtstat -A $ip 2>$null
        $m = $out | Select-String '^\s*(\S+)\s+<00>\s+UNIQUE'
        if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
    } catch { }
    return ''
}

# --- 3. Read the ARP table (source of truth for MAC addresses) ----------------
Start-Sleep -Milliseconds 500
$arp = arp -a | Select-String "^\s+($([regex]::Escape($Subnet))\.\d+)\s+([\da-fA-F-]{17})\s+(\w+)"

$devices = foreach ($line in $arp) {
    $ip   = $line.Matches[0].Groups[1].Value
    $mac  = $line.Matches[0].Groups[2].Value.ToUpper()
    $type = $line.Matches[0].Groups[3].Value      # dynamic / static

    # Name: try reverse-DNS first, then NetBIOS.
    $name = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { '' }
    if (-not $name -or $name -eq $ip) { $name = Get-NbName $ip }
    if (-not $name) { $name = '-' }

    [PSCustomObject]@{
        IP       = $ip
        MAC      = $mac
        Name     = $name
        Vendor   = Get-Vendor $mac
        Type     = $type
    }
}

# --- 4. Show results ----------------------------------------------------------
if (-not $devices) {
    Write-Host "No devices found. Try a longer -TimeoutMs or check your -Subnet." -ForegroundColor Yellow
    return
}

$devices |
    Sort-Object { [int]($_.IP -split '\.')[-1] } |
    Format-Table -AutoSize

Write-Host ("`nFound {0} device(s) on {1}.0/24" -f $devices.Count, $Subnet) -ForegroundColor Green
Write-Host "Tip: match each MAC/Hostname to your own gear. Anything you don't recognize is a guest or intruder." -ForegroundColor DarkGray
