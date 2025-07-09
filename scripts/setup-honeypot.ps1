<#
.SYNOPSIS
    Configure a minimal Windows 11 honeypot environment.

.DESCRIPTION
    Installs Sysmon and enables a variety of services so that many
    attack vectors (RDP, SMB, FTP, Telnet and HTTP) are reachable.
    Firewall logging, a writable network share and PowerShell auditing
    are configured to produce useful artifacts for later analysis.
    Execute this script on a disposable Windows 11 machine only.
#>


# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Warning 'Please run this script from an elevated PowerShell window.'
    exit 1
}

# Temporarily relax execution policy for the current process
$oldExecutionPolicy = Get-ExecutionPolicy -Scope Process
if ($oldExecutionPolicy -ne 'Bypass') {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
}

# Enable Remote Desktop and PSRemoting
Enable-PSRemoting -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0

# Enable common services frequently targeted by attackers
Set-Service -Name Spooler -StartupType Automatic
Start-Service Spooler
Set-Service -Name RemoteRegistry -StartupType Automatic
Start-Service RemoteRegistry
# Install legacy printer services for additional vectors
try {
    Add-WindowsCapability -Online -Name 'Printing.LPDPrintService~~~~0.0.1.0' -ErrorAction SilentlyContinue
    Add-WindowsCapability -Online -Name 'Printing.LPRPortMonitor~~~~0.0.1.0' -ErrorAction SilentlyContinue
} catch {}
# Install extra optional features to widen the attack surface
$optional = @(
    'TFTP.Client~~~~0.0.1.0',
    'TelnetClient~~~~0.0.1.0',
    'OpenSSH.Server~~~~0.0.1.0'
    'SNMP.Client~~~~0.0.1.0'
)
foreach ($cap in $optional) {
    try { Add-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue } catch {}
}
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service sshd -ErrorAction SilentlyContinue
# Start Bluetooth support if present
Set-Service -Name bthserv -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service bthserv -ErrorAction SilentlyContinue

# Record all PowerShell activity for later review
if (-not $TranscriptFile) {
    $TranscriptFile = "$env:USERPROFILE\Documents\honeypot_transcript.log"
}
Start-Transcript -Path $TranscriptFile -Force

# Open multiple ports to increase potential attack vectors
# The list includes a range of common services in addition to
# the basics from earlier versions of this script.  Additional
# ports cover industrial protocols, collaboration tools and
# database services to tempt more advanced attackers.
$ports = @(
    21,22,23,25,53,80,110,135,139,143,389,443,
    445,502,515,631,9100,2049,
    3389,5900,5901,5985,5986,1433,3306,5432,1723,27017,6379,
    20000,47808,
    5000,5060,5555,6667,1812,1813,50000,873,2222,
    8080,8081,8082,8443,8888
)
foreach ($port in $ports) {
    if (-not (Get-NetFirewallRule -DisplayName "Honeypot TCP $port" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Honeypot TCP $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any
    }
}
# Allow common UDP services as well
$udpPorts = 69,137,138,161,162,1900,3702,5353,5355,20000,47808
foreach ($udpPort in $udpPorts) {
    if (-not (Get-NetFirewallRule -DisplayName "Honeypot UDP $udpPort" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Honeypot UDP $udpPort" -Direction Inbound -Protocol UDP -LocalPort $udpPort -Action Allow -Profile Any
    }
}

# Create a writable share where logs can be copied off the system
$sharePath = 'C:\HoneypotShare'
if (-not (Test-Path $sharePath)) {
    New-Item -Path $sharePath -ItemType Directory -Force | Out-Null
}
if (-not (Get-SmbShare -Name Honeypot -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name 'Honeypot' -Path $sharePath -FullAccess 'Everyone' | Out-Null
}

# Optionally enable SMBv1 for additional attack surface
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

# Enable basic firewall logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\firewall.log'

# If Python is available, automatically start a simple HTTP server on port 80
# in the background.  This provides immediate web content for attackers without
# requiring IIS.
if (Get-Command python -ErrorAction SilentlyContinue) {
    try {
        Start-Process -WindowStyle Hidden -FilePath python -ArgumentList '-m http.server 80' -ErrorAction SilentlyContinue
    } catch {}
}

# Increase common event log sizes to prevent quick rollover
foreach ($log in 'Security','System','Application') {
    # Expand log size to 64MB so data is not lost quickly
    wevtutil sl $log /ms:65536
}
# Expand PowerShell log size
wevtutil sl 'Windows PowerShell' /ms:65536
wevtutil set-log "Microsoft-Windows-PrintService/Operational" /enabled:true
wevtutil set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true
wevtutil set-log "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" /enabled:true
wevtutil set-log "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /enabled:true
wevtutil set-log "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /enabled:true

# Enable PowerShell script block logging
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force | Out-Null
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1

# Install Sysinternals Sysmon for logging
if (-not (Get-Command sysmon64.exe -ErrorAction SilentlyContinue)) {
    $tmp = "$env:TEMP\Sysmon.zip"
    Write-Host "Downloading Sysmon..."
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $tmp
    $dest = "$env:TEMP\Sysmon"
    Expand-Archive $tmp -DestinationPath $dest -Force
    & "$dest\Sysmon64.exe" -accepteula -i -n -h md5 -l
}

# Enable Windows Event Forwarding quick config
wecutil qc /q

# Start vulnerable web app containers if Docker is available
if (Get-Command docker -ErrorAction SilentlyContinue) {
    if (-not (docker ps --format '{{.Names}}' | Select-String -SimpleMatch 'dvwa')) {
        Write-Host 'Starting DVWA container on port 8081...'
        docker pull vulnerables/web-dvwa | Out-Null
        docker run -d --name dvwa -p 8081:80 vulnerables/web-dvwa | Out-Null
    }
    if (-not (docker ps --format '{{.Names}}' | Select-String -SimpleMatch 'dvws')) {
        Write-Host 'Starting DVWS container on ports 8080 and 8888...'
        docker pull tssoffsec/dvws | Out-Null
        docker run -d --name dvws -p 8080:80 -p 8888:8888 tssoffsec/dvws | Out-Null
    }
} else {
    Write-Warning 'Docker not detected. Install Docker Desktop to enable DVWA and DVWS.'
}

Write-Host 'Honeypot setup complete. Logs will accumulate in Event Viewer and under %SystemRoot%\System32\LogFiles.'
Stop-Transcript

# Restore previous execution policy if it was changed
if ($oldExecutionPolicy -ne 'Bypass') {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldExecutionPolicy -Force
}
