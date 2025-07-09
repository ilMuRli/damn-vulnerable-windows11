# Damn Vulnerable Windows 11

This project provides a simple but extensible Windows 11 honeypot environment. The idea is to spin up a temporary VM or laptop and connect it directly to an untrusted network (for example the DEF CON conference Wi-Fi) in order to collect information about scanning attempts, exploitation and other suspicious activity.

## DISCLAIMER

Running a honeypot on a public network can expose the system to a wide variety of attacks. Only use a fresh, disposable Windows 11 instance that does not contain personal data. Place the machine on an isolated or dedicated network whenever possible. This repository contains example scripts and configuration steps, but you assume all risk for operating the environment.

## Prerequisites

1. **Fresh Windows 11 installation** in a virtual machine or on dedicated hardware.
2. **Administrator privileges** to install required software.
3. Optional network capture or logging tools (Sysmon, Wireshark, etc.).
4. A removable USB drive or network share if you plan to export the logs.

## Quick Setup

1. Clone or download this repository onto the Windows 11 machine.
2. Open **PowerShell** as Administrator.
3. Run `scripts/setup-honeypot.ps1`. The script now checks that it is running as Administrator, temporarily sets the execution policy to **Bypass**, installs Sysinternals Sysmon, enables services like the print spooler and remote registry, opens many ports (RDP, SMB, FTP, Telnet, WinRM, HTTP and others), turns on extensive logging and creates a writable share at `\\<ip>\Honeypot`.
4. If Python is detected the script automatically starts a simple HTTP server on port 80 so attackers immediately see web content.
5. Connect to the target Wi-Fi network. Be sure you comply with the event logging or packet capture policies of that network.
6. Ideally connect through a dedicated or isolated interface so the honeypot does not share the same network as your personal devices.
7. Review the Windows Event Viewer and the generated log files under `C:\Windows\System32\LogFiles` to see what kinds of connections were attempted.

### Detailed Setup

If you would like a more hands-on configuration:

1. After cloning the repo, inspect `scripts/setup-honeypot.ps1` to understand what will be changed on the system.
2. Optionally modify the script to tailor which ports are opened or which services are installed.
3. Run the script and reboot if prompted.
4. Launch **Event Viewer** and confirm that Sysmon, Security and PowerShell logs are being generated.
5. Set up a network capture tool such as **Wireshark** if you want full packet visibility alongside the Windows event logs.

Once the machine is online at the conference, simply leave it running and periodically export the logs to your removable drive or to the `\\<ip>\Honeypot` share created by the script.

### Customizing the Honeypot

You can edit `scripts/setup-honeypot.ps1` to change the exposed ports or disable unwanted features. The TCP and UDP port lists are near the top of the script in the `$ports` and `$udpPorts` arrays. After making your edits, rerun the script in an elevated PowerShell session and reboot.

## Monitoring and Attack Surface

The setup script intentionally exposes several services to invite scans and attacks:


- **RDP (TCP 3389)** – for brute-force login attempts.
- **SMB (TCP 445)** and **NetBIOS (TCP 139/UDP 137-138)** – observe file share probes or exploit attempts.
- **FTP (TCP 21)** and **Telnet (TCP 23)** – classic protocols that still attract a lot of automated attacks.
- **TFTP (UDP 69)** – left open to see if attackers attempt file transfers.
- **WinRM (TCP 5985/5986)** – remote management over HTTP/HTTPS.
- **HTTP (TCP 80)** – the script automatically launches a Python-based web server when available, otherwise you can enable IIS manually.
- **SMTP (TCP 25)** and **DNS (TCP 53)** – additional common services to attract exploitation attempts.
- **HTTPS (TCP 443)** – open though no certificate is configured by default.
- **POP3 (TCP 110)** and **IMAP (TCP 143)** – mail retrieval services.
- **LDAP (TCP 389)** – directory service endpoint.
- **SNMP (UDP 161/162)** – enumeration and trap messages.
- **NFS and Rsync (TCP 2049/873)** – extra file-transfer protocols that may interest attackers.
- **Redis (TCP 6379)** and **MongoDB (TCP 27017)** – often exploited when unsecured.
- **Industrial protocols (TCP 502/20000/47808)** – Modbus, DNP3 and BACnet listeners for OT attacks.
- **Alternate remote access (TCP 5901/2222)** – extra VNC and SSH ports.
- **SQL ports (TCP 1433/3306/5432)** – mimic MS SQL Server, MySQL and PostgreSQL.
- **VNC (TCP 5900)** – remote desktop alternative to RDP.
- **Printer protocols (TCP 515/631/9100)** – mimic LPD, IPP and JetDirect for print-based exploits.
- **PPTP VPN (TCP 1723)** – old remote access protocol sometimes targeted.
- **SIP (TCP 5060)**, **UPnP (TCP 5000)** and other high ports (5555, 6667, 1812/1813, 50000, 8082, 8888) – miscellaneous services to entice scans.
- **Custom web services (TCP 8080/8443)** – less common web front ends.
- **Vulnerable web apps (TCP 8081/8080)** – DVWA and DVWS containers expose purposely insecure applications.
- **Discovery protocols (UDP 1900/3702/5353/5355)** – SSDP, WS-Discovery, mDNS and LLMNR traffic.
- **File Share (`\\<ip>\Honeypot`)** – writable share for copying logs off the system.
- **Bluetooth support** – the local radio is left on for proximity attacks when hardware is present.
Firewall and PowerShell auditing are turned on to keep track of what remote commands run.  Sysmon further logs process creation and network connections for later analysis.  All of these logs can be reviewed locally or forwarded to another collector.

## Contents

- `scripts/setup-honeypot.ps1` – PowerShell script that downloads the current Sysinternals Sysmon release, opens several common ports, creates a writable file share and configures firewall and PowerShell logging.

The script does not fully harden the system. It is meant only as a starting point to help automate some common tasks for a throwaway research machine.

## Running Additional Vulnerable Web Apps

For a richer attack surface you can host purposely insecure applications. If
**Docker** is installed when the setup script runs it will automatically start
two containers:

1. **DVWA** on port **8081** using the `vulnerables/web-dvwa` image.
2. **DVWS** on ports **8080** and **8888** using the `tssoffsec/dvws` image.

If Docker is not installed you will see a warning. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
and re-run the script to enable these services. The web interfaces will then be
accessible at:

- `http://<ip>:8081/` for DVWA
- `http://<ip>:8080/` for DVWS

Each application maintains its own logs inside the container. These are not kept
permanently but you can run `docker logs dvwa` or `docker logs dvws` to review
activity. Consider exporting the logs periodically to `C:\HoneypotShare` if you
want to preserve them.

## Viewing Logs

After the honeypot has been running for a while, inspect the following logs:

- **Event Viewer → Windows Logs → Security** – login attempts, privilege use and other security events.
- **Event Viewer → Applications and Services Logs → Microsoft → Windows → PowerShell** – script block logging for any malicious PowerShell.
- **`%SystemRoot%\System32\LogFiles\Firewall\firewall.log`** – blocked and allowed connection attempts recorded by the Windows firewall.
- **`%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`** – Sysmon events about process creation and network connections.
 - **`%SystemRoot%\System32\winevt\Logs\Security.evtx`** – the raw Security event log if you prefer to process the file directly.
 - **`C:\HoneypotShare`** – network share created by the script where you can periodically copy log files.
- **`$env:USERPROFILE\Documents\honeypot_transcript.log`** – transcript of all PowerShell commands executed after the setup script starts.
- **`%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-PrintService%4Operational.evtx`** – print spooler activity for exploitation attempts.
- **`%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Bluetooth-User%4Operational.evtx`** – Bluetooth events when hardware is present.
- **`%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx`** – traces WMI-based attacks.
- **`%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`** – RDP connection attempts.
- **`%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`** – session logon events.

Export these logs or forward them to a separate collector for long-term analysis.


For deeper insight you can run **Wireshark** or another packet sniffer while the
honeypot is online. Store the resulting `.pcapng` file in `C:\HoneypotShare` so
you can analyze network-level attacks alongside the Windows event logs.

## Operating the Honeypot

The machine is ready for monitoring as soon as the setup script finishes, but
following these steps will help you collect meaningful data and keep the
honeypot running smoothly.

### After Setup

1. **Reboot the system**. Some optional features (such as the SSH server or
   Telnet client) only fully initialize after a restart.
2. Verify that the writable share works by navigating to `\\<ip>\Honeypot`
   from another computer and copying a test file.
3. Confirm the temporary Python HTTP server (if started) by browsing to `http://<ip>/`.  You should see the contents of the current directory.
4. Run `netstat -an` in PowerShell to confirm that the expected ports are
   listening. You should see entries for ports like 22, 80, 3389 and 5900 among
   many others.
5. Ensure **Sysmon** and **sshd** are running:

   ```powershell
   Get-Service Sysmon64,sshd | Select-Object Status,Name
   Get-NetFirewallRule -DisplayName "Honeypot*" | Select-Object DisplayName,Enabled
   ```
6. Consider placing decoy documents in `C:\HoneypotShare` or the web server
   directory to lure attackers and observe interaction attempts.

### Routine Monitoring

1. Use **Event Viewer** to watch the logs listed above in near real-time. The
   Sysmon Operational log will show new processes and network connections, while
   the Security log captures logon attempts.
2. Periodically inspect `firewall.log` for blocked traffic. Signs of scanning or
   exploitation attempts often appear here first.
3. The PowerShell transcript file grows quickly; rotate it manually or copy it
   off to another system if space becomes an issue.

### Exporting Evidence

When you are ready to analyze the captured activity offline, export the logs to
the writable share. Example commands:

```powershell
wevtutil epl Security C:\HoneypotShare\Security.evtx
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\HoneypotShare\Sysmon.evtx
Copy-Item $env:USERPROFILE\Documents\honeypot_transcript.log C:\HoneypotShare\
```

You may also copy container logs if Docker-based services are running:

```powershell
docker logs dvwa > C:\HoneypotShare\dvwa.log
docker logs dvws > C:\HoneypotShare\dvws.log
```

### Cleanup and Reuse

After the conference or research session concludes, you can either archive the
virtual machine or reset it for another run. To remove the additional services:

```powershell
Stop-Service sshd
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
wecutil qc /u
Remove-SmbShare -Name Honeypot -Force
```

Deleting the VM entirely is recommended if you suspect it was compromised.

