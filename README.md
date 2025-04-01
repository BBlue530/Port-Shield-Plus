Port-Shield-Plus is an upgraded version of a previous project called Port-Shield. It is a Linux-based security tool that enhances the original logic by adding more advanced monitoring and defense capabilities. 
Port-Shield-Plus monitors network activity and newly added programs to detect and block potential threats. It disassembles programs to check for malicious code, quarantines unsafe software, and blocks IPs engaging in suspicious port scanning. 
In case of a severe security breach, it executes a "last line of defense," encrypting backups, removing compromised files, disabling network interfaces, and locking down BIOS to prevent further damage.
Features:



-Disassemble & Quarantine Programs: 



Port-Shield-Plus disassembles newly added programs on the machine and checks for restricted code patterns against security rules. If violations are found, the program is quarantined.



-IP Blocking for Excessive Port Access: 



It detects and blocks IPs that attempt to access too many ports in a short time frame.







Components:



-portmonitoring - Monitor & Block Suspicious IPs:

This folder contains scripts that monitor incoming traffic.

It logs suspicious IPs and blocks those exceeding predefined thresholds.



-programmonitoring - Program Scanner & Disassembler:

This folder contains scripts that find new programs on the machine.

If possible, it disassembles the program and checks for security violations.

For open-source programs, it directly analyzes the source code.



-securitychecks - Final Security Defense:

This folder contains scripts that double-check security failures.

If a critical failure occurs, it executes the last line of defense:

Encrypting backup files.

Removing compromised programs.

Notifying the owner via email.

Disabling network interfaces.

Locking down BIOS to prevent tampering.







Technologies Used:

-Python: For disassembly, rule checking, and quarantine management.

-Firewall Rules: To detect and block unauthorized access attempts.

-Logging & Alerting: For real-time security monitoring.







How to Use:

1: Install Port-Shield-Plus on the target machine.

2: It automatically scans new programs and monitors network activity.

3: If a program violates security rules, it is quarantined.

4: If an IP performs excessive port scanning, it is blocked.

5: If a security failure occurs, the last line of defense will trigger emergency measures.

