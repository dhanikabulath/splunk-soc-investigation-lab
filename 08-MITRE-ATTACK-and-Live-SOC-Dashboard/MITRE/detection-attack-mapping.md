# MITRE ATT&CK Detection Mapping

This mapping connects the behaviours investigated in the Splunk labs with relevant MITRE ATT&CK techniques.

The mappings describe the behaviour being monitored. They do not mean that every matching event is malicious.

| Detection / Activity | ATT&CK Technique | ID |
|---|---|---|
| Repeated failed authentication | Brute Force | T1110 |
| PowerShell execution | PowerShell | T1059.001 |
| Command Prompt execution | Windows Command Shell | T1059.003 |
| `whoami.exe` activity | System Owner/User Discovery | T1033 |
| `hostname.exe` activity | System Information Discovery | T1082 |
| `ipconfig.exe` activity | System Network Configuration Discovery | T1016 |
| New user account | Create Account | T1136 |
| Account/group privilege change | Account Manipulation | T1098 |

## How I Used ATT&CK

I used ATT&CK after identifying the behaviour in the logs rather than treating technique IDs as proof of an attack.

For example, PowerShell, `whoami`, and `ipconfig` are legitimate administration tools. Their ATT&CK mappings help describe behaviour that may be relevant during an investigation, but additional context is still required before classifying activity as malicious.