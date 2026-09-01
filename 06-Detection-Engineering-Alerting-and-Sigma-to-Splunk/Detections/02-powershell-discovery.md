# PowerShell Discovery Activity

## Detection Goal
Identify discovery utilities launched from PowerShell that may warrant analyst investigation.

## Data Source
Sysmon

## Processes Monitored
- whoami.exe
- hostname.exe
- ipconfig.exe
- nslookup.exe

## Detection Logic
Look for multiple discovery processes where PowerShell is the parent process.

## Severity
Medium

## MITRE ATT&CK
- T1059.001 — PowerShell
- T1033 — System Owner/User Discovery
- T1082 — System Information Discovery
- T1016 — System Network Configuration Discovery

## Analyst Notes
These utilities are legitimate Windows tools. The detection is intended to identify suspicious-looking execution patterns for investigation rather than automatically classify the activity as malicious.