# Endpoint and PowerShell Investigation

## Incident Summary

PowerShell activity on the Windows endpoint was investigated using Sysmon telemetry in Splunk.

The activity included system and network discovery commands, DNS-related activity, command-shell execution and other processes launched during a controlled test.

## Initial Triage

The investigation started with PowerShell process activity.

I reviewed the user, parent process, executable and command line to understand how PowerShell was being used rather than treating PowerShell itself as malicious.

## Process Investigation

Sysmon telemetry was used to identify PowerShell and related processes.

The investigation included:

- powershell.exe
- cmd.exe
- whoami.exe
- hostname.exe
- ipconfig.exe
- nslookup.exe

Reviewing the parent and child processes helped reconstruct how the commands were executed.

## Discovery Activity

Several discovery commands were observed during the test.

`whoami` was used to identify the current user, `hostname` identified the system and `ipconfig` returned network configuration information.

These tools are commonly used by administrators but can also appear during attacker reconnaissance.

## DNS and Network Activity

DNS-related activity was investigated around `nslookup.exe`.

Where network telemetry was available, I also reviewed destination information associated with the PowerShell activity.

The network evidence was considered together with the responsible process and command line rather than treating a connection by itself as malicious.

## Assessment

**Verdict: Suspicious-looking endpoint activity — benign controlled activity**

The activity was intentionally generated as part of the lab.

None of the individual commands demonstrated compromise. However, an unexpected sequence of PowerShell execution, discovery commands, command-shell activity and outbound communication would justify further investigation in a production environment.

## MITRE ATT&CK

Relevant techniques for the activity observed included:

- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1033 — System Owner/User Discovery
- T1082 — System Information Discovery
- T1016 — System Network Configuration Discovery

## Escalation Decision

No escalation was required because the activity was generated intentionally.

If the same behaviour appeared unexpectedly, I would investigate the user, parent process, PowerShell command line, related processes, destination activity and other endpoint events before deciding whether escalation or containment was necessary.

## Conclusion

The main takeaway from this investigation was that legitimate Windows tools can still form a suspicious behavioural pattern.

Looking at the process relationships, commands, user context and surrounding activity provided much more useful information than investigating each executable separately.