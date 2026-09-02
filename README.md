# Splunk SOC Investigation Lab

## Overview

This repository documents my hands-on work with Splunk for security monitoring, log analysis, detection engineering and incident investigation.

I built the lab around Windows Security and Sysmon telemetry rather than using a prepared dataset. The work started with getting the logs into Splunk and learning how to search them with SPL, then moved into authentication and endpoint investigations, detections, alerting, dashboards and controlled ATT&CK testing.

The main goal was to practice the workflow I would expect to use as a junior SOC analyst:

**Collect telemetry → search logs → detect activity → investigate → correlate evidence → make an analyst decision → document the case**

---

## Lab Environment

- Splunk Enterprise
- Windows 11 / Windows lab environment
- Windows Security Event Logs
- Sysmon
- PowerShell
- Atomic Red Team
- MITRE ATT&CK
- Sigma-style detection rules

Windows Security, System, Application and Sysmon telemetry were collected into a dedicated `windows` index.

---

## Projects

| # | Project | What I Worked On |
|---|---|---|
| 01 | Splunk Deployment & Log Ingestion | Splunk setup, Windows log collection, Sysmon ingestion and telemetry validation |
| 02 | SPL & Security Log Analysis | SPL searches, authentication analysis, process analysis, PowerShell and DNS activity |
| 03 | Windows Security Event Analysis | Account creation, privilege changes, password resets, process creation and account lifecycle events |
| 04 | Authentication Attack Investigation | Failed logon investigation, source analysis, authentication correlation and analyst verdict |
| 05 | Endpoint, PowerShell & Network Investigation | PowerShell activity, parent-child processes, discovery commands, DNS and endpoint investigation |
| 06 | Detection Engineering, Alerting & Sigma-to-Splunk | Custom SPL detections, scheduled alerts, alert validation and Sigma-to-Splunk adaptation |
| 07 | SOC Incident Investigation & Response | Alert triage, evidence correlation, process pivots, timeline analysis and escalation decision |
| 08 | MITRE ATT&CK & Live SOC Dashboard | SOC monitoring dashboard, security KPIs and ATT&CK mapping |
| 09 | Atomic Red Team Detection & Investigation | Controlled ATT&CK test, Sysmon telemetry, SPL detection and analyst investigation |

---

## Detection Engineering

I built and tested detections for activity including:

- repeated failed authentication
- PowerShell discovery commands
- account creation and privileged group changes
- hostname/system discovery

One of the failed-authentication detections was converted into a scheduled Splunk alert and validated with fresh Windows authentication events.

The workflow was:

**Windows Event → Splunk → SPL detection → threshold → scheduled alert → triggered alert**

I also worked through translating Sigma-style detection logic into SPL based on the fields actually available in my Sysmon data.

---

## Investigation Work

The repository includes investigation reports rather than only screenshots of searches.

During the labs I worked through:

- failed authentication triage
- account activity analysis
- Windows Security Event ID investigation
- PowerShell and process-chain analysis
- Sysmon process pivots
- account enumeration analysis
- DNS and network context
- timeline building
- MITRE ATT&CK mapping
- escalation decisions
- incident closure

An important part of the work was avoiding conclusions that the evidence did not support.

For example, during one investigation I found the same PID value associated with different process instances at different timestamps. I did not use the matching PID alone to claim that the events were related.

---

## SOC Dashboard

I built a Splunk monitoring dashboard covering:

- Windows Security event volume
- failed authentication by account
- account and privilege changes
- top Sysmon processes
- PowerShell discovery activity
- failed-authentication KPI
- recent security events

The dashboard uses the same Windows and Sysmon telemetry used throughout the investigation labs.

---

## Atomic Red Team

For the final lab, I used Atomic Red Team to generate controlled:

**T1082 — System Information Discovery**

I executed the Windows hostname-discovery test and followed the resulting activity through Sysmon and Splunk.

The test was detected successfully and then investigated using process and surrounding-event context.

The final assessment distinguished between:

**Detection Result: True Positive**

and

**Incident Verdict: Benign / Controlled Activity**

That distinction was useful because detecting ATT&CK-mapped behaviour does not automatically mean an endpoint is compromised.

---

## MITRE ATT&CK Coverage

Some of the techniques covered during the labs include:

| Technique | ID |
|---|---|
| Brute Force | T1110 |
| PowerShell | T1059.001 |
| Windows Command Shell | T1059.003 |
| System Owner/User Discovery | T1033 |
| System Information Discovery | T1082 |
| System Network Configuration Discovery | T1016 |
| Create Account | T1136 |
| Account Manipulation | T1098 |

ATT&CK was used to describe observed behaviour and detection coverage, not as proof that activity was malicious.

---

## SPL Skills Practiced

The project gave me practical experience using SPL commands including:

```text
search
table
stats
sort
dedup
eval
where
rex
timechart
top
rare
```

I used `rex` frequently because some of the Sysmon telemetry arrived as XML without all of the fields automatically extracted.

---

## What I Learned

The biggest improvement for me was moving beyond simply finding an event in Splunk.

A useful investigation requires context: what happened before and after the event, which user and host were involved, what process launched it, whether other telemetry supports the same conclusion, and whether the evidence is strong enough to escalate.

I also learned that not every alert needs to become an incident. Some of the most useful exercises ended with a benign verdict because the available evidence did not support compromise.

That process of investigating first and deciding second was the main focus of this lab.

---

## Disclaimer

This repository contains work from a controlled lab environment. The activity and incidents documented here were generated for learning and detection testing and do not represent production SOC experience.
