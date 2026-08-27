# Project 01 — Splunk Deployment and Log Ingestion

## Overview

This project sets up the logging environment for the rest of my Splunk SOC lab.

I deployed Splunk Enterprise on a Windows environment and configured it to collect Windows Event Logs and Sysmon telemetry. I then verified the data in Splunk and searched endpoint activity to confirm that events generated on the host could be found during an investigation.

The purpose of this project was to build a working telemetry pipeline before moving into deeper log analysis and incident investigation.

## Environment

- Windows Server 2022 / Windows environment
- Splunk Enterprise
- Sysmon
- Windows Event Viewer
- PowerShell

## Log Sources

The following Windows logs were collected into the `windows` index:

- Security
- System
- Application
- Microsoft-Windows-Sysmon/Operational

This provides both standard Windows event data and more detailed endpoint telemetry from Sysmon.

## Splunk Index

A dedicated index was created for the lab:

```text
index=windows
```

Keeping the Windows telemetry in its own index makes it easier to search and investigate the endpoint data throughout the later SOC projects.

## Windows Event Log Collection

I configured Splunk to collect the main Windows event channels used throughout the lab.

The Security log provides authentication and security-related events, while the System and Application logs provide additional context when troubleshooting or investigating activity.

Example search used to verify the available log sources:

```spl
index=windows
| stats count by source
```

## Sysmon

Sysmon was installed to provide additional endpoint visibility beyond the standard Windows Event Logs.

The Sysmon Operational log was added to Splunk:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

The collected telemetry includes information that can be used to investigate areas such as:

- Process execution
- User activity
- Parent and child processes
- Command-line activity
- Network activity
- DNS activity
- File and registry activity

## Verifying Sysmon in Splunk

I verified that Sysmon events were being collected by Splunk alongside the standard Windows logs.

The Sysmon data was ingested using the following sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

One issue I encountered was that some Sysmon fields were not automatically extracted from the XML event data. I inspected the raw events directly to confirm the Event ID and other event details rather than assuming the data had failed to ingest.

This was useful because it separated an ingestion problem from a field-extraction/search problem.

## Process Activity Test

To confirm the full logging pipeline, I generated known process activity on the Windows host and searched for it in Splunk.

Test activity included processes such as:

```text
powershell.exe
cmd.exe
notepad.exe
whoami.exe
ipconfig.exe
nslookup.exe
```

The resulting Sysmon events could then be traced in Splunk.

This confirmed the basic workflow:

```text
Endpoint Activity
       ↓
     Sysmon
       ↓
Windows Event Log
       ↓
     Splunk
       ↓
Search and Analysis
```

## Example Searches

### View Windows log sources

```spl
index=windows
| stats count by source
```

### Search Windows Security events

```spl
index=windows source="WinEventLog:Security"
```

### Search successful Windows logons

```spl
index=windows source="WinEventLog:Security" EventCode=4624
```

### Search Sysmon events

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

### Find specific process activity

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "notepad.exe"
```

## Troubleshooting

During the setup, Sysmon was running and generating events locally, but the Sysmon channel was not initially available through the Splunk Local Event Log Collection interface.

I confirmed the Sysmon Operational log was active using PowerShell and then configured Splunk to collect the channel.

I also found that the Sysmon events were arriving as XML and some expected fields were not automatically extracted. Checking the raw event data confirmed that the telemetry itself was being collected correctly.

This reinforced an important troubleshooting point: **verify the data at each stage of the pipeline before changing the configuration.**

## What I Practised

- Deploying and configuring Splunk Enterprise
- Creating and working with a dedicated Splunk index
- Collecting Windows Event Logs
- Deploying Sysmon endpoint telemetry
- Verifying log ingestion
- Searching raw Windows and Sysmon events
- Understanding Splunk sources and sourcetypes
- Inspecting XML event data
- Troubleshooting missing fields versus missing logs
- Tracing endpoint activity into Splunk

## Screenshots

### Windows Index

![Windows Index](screenshots/01-windows-index.png)

### Windows Event Log Inputs

![Windows Event Log Inputs](screenshots/02-windows-event-log-inputs.png)

### Windows Log Sources

![Windows Log Sources](screenshots/03-windows-log-sources.png)

### Windows Security Events

![Windows Security Events](screenshots/04-security-event-codes.png)

### Successful Logons

![Successful Logons](screenshots/05-successful-logons-4624.png)

### Sysmon Service

![Sysmon Service](screenshots/06-sysmon-service-running.png)

### Sysmon Event Viewer

![Sysmon Event Viewer](screenshots/07-sysmon-event-viewer.png)

### Windows and Sysmon Sources

![Windows and Sysmon Sources](screenshots/08-windows-and-sysmon-sources.png)

### Sysmon Source Verification

![Sysmon Source Verification](screenshots/09-sysmon-source-verification.png)

### Sysmon Event Analysis

![Sysmon Event Analysis](screenshots/10-sysmon-event-id-analysis.png)

### Process Creation Analysis

![Process Creation Analysis](screenshots/11-process-creation-analysis.png)

## Next

Project 02 moves from collecting telemetry into **SPL and security log analysis**, using the data collected here to search, filter, aggregate, and investigate Windows security activity.