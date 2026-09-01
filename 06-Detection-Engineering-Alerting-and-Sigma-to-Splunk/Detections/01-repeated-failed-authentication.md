# Repeated Failed Authentication

## Detection Goal
Identify accounts generating repeated failed Windows authentication attempts within a short period.

## Data Source
Windows Security Event Log

## Event ID
4625 — Failed Logon

## Detection Logic
Five or more failed authentication attempts grouped by account and source.

## Severity
Medium

## MITRE ATT&CK
T1110 — Brute Force

## Analyst Notes
The threshold of five attempts was selected for this lab and would require tuning in a production environment.

The detection was converted into a scheduled Splunk alert and successfully triggered using controlled authentication failures.