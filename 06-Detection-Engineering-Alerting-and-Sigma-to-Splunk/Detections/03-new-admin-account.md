# New Account and Administrator Group Change

## Detection Goal
Identify account creation followed by a security-sensitive group membership change.

## Data Source
Windows Security Event Log

## Event IDs
- 4720 — User Account Created
- 4732 — Member Added to Local Security Group

## Severity
High

## MITRE ATT&CK
- T1136 — Create Account
- T1098 — Account Manipulation

## Analyst Notes
Account creation is not inherently malicious. Combining account creation with a subsequent privileged group change provides stronger context for investigation.

The lab detection was validated against controlled account lifecycle activity.