# SOC-IR-001 — Repeated Failed Authentication Investigation

## Incident Summary

A Splunk alert detected repeated failed authentication attempts associated with the SOC-Auth-Test account. The alert was generated from controlled activity created during the detection engineering lab.

The investigation focused on determining whether the authentication activity was followed by successful access or suspicious endpoint behaviour.

## Initial Triage

- Alert: Repeated Failed Authentication Attempts
- Initial Severity: Medium
- Target Account: SOC-Auth-Test
- Primary Data Source: Windows Security Event Log
- Initial Detection: Event ID 4625 threshold
- Host: DC01

The detection had successfully triggered after multiple failed authentication attempts.

## Investigation

### Account Activity

The account was searched across the available Windows Security telemetry.

During the current investigation window, the account appeared in Event ID 4798, which records enumeration of a user's local group membership.

### Group Membership Enumeration

Event 4798 showed:

- Account: SOC-Auth-Test
- Caller Process: C:\Windows\System32\wbem\WmiPrvSE.exe
- Process ID: 0x3a50

The caller was Windows WMI Provider Host. This process is legitimate and its presence alone was not treated as evidence of malicious activity.

### Process Pivot

Sysmon telemetry was reviewed for related WMI activity.

A matching process relationship between the Security event and suspicious endpoint execution could not be established. PID values observed elsewhere in Sysmon were associated with different process instances, so PID reuse was considered during analysis.

No malicious process execution was identified from this pivot.

### Enumeration Context

Event ID 4798 activity was reviewed across the environment.

Eight different accounts appeared in 4798 events, while SOC-Auth-Test appeared only once. This reduced the likelihood that the enumeration represented activity specifically targeting the test account.

### Surrounding Activity

Windows and Sysmon telemetry around the event timestamp was reviewed for suspicious follow-on behaviour.

No clearly suspicious related activity was identified.

## Timeline

1. Controlled failed authentication attempts were generated.
2. Splunk detected the authentication threshold.
3. The scheduled alert triggered.
4. SOC-Auth-Test was investigated across Windows Security telemetry.
5. Event ID 4798 was identified.
6. The caller process was identified as WmiPrvSE.exe.
7. Sysmon telemetry was reviewed for process context.
8. 4798 activity was compared across other accounts.
9. No suspicious follow-on activity was identified.

## MITRE ATT&CK Context

The original detection was mapped to:

- T1110 — Brute Force

The mapping describes the behaviour monitored by the detection. It does not mean that a real brute-force attack was confirmed.

## Analyst Assessment

**Verdict: Benign / Controlled Activity**

The failed authentication activity was intentionally generated for testing.

The investigation did not establish successful unauthorized access, malicious process execution, or suspicious follow-on behaviour.

Event ID 4798 was investigated but did not provide sufficient evidence to raise the incident severity. Similar enumeration activity was observed for several other accounts.

## Escalation Decision

**No escalation required.**

In a production environment, escalation would be considered if the failed authentication activity were followed by successful access, originated from an unusual source, affected privileged accounts, or correlated with suspicious endpoint activity.

## Recommended Response

For the controlled lab incident, no containment action was required.

For a similar production alert:

- Validate the authentication source.
- Check for successful authentication after the failures.
- Review affected account privileges.
- Investigate endpoint activity around the same period.
- Reset or disable the account if compromise is suspected.
- Escalate if additional evidence supports unauthorized access.

## Closure

The incident was closed as controlled lab activity with no evidence of account compromise.