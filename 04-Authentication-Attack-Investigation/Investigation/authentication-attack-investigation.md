# Authentication Attack Investigation

## Incident Summary

Multiple failed authentication attempts were observed against the temporary `SOC-Auth-Test` account.

The activity was generated in a controlled lab environment and investigated using Windows Security logs in Splunk.

## Initial Triage

**Event ID:** 4625  
**Target account:** SOC-Auth-Test  
**Activity:** Repeated failed authentication attempts  
**Successful authentication observed afterward:** No

The repeated failures were close enough together to justify investigating the activity as a possible password-guessing attempt.

## Investigation

I started by isolating Event ID 4625 activity associated with the account.

```spl
index=windows source="WinEventLog:Security" EventCode=4625 "SOC-Auth-Test"
| table _time Account_Name Account_Domain Logon_Type Source_Network_Address Failure_Reason Status Sub_Status
| sort _time
```

I then counted the failures and reviewed the account, source information, logon type and failure reason.

To determine whether access was eventually gained, I searched for both successful and failed authentication events.

```spl
index=windows source="WinEventLog:Security"
(EventCode=4624 OR EventCode=4625)
"SOC-Auth-Test"
| eval Result=if(EventCode=4624,"SUCCESS","FAILURE")
| table _time Result Account_Name Logon_Type Source_Network_Address
| sort _time
```

Only failed authentication events were observed for the test activity.

## Timeline

The investigation showed a short sequence of repeated authentication failures against the same account.

No successful authentication event for `SOC-Auth-Test` was identified following the failures.

## Assessment

**Verdict: Suspicious authentication activity — unsuccessful**

The pattern was consistent with repeated password guessing. Because this was controlled activity, I knew the cause of the events.

If the same pattern appeared unexpectedly in a production environment, I would investigate the source, affected account, surrounding authentication activity and whether any successful login followed the failures.

The available evidence did not show that access to the account was gained.

## MITRE ATT&CK

The activity can be investigated in the context of:

**T1110 — Brute Force**

The lab only reproduced a small controlled set of failed authentication attempts rather than a real attack.

## Escalation Decision

For this lab, no escalation was required because the activity was intentionally generated.

In a production environment, repeated unexplained failures would warrant further investigation. Escalation would depend on factors such as the number of attempts, source, targeted accounts, successful authentication, privileged access and related endpoint activity.

## Recommended Response

For unexplained activity of this type, I would:

- validate whether the authentication attempts were expected;
- review the source and targeted account;
- check for successful authentication following the failures;
- review related activity on the affected host;
- protect or reset the account if compromise is suspected;
- block or investigate a malicious source where appropriate; and
- continue monitoring for repeated attempts.

## Conclusion

The main takeaway from this investigation was that Event ID 4625 alone does not prove an attack or compromise.

The useful part is correlating repeated failures with the account, source, timing and any successful authentication that follows them.