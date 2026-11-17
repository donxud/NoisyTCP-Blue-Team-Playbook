# SIEM Detection Content Update Policy

**Purpose:** make sure a newly disclosed, high-impact vulnerability such as NoisyTCP (CVE-2026-99288) becomes working, tested detection in the SIEM within a defined time, and that emergency rules are tuned and retired rather than left to rot.

**Scope:** all detection content (analytics rules, saved searches, Sigma sources, watchlists/lookups, SOAR triggers) in Sentinel, Splunk and Elastic.

## 1. Triggers for an emergency content update

Any one of these starts the process:

- CVSS 7.0+ or vendor rating Important/Critical affecting assets we run
- The vulnerability is on the CISA KEV list or has public exploit details
- Remote, unauthenticated impact on internet-facing services
- Management, the CSIRT or a vendor requests coverage

NoisyTCP met three: Red Hat CVSS 7.5 (Important), remote unauthenticated, and public technical details.

## 2. Service levels

| Stage | Emergency (trigger met) | Standard |
|---|---|---|
| Triage: decide whether detection is possible and useful | 4 business hours | 5 business days |
| First rule deployed (may be noisy, labelled `experimental`) | 1 business day | 15 business days |
| Tuned to `stable` | 10 business days | 30 business days |
| Coverage review / retirement decision | When the fleet is verified patched, or 90 days | Annual review |

## 3. Rule lifecycle

```text
proposed → experimental → stable → deprecated → retired
```

| State | Meaning | Who approves the move |
|---|---|---|
| proposed | Idea and data source identified | Detection engineer |
| experimental | Deployed; alerts go to triage queue, not paging | Detection lead |
| stable | False positive rate accepted; may page | Detection lead + SOC lead |
| deprecated | No longer needed (e.g. fleet patched); still runs at low severity | Detection lead |
| retired | Disabled and archived in version control | Detection lead |

CVE-specific rules (NoisyTCP Rules 1, 2 and 4) are reviewed for retirement once every in-scope host reports `FIXED`. Generic rules (kernel oops in network code, mitigation drift, unexpected reboot) stay as part of baseline coverage.

## 4. Required metadata on every rule

- Title, unique ID, author, date, version
- Description of the behaviour detected and why it matters
- References (advisory, vendor bulletin)
- MITRE ATT&CK mapping and CVE tag
- Data source and fields required, with the health check that proves they arrive
- Severity, and the condition that raises it (e.g. host unpatched)
- Known false positives and the triage steps
- Owner and next review date

## 5. Testing before deployment

1. **Syntax:** rule parses in the target SIEM; Sigma validates with `sigma check`.
2. **Data presence:** the required table, index or dataset has events from the in-scope hosts in the last 24 hours. A rule with no data is a silent gap, not coverage.
3. **True positive:** replay a known log sample (e.g. a recorded `Possible SYN flooding` message or a captured oops) into a test index and confirm the alert fires. Never trigger the real vulnerability on production.
4. **Noise estimate:** run the query over the last 14 days and record the expected alert volume.
5. **Peer review:** a second detection engineer reviews logic and metadata.

## 6. Change control

- All content is stored as code in version control; deployment from the repository, not hand edits in the console.
- Emergency content may deploy under a standard pre-approved change, with a ticket linking the CVE, the rule IDs and the test evidence.
- Any rule edited directly in production during an incident is committed back to the repository within one business day.

## 7. Supporting updates for each emergency

- **Log sources:** confirm kernel messages (facility `kern`), auditd EXECVE, and heartbeat are collected from all Linux hosts; add netconsole, serial console or pstore capture for crash messages where possible.
- **Watchlists / lookups:** create the patch-status list (e.g. `NoisyTCP_Unpatched`) and refresh it from the exposure check at least daily.
- **SOAR:** link each new rule to a playbook (`soar/noisytcp_soar_workflow.yml`) before it moves to `stable`.
- **Documentation:** update the playbook and the SOC triage notes.

## 8. Review

After each emergency update, record within 5 business days: time from disclosure to first rule, alert volume, true and false positives, data gaps found, and what to change in this policy.
