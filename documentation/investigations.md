# Home Lab SOC — Investigation Notes

## Lab Environment

- **SIEM:** Wazuh
- **Endpoint monitoring:** Sysmon
- **Endpoint:** Windows 11
- **Analysis system:** Ubuntu Wazuh server
- **Test system:** Kali Linux
- **Virtualization:** VMware
- **Windows endpoint IP:** 192.168.50.129
- **Wazuh server IP:** 192.168.50.130

## Investigation 1: PowerShell Process Execution

**Objective:** Validate endpoint process monitoring and investigate a PowerShell process alert.

**Test activity:** Executed a controlled PowerShell command that printed `SOC-LAB-TEST-01`.

**Evidence observed:**
- Sysmon Event ID 1 recorded the process creation.
- Wazuh generated rule `92027`, level 4.
- The alert description was `Powershell process spawned powershell instance`.
- The command line, process image, parent process, user and process hashes were available.

**Analysis:** The command was intentionally executed in the lab. The observed activity was benign. PowerShell execution alone is not evidence of malicious activity; the command line and process ancestry must be examined.

**MITRE ATT&CK:** T1059.001 — PowerShell.

**Evidence:** `investigation-01-powershell-wazuh-alert.png`

## Investigation 2: Failed Windows Authentication

**Objective:** Validate collection and detection of failed Windows logons.

**Test activity:** Intentionally entered an incorrect password during a controlled `runas` test.

**Evidence observed:**
- Windows Security Event ID 4625 was detected.
- Wazuh generated rule `60122`, level 5.
- The target account was `socuser`.
- The logon type was 2 (interactive).
- The source address was `::1` (IPv6 loopback).
- The failure status indicated an incorrect password.

**Analysis:** The failures were intentionally generated during testing. The loopback source and interactive logon context do not support classifying this test as a remote brute-force attack. Multiple failed logons in a short period warrant investigation in a real environment.

**MITRE ATT&CK note:** The Wazuh rule included T1531, but the observed event was a failed logon. A rule's mapping is a reference for investigation, not proof that the mapped technique occurred.

**Evidence:** `investigation-02-windows-authentication-alert.png`

## Investigation 3: Windows Account Discovery

**Objective:** Test detection of local account enumeration.

**Test activity:** Executed `net user` to list local user accounts.

**Evidence observed:**
- Sysmon Event ID 1 recorded process creation.
- Wazuh rule `92031`, level 3, generated an alert.
- The alert mapped to T1087 — Account Discovery.
- The process chain included `net.exe` and `net1.exe`.
- The interactive execution was associated with `DESKTOP-1TI7A9U\\socuser`.

**Analysis:** The command was intentionally run for this lab and was benign. The same command can be used by an attacker for account discovery, so the process ancestry, user context and surrounding events are important.

**Evidence:** `investigation-03-account-discovery-wazuh-alert.png`

## Custom Detection Rule Validation

**Custom rule ID:** 100100  
**Severity:** Level 7  
**Purpose:** Detect a controlled PowerShell marker when it appears in a matching PowerShell process-creation event.

**Positive test:** `SOC-CUSTOM-DETECTION-01` triggered rule 100100.

**Negative test:** `SOC-CUSTOM-NEGATIVE-TEST` did not trigger rule 100100.

**Case-sensitivity test:** `soc-custom-detection-01` did not trigger rule 100100.

**MITRE ATT&CK:** T1059.001 — PowerShell.

**Result:** The rule behaved as configured in the tested cases. This is a controlled demonstration of rule matching, not a general-purpose detection for malicious PowerShell.

**Evidence:** `custom-rule-powershell-detection.png`

## Network Visibility Limitation

A Kali-to-Windows Nmap scan was attempted in the isolated lab. The target was reported up, but the tested ports were filtered. No matching Sysmon Event ID 3 for the Kali address was found in the checks performed, and no corresponding alert was confirmed.

**Conclusion:** The scan's detection was inconclusive. Do not claim that Wazuh detected the scan. Raw-event archiving was disabled, so the absence of a matching record in `archives.json` does not prove that the endpoint never recorded the activity.

## Investigation Method

For each test, the workflow was:

1. Generate controlled activity in the lab.
2. Check endpoint telemetry and Wazuh alerts.
3. Examine the command line, user, process image and parent process where available.
4. Review the alert rule and MITRE ATT&CK mapping.
5. Decide whether the observed activity was benign, suspicious or inconclusive.
6. Record the evidence and limitations.

## Limitations

- The lab uses a small, isolated virtual network.
- Not every endpoint event necessarily produces a Wazuh alert.
- Raw-event archiving is disabled.
- The network scan was not confirmed as detected.
- Results from these controlled tests do not establish detection coverage against all attack techniques.