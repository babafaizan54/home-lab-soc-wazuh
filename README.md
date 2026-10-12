# Home Lab SOC & SIEM — Wazuh

A hands-on Security Operations Center (SOC) lab built using Wazuh, Windows 11, Sysmon, Ubuntu Server, Kali Linux, and VMware. This project focuses on endpoint monitoring, security alert investigation, custom detection rules, and documenting findings using the MITRE ATT&CK framework.

## Architecture

![Home Lab SOC Architecture](architecture/lab-architecture.svg)

## Lab Environment

| Component | Purpose | IP Address |
|---|---|---|
| Windows 11 | Monitored endpoint | `192.168.50.129` |
| Ubuntu Server | Wazuh Manager, Indexer, Dashboard | `192.168.50.130` |
| Kali Linux | Controlled security testing | `192.168.50.128` |
| Sysmon | Windows process and system telemetry | — |
| Wazuh Agent | Forwards configured Windows events | — |
| VMware | Virtual lab environment | — |

## Project Objectives

- Configure centralized endpoint monitoring with Wazuh.
- Collect Windows telemetry using Sysmon and the Wazuh Agent.
- Investigate process-creation and authentication-related alerts.
- Create and validate a custom Wazuh detection rule.
- Review command lines, process ancestry, user context, and event details.
- Document findings and limitations using a SOC investigation workflow.

## Detection and Investigation Results

### 1. PowerShell Process Execution

- Investigated Wazuh rule `92027`, which identifies a PowerShell process spawned by another PowerShell process.
- Examined the command line, process image, parent process, user, and available hashes.
- Classified the controlled test as benign.

**MITRE ATT&CK:** T1059.001 — PowerShell.

### 2. Failed Windows Authentication

- Generated controlled failed logon attempts.
- Investigated Windows Security Event ID `4625` and Wazuh rule `60122`.
- Reviewed the target account, logon type, failure status, and source address.
- Determined that the observed test was local activity, not evidence of a remote brute-force attack.

### 3. Windows Account Discovery

- Executed `net user` to enumerate local accounts.
- Investigated process-creation telemetry for `net.exe` and `net1.exe`.
- Reviewed the associated user and process context.
- Classified the controlled activity as benign.

**MITRE ATT&CK:** T1087 — Account Discovery.

## Custom Detection Rule

Custom rule ID `100100` detects the controlled marker `SOC-CUSTOM-DETECTION-01` in a matching PowerShell process-creation event.

Validation performed:

- **Positive test:** The configured marker triggered rule `100100`.
- **Negative test:** A different marker did not trigger rule `100100`.
- **Case-sensitivity test:** A lowercase marker did not trigger the rule.

The rule uses existing Wazuh rule `92027` as its parent. It demonstrates custom rule creation and validation; it is not a general-purpose malicious PowerShell detector.

See [`rules/custom-rules.xml`](rules/custom-rules.xml).

## Evidence

Screenshots of the dashboard and investigation results are available in the [`evidence/`](evidence/) directory.

## Investigation Methodology

1. Generate controlled activity in the isolated lab.
2. Check endpoint telemetry and Wazuh alerts.
3. Review process details, command lines, user context, and parent processes.
4. Examine the detection rule and relevant MITRE ATT&CK mapping.
5. Classify the activity as benign, suspicious, or inconclusive.
6. Document the evidence, reasoning, and limitations.

## Known Limitations

- The lab uses a small, isolated virtual network.
- Not every collected event generates a Wazuh alert.
- Raw-event archiving is disabled in the current configuration.
- A Kali-to-Windows Nmap scan was attempted, but its detection by Wazuh was inconclusive. No confirmed detection is claimed.
- The tested scenarios demonstrate specific behaviors and do not establish comprehensive detection coverage.

## Technologies

Wazuh · Sysmon · Windows 11 · Ubuntu Server · Kali Linux · VMware · MITRE ATT&CK · Nmap

## Disclaimer

This project was conducted in a controlled, isolated home lab for educational and defensive cybersecurity purposes. Testing was performed against virtual machines under my control.
