# Iron Sentinel — SOC Analyst Capstone

A simulated multi-stage intrusion against a Windows Server 2022 host, built and investigated end-to-end in a home lab. This project covers the full Tier-1 SOC analyst workflow: SIEM configuration, detection engineering, incident response, threat intelligence, and vulnerability assessment.

**[Watch the demo walkthrough →](https://somup.com/cO1UYlVnlRk)**

## Scenario

Acting as a SOC analyst for a simulated company, I built a home lab (Windows Server 2022 + Ubuntu/Splunk), wrote and validated detection rules against three MITRE ATT&CK techniques, investigated the resulting "incident," and produced the documentation a real SOC would generate — an incident response report, an attack timeline, a vulnerability assessment, and a threat intel tracker.

## Environment

- **Splunk Enterprise** (SIEM) — Ubuntu 22.04, ingesting Windows Security, Sysmon, and System logs via Universal Forwarder
- **Sysmon** — endpoint visibility (SwiftOnSecurity config)
- **Windows Server 2022** — simulated target host
- **Nessus Essentials** — vulnerability scanning
- **MITRE ATT&CK Navigator** — technique mapping
- **Python** — Nessus findings parser/automation

## What's in this repo

| Folder | Contents |
|---|---|
| [`detection-rules/`](./detection-rules) | 3 Splunk SPL queries, each mapped to a MITRE ATT&CK technique |
| [`incident-response/`](./incident-response) | Full Incident Response Report (IS-2026-001) |
| [`attack-timeline/`](./attack-timeline) | Technical timeline — commands run, evidence captured, detection results |
| [`vulnerability-scan/`](./vulnerability-scan) | Nessus scan findings + the Python script used to parse them |
| [`threat-intel/`](./threat-intel) | IOC tracker and MITRE ATT&CK Navigator layer (JSON) |
| [`scripts/`](./scripts) | `parse_nessus.py` — turns raw Nessus XML exports into a prioritized CSV |
| [`screenshots/`](./screenshots) | Supporting evidence referenced in the IR report |

## Detection rules at a glance

| Technique | MITRE ID | Result |
|---|---|---|
| Brute Force (NTLM) | T1110 | Validated — 3 windows exceeded threshold (28/22/24 attempts) |
| PowerShell Obfuscation | T1059.001 | Validated — command line captured in Sysmon |
| Off-Hours Login | T1078 | Logic verified against 720 historical events |

## Notable troubleshooting (the part that actually teaches you something)

- A multi-day gap in Splunk log forwarding went undetected until manually checked — now I check forwarder health at the start of every session.
- Raw XML-formatted Sysmon data doesn't behave like extracted Splunk fields — searches need raw text matching, not field syntax, unless extraction is explicitly configured.
- Not every detection rule needs a live-fired trigger to be considered validated — verifying logic against historical data is legitimate for time-boundary conditions.
- Offensive security tooling (Atomic Red Team) gets flagged by antivirus as malicious by design — manually scripting equivalent test commands avoided this while still exercising the same detection logic.

## Author

Logan — CompTIA Security+ certified, pursuing CySA+ and SSCP. Built as part of a cybersecurity certificate capstone.
