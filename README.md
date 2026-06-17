# Wazuh Detection Engineering: FIM Escalation Lab

## Project Overview
This project demonstrates the design and implementation of an end-to-end security monitoring and automated incident response pipeline. By deploying File Integrity Monitoring (FIM), I established a controlled environment to detect, visualize, and automatically respond to unauthorized modifications of critical Windows system files in real-time.

## Architecture
The lab utilizes a multi-platform architecture to simulate professional SOC workflows:
**Windows Host (Wazuh Agent) -> Wazuh Manager (Detection Engine) -> SMTP Alerting**

*   **Wazuh Agent:** Monitors critical system paths and reports integrity changes.
*   **Wazuh Manager:** Processes events, applies custom rule overrides, and manages alert severity.
*   **Automated Response:** Configured SMTP integration for real-time security alerts (SOAR workflow).

## Key Skills
*   **Detection Engineering:** Creating and testing custom rules to reduce noise and escalate critical alerts.
*   **FIM (File Integrity Monitoring):** Monitoring system-critical assets for unauthorized changes.
*   **Incident Response:** Configuring SMTP/TLS for automated security notifications.
*   **MITRE ATT&CK:** Mapping detections to specific adversarial tactics (T1565.001 - Data Manipulation).

## Custom Rule Implementation
```xml
<group name="fim,windows">
  <rule id="100002" level="12" overwrite="yes">
    <if_sid>550</if_sid>
    <match>c:\\windows\\system32\\drivers\\etc\\hosts</match>
    <options>no_full_log</options>
    <description>CRITICAL: Unauthorized modification to Windows hosts file!</description>
    <mitre>
      <id>T1565.001</id>
    </mitre>
  </rule>
</group>
Lab Visualization & Evidence
1. Rule Registration
Confirmation that the custom rule has been successfully registered and active within the Wazuh manager.

2. Critical Alert Verification
Wazuh dashboard showing the successful escalation of the integrity violation to a Level 12 (Critical) alert.

3. Email Notification Workflow
Configuration of SMTP settings to enable real-time automated security notifications.

4. Alert Captured in Inbox
Real-time security notification received via email, demonstrating the complete detection and response pipeline.

Testing & Validation
To validate the detection pipeline, I simulated an unauthorized modification to the Windows hosts file:

Bash
# Modifying hosts file to trigger FIM alert
echo "127.0.0.1 malicious-site.com" >> C:\Windows\System32\drivers\etc\hosts
