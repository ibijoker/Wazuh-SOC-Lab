Wazuh Detection Engineering: FIM Escalation Pipeline
Overview
This project documents the development of a custom security detection pipeline within a Wazuh-based Security Operations Center (SOC) home lab. The objective was to improve incident prioritization by escalating standard File Integrity Monitoring (FIM) alerts for high-value system configuration files from generic logs to actionable, critical-severity incidents.

Technical Implementation
Target Asset: Windows hosts file (C:\Windows\System32\drivers\etc\hosts).

Strategy: Implemented a custom rule in local_rules.xml using overwrite="yes" to intercept Rule 550 and re-classify the event.

Resolution: Resolved path matching issues by utilizing the <match> tag with case-insensitive logic to ensure reliable alert escalation.

Custom Rule Definition
XML
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
2. Critical Alert Verification
3. Email Notification Workflow
4. Alert Captured in Inbox
