Project: Wazuh Detection Engineering - FIM EscalationOverviewThis project documents the development of a custom security detection pipeline within a Wazuh-based Security Operations Center (SOC) home lab. The objective was to improve incident prioritization by escalating standard File Integrity Monitoring (FIM) alerts for high-value system configuration files from generic logs to actionable, critical-severity incidents.Technical ChallengeThe default Wazuh FIM rule (ID 550) triggers for any monitored file modification, creating significant "noise" in a production environment. Additionally, during implementation, I encountered path normalization issues where the system path was being evaluated in lowercase, causing custom rules to fail to match the specific file being targeted.ImplementationTarget Asset: Windows hosts file (C:\Windows\System32\drivers\etc\hosts).Strategy: Implemented a custom rule in local_rules.xml using overwrite="yes" to intercept Rule 550 and re-classify the event.Resolution: Resolved path matching issues by utilizing the <match> tag with case-insensitive logic to ensure reliable alert escalation.Custom Rule DefinitionXML<group name="fim,windows">
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
ResultsBy mapping this event to the MITRE ATT&CK Tactic: Impact (T1565.001 - Data Manipulation), the security team is now immediately notified of unauthorized modifications to this critical file via a Level 12 (Critical) alert.VerificationAlert LevelRule IDDescription7 (Medium)550Integrity checksum changed (Default)12 (Critical)100002CRITICAL: Unauthorized modification to Windows hosts file!(See /docs/image_364949.png for dashboard confirmation of the escalation).
