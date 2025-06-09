# Detection Use Case: Brute Force Followed by Successful Login

## Scenario Description
This detection identifies a brute force login attempt where multiple failed login events (Event ID 4625) are followed by a successful login (Event ID 4624) from the same IP address. In this scenario, 8 failed login attempts occurred on a desktop machine, followed by one successful login.

## Objective
To detect potential brute force attacks that result in a successful login, which may indicate unauthorized access after credential guessing.

## Tools Used
- SIEM: Wazuh
- Log Source: Windows Event Logs (via Winlogbeat + Sysmon)
- Lab Setup: 
  - One Windows 11 desktop VM with Wazuh agent, Sysmon, and Winlogbeat installed.
  - Wazuh server running on Kali Linux for centralized log collection and alerting.
  - Alerts configured via email and Telegram.

## Event ID / Data Source Mapping
| Source        | Event ID / Field | Description                      |
|---------------|------------------|----------------------------------|
| Windows Logs  | 4625             | Failed login attempt             |
| Windows Logs  | 4624             | Successful login                 |
| Sysmon        | N/A              | (Not used in this detection)     |

## Detection Logic / Query
```
<!-- Rule 1: Detect multiple failed login attempts -->
<rule id="60204" level="10" frequency="$MS_FREQ" timeframe="240">
  <if_matched_group>authentication_failed</if_matched_group>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>Multiple Windows Logon Failures</description>
  <options>no_full_log</options>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```
```
<!-- Rule 2: Detect successful login -->
<rule id="60106" level="3">
  <field name="win.system.eventID">^528$|^540$|^673$|^4624$|^4769$</field>
  <description>Windows Logon Success</description>
  <options>no_full_log</options>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
```
```
<!-- Rule 3: Correlate both to indicate brute force success -->
<group name="windows_brute_force">
  <rule id="100021" level="12">
    <if_sid>60106</if_sid>
    <if_matched_sid>60204</if_matched_sid>
    <description>Successful Login After Possible Brute Force</description>
  </rule>
</group>
```
