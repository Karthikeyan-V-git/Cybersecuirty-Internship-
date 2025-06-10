# Detection Use Case: New User Account Creation Followed by Privilege Escalation
![](./assets/user_escalation.jpg)

## Scenario Description
This detection identifies a suspicious behavior pattern where a new user account is created (Event ID 4720), followed by the addition of the user to the local Administrators group (Event ID 4732). This activity, especially if it occurs after business hours, may indicate unauthorized privilege escalation.

## Objective
To detect potentially malicious user creation and privilege escalation, particularly during non-business hours, which may suggest lateral movement or privilege abuse.

---

## Tools Used
- **Command Line Utility**: `net` command
  - `net user <username> <password> /add` – Create a new user.
  - `net localgroup administrators <username> /add` – Add user to Administrators group.
  - `net user <username> /delete` – Cleanup/removal.
- **SIEM**: Wazuh
- **Log Source**: Windows Event Logs (Security)
- **Lab Setup**:
  - One Windows 11 VM with Wazuh agent and Sysmon installed.
  - Wazuh server on Kali Linux for centralized log analysis.
  - Default security restrictions relaxed for test purposes.
  - Alerts configured for email and Telegram delivery.

---

## Event ID / Rule ID / Data Source Mapping
| Source        | Event ID / Field | Description                              |
|---------------|------------------|------------------------------------------|
| Windows Logs  | 4720             | New user account created                 |
| Windows Logs  | 4732             | User added to local group (Administrators) |
| Wazuh Rule    | 60210            | New User Creation Detected               |
| Wazuh Rule    | 60211            | Privilege Escalation Detected            |
| Custom Rule   | 100030           | New Admin User Created After Hours       |

---

## Detection Logic / Rules

### 1. Detect new user account creation.
```xml
<rule id="60210" level="7">
  <field name="win.system.eventID">4720</field>
  <description>New User Account Created</description>
  <options>no_full_log</options>
  <mitre>
    <id>T1136</id>
  </mitre>
</rule>
```

### 2. Detect privilege escalation (user added to local Administrators group).
```xml
<rule id="60211" level="10">
  <field name="win.system.eventID">4732</field>
  <description>User Added to Administrators Group</description>
  <options>no_full_log</options>
  <mitre>
    <id>T1068</id>
  </mitre>
</rule>
```

### 3. Custom rule to detect both events and evaluate time.
```xml
<!-- Rule 3: Correlate user creation and escalation after business hours -->
<group name="windows_privilege_escalation">
  <rule id="100030" level="13">
    <if_sid>60211</if_sid>
    <if_matched_sid>60210</if_matched_sid>
    <timeframe>360</timeframe>
    <description>Privilege Escalation Detected After New User Creation (Possible After Hours)</description>
  </rule>
</group>
```

---

## Attack Triggering Scenario
Triggered when an attacker creates a new user account and escalates its privileges using the `net` command, particularly during off-hours to evade detection.

---

### Log - New User Creation (Sample)
```json
{
  "eventID": "4720",
  "description": "A user account was created.",
  "userAccount": "testuser",
  "agent": {
    "name": "workstation",
    "ip": "192.168.1.5"
  },
  "eventTime": "2025-06-09T22:45:00Z",
  "creator": "Administrator"
}
```

### Log - Privilege Escalation (Sample)
```json
{
  "eventID": "4732",
  "description": "A member was added to a security-enabled local group.",
  "group": "Administrators",
  "member": "testuser",
  "agent": {
    "name": "workstation",
    "ip": "192.168.1.5"
  },
  "eventTime": "2025-06-09T22:46:30Z"
}
```

---

### Evidence / Alerts
![Wazuh](./assets/escalation_alert.png)
![Telegram](./assets/escalation_telegram.png)

---

### Analyst Notes / Recommendations
1. **What should an analyst do when this alert triggers?**
   - Validate if account creation was authorized.
   - Confirm if activity occurred outside business hours.
   - Investigate login activity and account usage.
   - Disable or remove the user account if deemed malicious.

2. **Possible false positives?**
   - Legitimate admin actions during maintenance windows.
   - Service accounts being created and escalated by scripts.

---

### Detection Status
✅ Detection tested successfully with alerts triggered and received via Telegram and Wazuh dashboard.
