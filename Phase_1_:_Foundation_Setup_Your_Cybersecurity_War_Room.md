# 🛡️ Phase I: Foundation Setup — Your Cybersecurity War Room
![](./assets/Phase_1.png)

**Duration:** Day 1 — Day 7  
**Objective:** Build a personal cybersecurity lab environment and configure basic monitoring and detection capabilities.

---

## 🎯 Phase Goals

- Set up a virtual SOC environment
- Configure log generation and forwarding
- Implement basic detection rules
- Track progress and maintain documentation

---

## 🛠️ Tools Used

| Category        | Tool              |
|----------------|-------------------|
| SIEM            | Wazuh             |
| Log Source      | Windows 11 VM     |
| Log Agent       | Winlogbeat, Sysmon|
| Platform        | VirtualBox        |

---

## 1️⃣ Lab Setup

### ✅ Configured Virtual Environment:
- **One Windows 11 VM** (Target/Victim)
- **One non-virtual SIEM box** with **Wazuh** (deployed separately)

📸 Screenshot:  
![VM Setup](./screenshots/vm_setup.png)

---

## 2️⃣ Log Agent Installation & Configuration

### ✔️ Installed Sysmon
- Used `Sysinternals` from Microsoft
- Configured with a recommended template

📥 Download: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)  
📄 Template: [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

📸 Screenshot:  
![Sysmon Running](./screenshots/sysmon_running.png)

---

### ✔️ Installed Winlogbeat
- Configured Winlogbeat to send logs to Wazuh
- Edited `winlogbeat.yml` to enable Wazuh output

📥 Download: [Winlogbeat](https://www.elastic.co/downloads/beats/winlogbeat)

📸 Screenshot:  
![Winlogbeat Logs](./screenshots/winlogbeat_logs.png)

---

## 3️⃣ Log Collection Verification

- Checked Wazuh dashboard for incoming logs
- Verified Sysmon logs for process creation, network events, and login attempts

📸 Screenshot:  
![Wazuh Log View](./screenshots/wazuh_log_view.png)

---

## 4️⃣ Summary

Successfully completed foundational setup of a SOC-style lab environment. Logs are flowing from the Windows victim VM to the Wazuh SIEM.

Next up: Detect and alert on brute-force attempts and login anomalies.

---

## 🔗 References & Downloads

See [references.md](./references.md) for all download links and documentation references.
