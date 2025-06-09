# Log Tampering Simulation Detection

## Scenario

This simulation involves detecting potential log tampering activities in a Windows environment. The attacker attempts to clear logs using tools like `wevtutil`, `auditpol`, and PowerShell cmdlets such as `Clear-EventLog`.

## Tools/Commands Used

- `auditpol`
- `wevtutil`
- `Clear-EventLog` (PowerShell)

## Detection Rules

### 1. Base Rule - Security Event Log

```xml
<rule id="63103" level="10">
    <if_sid>63108</if_sid>
    <field name="win.system.eventID">^1102$</field>
    <description>
      The audit log was cleared by user: $(win.logFileCleared.subjectUserName)
        Log from : Security
    </description>
    <mitre>
      <id>T1070</id>
    </mitre>
    <group>log_clearing_auditlog,gpg13_10.1,gdpr_II_5.1.f,gdpr_IV_30.1.g,</group>
</rule>
```

### 2. Base Rule 2 - Sysmon Log

```xml
<rule id="61603" level="5">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID">^1$</field>
  <description>Sysmon - Event 1: Process creation $(win.eventdata.description)</description>
  <group>sysmon_event1,</group>
</rule>
```

### 3. Custom Rules - Group: `log_tamper`

```xml
<group name="log_tamper">
<rule id="100025" level="10">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.originalFileName">^wevtutil.exe$</field>
  <description> 
    Possible log clear done (Log Generated from - Sysmon)  
    Command used: $(win.eventdata.commandLine)  
    Agent : $(win.eventdata.user)
  </description>
  <group>sysmon, suspicious, windows</group>
</rule>

<rule id="100026" level="10">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.originalFileName">^AUDITPOL.EXE$</field>
  <description> 
    Audit Policy - Command Run (Log Generated from - Sysmon)  
    Command used: $(win.eventdata.commandLine)  
    Agent : $(win.eventdata.user)
  </description>
  <group>sysmon, suspicious, windows</group>
</rule>
</group>
```

## Trigger Scenarios

- `wevtutil cl Security`
  - Triggers Base Rule 1 (Event ID 1102)
  - Triggers Sysmon Rule 61603 leading to detection via rule `100025`
  - Works even if executed via PowerShell

- `Clear-EventLog -Logname Security`
  - Triggers Base Rule 1

- Any `auditpol` command
  - Triggers Sysmon Rule 61603 leading to detection via rule `100026`
  - Works even if executed via PowerShell