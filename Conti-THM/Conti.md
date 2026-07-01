# Conti

An Exchange server was compromised with ransomware. Use Splunk to investigate how the attackers compromised the server. 

---

# Task 1

Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird readme files settled on the Exchange server.  

Below is a copy of the ransomware note.

<img width="1128" height="375" alt="image" src="https://github.com/user-attachments/assets/07b2f8b8-ad59-483d-b980-1ac0bc580738" />


Read the latest on the Conti ransomware here (opens in new tab). 

---

Task 2

### 1) Can you identify the location of the ransomware?
> C:\Users\Administrator\Documents\cmd.exe

**Explaination: **
## Identifying the Ransomware Executable

To identify the ransomware executable, I used a correlation-based SPL query. Instead of reviewing every process individually, I filtered for executables that performed three key activities commonly associated with ransomware.

* **Process Creation (Sysmon Event ID 1):** Identifies executables that were launched.
* **Network Connection (Sysmon Event ID 3):** Identifies executables that established network connections, which may indicate communication with external systems or lateral movement.
* **File Creation (Sysmon Event ID 11):** Identifies executables that created files, a common behavior during ransomware execution when dropping ransom notes or writing encrypted files.

The query correlates the common **Image** field across these three Sysmon event types, returning only executables that appear in all of them. This reduces noise and highlights processes exhibiting multiple stages of ransomware behavior.

```spl
index="*" EventCode="1"
| fields Image
| search [ search index="*" EventCode="3" | fields Image ]
| search [ search index="*" EventCode="11" | fields Image ]
| stats count by Image
```

The query returned three executables that satisfied all three conditions. During manual analysis, I identified a suspicious executable located at:

```
C:\Users\Administrator\Documents\cmd.exe
```

Although the filename is **cmd.exe**, its location is highly suspicious. The legitimate Windows Command Prompt executable resides in `C:\Windows\System32\cmd.exe`

Attackers commonly disguise malware by naming it after legitimate Windows binaries and placing it in user-writable directories to evade casual inspection.

### Hash Verification

To retrieve the file hash from Sysmon, I executed the following SPL query:

```spl
index="*" Image="C:\\Users\\Administrator\\Documents\\cmd.exe"
| where Hashes!=""
| table Image, Hashes
```

I then submitted the extracted hash to VirusTotal for reputation analysis. VirusTotal reported that **52 out of 61 security vendors** detected the file as malicious, confirming that the executable was ransomware.

This analysis verified that the `cmd.exe` file located in the Administrator's **Documents** directory was a malicious binary rather than the legitimate Windows Command Prompt executable.
