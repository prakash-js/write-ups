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

<img width="1117" height="172" alt="image" src="https://github.com/user-attachments/assets/d6db74ed-abea-4543-ba97-669ce4f42459" />


</br>
This analysis verified that the `cmd.exe` file located in the Administrator's **Documents** directory was a malicious binary rather than the legitimate Windows Command Prompt executable.

### Q2 What is the Sysmon event ID for the related file creation event?
> 11

**Explaination: **

Sysmon Event ID 11 records File Create events, logging whenever a process creates a new file on the system. During a ransomware attack, this event is particularly valuable because ransomware typically creates ransom notes and writes encrypted files to disk.

By analyzing Event ID 11, I was able to identify the file creation activity associated with the ransomware and correlate it with the originating process, helping confirm the malicious executable involved in the attack.

### Q3 Can you find the MD5 hash of the ransomware?
> 290C7DFB01E50CEA9E19DA81A781AF2C

**Explaination :**

The MD5 hash was extracted from the Sysmon Hashes field for the suspicious executable identified in Question 1.

```
index="*" Image="C:\\Users\\Administrator\\Documents\\cmd.exe"
| where Hashes!=""
| table Image, Hashes
```

The extracted hash was then verified using VirusTotal, where 52 out of 61 security vendors identified the file as malicious, confirming that the executable was the Conti ransomware.
