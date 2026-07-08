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

**Explaination:**
 
Identifying the Ransomware Executable

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

Hash Verification

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

### Q4 What file was saved to multiple folder locations?
> readme.txt

**Explaination :**

Since the lab focuses on post-incident investigation, I first identified when the ransomware executable started running. I searched for the process creation event associated with the previously identified malicious executable:
```
index="*" EventCode="1" Image="C:\\Users\\Administrator\\Documents\\cmd.exe"
| sort _time
```

The earliest relevant process creation event occurred at: `08/09/2021 13:05:32.000`

I used this timestamp as the starting point for the investigation and focused on Sysmon Event ID 11, which records file creation events. I also restricted the search to the affected Exchange server to reduce unrelated events.

```
index="*" host="WIN-A0QKG2AS2Q7" EventCode="11"
| eval FileName=mvindex(split(TargetFilename,"\\"),-1)
| stats count by FileName
| sort - count
````
The TargetFilename field contains the full path of each created file. The split() function separates the path at each backslash (\), and mvindex(...,-1) selects the final value, leaving only the filename.

I then used stats count by FileName to count how many times each filename appeared and sorted the results in descending order. The results showed that readme.txt was created 18 times, while the other files appeared only once.

This identified readme.txt as the file saved across multiple folder locations, consistent with ransomware behavior of distributing ransom notes throughout affected directories.

<img width="1568" height="427" alt="image" src="https://github.com/user-attachments/assets/20524c27-62df-4aaf-805e-628a1d831919" />

### Q5 What was the command the attacker used to add a new user to the compromised system?
> net user /add securityninja hardToHack123$

**Explaination :**
I initially suspected that the user-creation command would appear after cmd.exe execution, but the timeline did not support that assumption.

I then analyzed Sysmon Event ID 3 network connections and filtered out loopback and self-connections. 

```
index=* host="WIN-AOQKG2AS2Q7" EventCode=3
| where NOT Like(DestinationIp,"0:0:0:0:0:0:0:1") 
| where NOT Like(DestinationIp,"10.10.10.6") 
| where DestinationIp != "" 
| table _time SourceIp SourcePort DestinationIp DestinationPort
| sort time
```
This left communication with 10.10.10.4 and 10.10.10.2. I identified 10.10.10.4 as the DNS server based on repeated connections to DNS-related ports.

I then narrowed the investigation window between the first suspicious external connection and the later cmd.exe activity
```
index="*" EventCode=1 host="WIN-AOQKG2AS2Q7"
earliest="09/08/2021:12:51:55"
latest="09/08/2021:13:05:32"
| where NOT like(Image, "%Splunk%")
| where NOT like(ParentImage, "%Splunk%")
| where isnotnull(Image) AND Image!=""
| table _time Image ParentImage ParentCommandLine CommandLine
| sort _time
```

Searching Sysmon Event ID 1 process-creation logs within this period revealed the command `net user /add securityninja hardToHack123$` at `2021-09-08 13:04:10`.
