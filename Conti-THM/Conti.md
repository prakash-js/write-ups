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

---

### Q2 What is the Sysmon event ID for the related file creation event?
> 11

**Explaination :**

Sysmon Event ID 11 records File Create events, logging whenever a process creates a new file on the system. During a ransomware attack, this event is particularly valuable because ransomware typically creates ransom notes and writes encrypted files to disk.

By analyzing Event ID 11, I was able to identify the file creation activity associated with the ransomware and correlate it with the originating process, helping confirm the malicious executable involved in the attack.

---

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

---

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

---

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
| sort _time
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

---

### Q6 The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?
> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe

**Explaination :**
The question indicated that the attacker migrated the process after gaining access to the compromised system. Since process migration can involve creating a thread inside another process, I searched for Sysmon Event ID 8 (CreateRemoteThread) within the previously identified attack timeframe.
```
index="*" EventCode=8 host="WIN-AOQKG2AS2Q7"
earliest="09/08/2021:12:51:55"
latest="09/08/2021:13:05:32"
| sort _time
```

The search returned two events. In the first event, I identified the following source and target process images:
```
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetImage: C:\Windows\System32\wbem\unsecapp.exe
```
The SourceImage shows the original process from which the remote thread was created, while the TargetImage identifies the process into which execution was migrated.

---

### Q7 The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?
> C:\Windows\System32\lsass.exe

**Explaination :**
The first event showed the attacker migrating from powershell.exe into unsecapp.exe. The second event showed the attacker-controlled unsecapp.exe targeting lsass.exe. Since lsass.exe contains credential material and was the process accessed during the hash-retrieval activity, the process image used for obtaining the system hashes was C:\Windows\System32\lsass.exe.

---

### Q8 What is the web shell the exploit deployed to the system?
> i3gfPctK1c2x.aspx

**Explaination :**
While investigating Q5, I reviewed the same Sysmon Event ID 1 process-creation results:

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
Among these events, one command at `2021-09-08 12:52:09` stood out: 
```
attrib.exe -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```
Two characteristics made the file suspicious:

 - Location: The file was located under the Exchange OWA authentication path, \owa\auth\, where a newly introduced, randomly named ASPX file warranted further investigation.
 - Filename: i3gfPctK1c2x.aspx had a random-looking name with no obvious functional meaning.

I did not conclude that the file was malicious based on its name or location alone. To verify whether it was being accessed through the web server, I pivoted to the IIS logs and searched for requests referencing the file:
```
index=main sourcetype=iis cs_method=POST
| search *i3gfPctK1c2x.aspx*
| table _time c_ip cs_method cs_uri_query cs_uri_stem
```
The search returned four events, all showing POST requests from 10.10.10.2 to: `/owa/auth/i3gfPctK1c2x.aspx`

Repeated POST requests to a randomly named ASPX file in the Exchange OWA path are consistent with active interaction with a web shell rather than the file merely existing unused on the server.

At this point, I had identified i3gfPctK1c2x.aspx as the deployed web shell and confirmed that it was being accessed through the web server. However, I had not yet determined how the file was initially deployed to the system.

---

### Q9 What is the command line that executed this web shell?
> attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx

**Explaination :**
This command line was already identified during the Q8 process investigation, where cmd.exe was the parent process and attrib.exe referenced the web-shell file. The -r option removes the read-only attribute from the ASPX file, while the IIS logs identified in Q7 showed successful POST requests to /owa/auth/i3gfPctK1c2x.aspx. Therefore, the command line associated with the web shell was: `attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx`.

---

### Q10 What three CVEs did this exploit leverage? Provide the answer in ascending order.
> CVE-2018-13374,CVE-2018-13379,CVE-2020-0796

**Explaination :**
According to the Task 1 description, the incident involved a compromised Exchange server. Based on this context, I researched Conti-related vulnerabilities affecting Exchange. My Splunk evidence, including the web shell in `\owa\auth\` and Autodiscover SSRF requests, pointed to the ProxyShell chain (`CVE-2021-31207`, `CVE-2021-34473`, `CVE-2021-34523`), but this was not the accepted answer.

Thanks to this [InfosecWriteups write-up](https://infosecwriteups.com/conti-ransomware-threat-hunting-with-splunk-5dfe72635dbe), which helped me find the appropriate answer to this question: `CVE-2018-13374, CVE-2018-13379, CVE-2020-0796`

