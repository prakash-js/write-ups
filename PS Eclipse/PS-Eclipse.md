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

## 1) A suspicious binary was downloaded to the endpoint. What was the name of the binary?

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
