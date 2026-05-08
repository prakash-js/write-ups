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

1) A suspicious binary was downloaded to the endpoint. What was the name of the binary?

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
