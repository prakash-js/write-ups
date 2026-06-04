# Benign

Benign - Premium room

Challenge room to investigate a compromised host.


## TASK 2 Scenario: Identify and Investigate an Infected Host

### Q1 How many logs are ingested from the month of March, 2022?
>  13959

**Explaination :**
- To determine how many logs were ingested during March 2022, I logged into Splunk and used the time picker on the left side of the interface. I selected Date Range, chose the Since option, and entered the date 01/03/2022.

- To view the total number of logs, I executed the following search `index="*"`

- From the search results, Splunk displayed a total event count of 13,959 events, indicating the number of logs ingested for the selected time range.


### Q2 Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?
>  Amel1a

**Explaination :**
- To identify the suspected imposter account, I first listed all usernames and their occurrence counts using the following Splunk query:
```
index="*"
| stats count by UserName
```

- While reviewing the results, I noticed two very similar usernames:
    - Amelia
    - Amel1a

- This technique is known as typosquatting (or impersonation through look-alike characters), where an attacker creates an account name that     closely resembles a legitimate user's account in an attempt to deceive users or evade detection.

### Q3 Which user from the HR department was observed to be running scheduled tasks?
> Chris.fort

**Explaination :**

- I first searched for all schtasks activity:
```
index=win_eventlogs (*schtasks*)
| table CommandLine, UserName
```
This returned approximately 87 events, and almost every user had executed schtasks commands, making it difficult to identify the correct user.

- Since the question mentioned users running scheduled tasks, I next searched for commands containing /Run, which is used to execute an existing scheduled task:
```
index=win_eventlogs (*schtasks* AND *run*)
| table CommandLine, UserName
```
This search returned no results.


- I then investigated common scheduled task triggers such as ONSTART, ONLOGON, and DAILY, which are frequently used when creating scheduled tasks. Searching for these trigger values narrowed the results:
```
index=win_eventlogs (*schtasks* AND *ONSTART*)
| table CommandLine, UserName
```
This revealed the command: `schtasks /create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart`

- The associated user was Chris.fort, indicating that Chris.fort was the HR user observed using scheduled tasks.

### Q4 Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host. 
> Haroon

**Explaination :**
- The question explicitly mentions a LOLBIN (Living Off The Land Binary), which refers to a legitimate Windows binary that can be abused to perform malicious actions. Common LOLBINs used for downloading payloads include `certutil.exe`, `powershell.exe` (`Invoke-WebRequest`), and `curl.exe`.

- To identify the user who downloaded a payload using a LOLBIN, I searched for common download-related LOLBIN commands:

```spl
index="*"
("Invoke-WebRequest" OR "certutil" OR "curl")
| table CommandLine, UserName
```

- The search results revealed that **haroon** executed `certutil.exe` to download the file **e4d11035_benign.exe** from **controlc.com**, indicating that haroon was the HR user who used a LOLBIN to download a payload from a file-sharing host.

