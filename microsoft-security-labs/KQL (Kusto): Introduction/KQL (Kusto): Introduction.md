# KQL (Kusto): Introduction
---

## Taks 1

### Q1 Let's go!
> No answer needed

## Task 2

### Q1 In addition to being a SIEM solution, what else is Microsoft Sentinel? (use the abbreviation)
> SOAR

** Explaination :**

- Microsoft Sentinel acts as a SIEM by collecting, monitoring, and analyzing security logs from multiple sources to detect threats and suspicious activities.
- Microsoft Sentinel also functions as a SOAR platform by automating security responses, orchestrating workflows, and reducing manual incident handling through playbooks and automated actions.

### Q2 How does MS Sentinel support other security solutions that are not included in the built-in connectors? 
> REST API Integration

** Explaination :**

- Microsoft Sentinel supports third-party and unsupported security solutions through REST APIs, allowing external tools and applications to send security data, alerts, and incidents into Sentinel for monitoring and response.

## Task 3
```
| summarize AggregatedHeartbeatCount = count() by Computer
| order by AggregatedHeartbeatCount desc
| take 10
```
### Q1 What initial service was KQL created for?
> Azure Data Explorer

** Explaination :**

- Kusto Query Language (KQL) was originally created for the Azure Data Explorer (Kusto) service at Microsoft. It was designed to efficiently analyze massive amounts of telemetry, log, and monitoring data in real time.

- Later, Microsoft expanded KQL into other services such as Microsoft Sentinel, Azure Monitor, and Microsoft Defender to support security analysis, threat hunting, and cloud monitoring.

### Q2 Analyze the example query from the task. How many computers will the query return?
> take 10

**Explaination :**

`take 10` limits the output to only the first 10 results after sorting.

### What table is the example query retrieving its data from?

> Heartbeat

** Explaination :**

The query retrieves data from the Heartbeat table because the first line in a KQL query specifies the data source or table being used. All the summarize, sorting, and filtering operations are performed on the records stored in the Heartbeat table.

# Task 4

```
SecurityEvent
| where TimeGenerated >= ago(3h) and TargetUserName == "JBOX00$"
| project TimeGenerated, Account, Activity, Computer
| sort by TimeGenerated desc
```
### Q1 What operator can be used to output results in graphical form?
> render

**Explaination :**

`render` converts the query output into a visual chart or graph.

### Q2 What operator can be used to filter a specified table based on specified conditions?
> Where

**Explaination :**

where filters the table and returns only rows that match the condition.


### Q3 What user account name was queried in our second example query above?
> JBOX00$

**Explaination :**

The where operator filters the logs and searches for records where:
`TargetUserName == "JBOX00$"`
So the query is specifically looking for activity related to the JBOX00$ account.

## Task 5
```
SecurityEvent
| where TimeGenerated > ago(1d)
| summarize EventCount = count() by Computer
| order by EventCount desc | limit 10 
```

### Q1 What is the name of the table queried in our example query?

> SecurityEvent

**Explaination :**

In KQL, the first line specifies the table being used: `SecurityEvent`

### Q2 Analyze the example query from the task. What does the query aggregate per computer?
> EventCount

**Explaination :**

The query uses `summarize EventCount = count() by Computer ` This creates a value called EventCount that stores the count of events for each computer.


## Task 6

```
SecurityEvent
| where EventID == 4625
```

### Q1 What are we searching for in the SecurityEvent table on the first query?
 > failed login attempts
 
 **Explaination :**

The condition `EventID == 4625` filters events with Event ID 4625, which in Windows Security Logs represents a failed login attempt.

### Q2 Which operator was used on the second query to streamline our search to a range of user accounts from the TargetUserName column? 
> contains

**Explaination :**

The contains operator searches for a specific word or text pattern inside a column value. In this query, it checks whether the TargetUserName column contains the word "admin", helping filter multiple related user accounts.
