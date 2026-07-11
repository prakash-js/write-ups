# MS Sentinel: Introduction
---

# Task 1 : Microsoft Security Operations Analyst

### Q1 ) What security unit is responsible for protecting the organization against security threats?
> Security Operations Center

### Q2) Generally, which level of SOC Analyst is responsible for responding to incidents?
> SOC Level 2 Analyst

### Q3) Besides monitoring, what else do SOC Level 1 Analysts spend the majority of their time with?
> triage

**Explanation :**

`Security Operations Center`
- A Security Operations Center (SOC) is a security team or department that protects an organization from cyber threats and attacks.
- A SOC Analyst is a person in the SOC team whose role is to monitor systems, detect threats, analyze alerts, and respond to security incidents.

***The main goal of a SOC team is to reduce security risks in the organization.***

Their responsibilities include:
- Stopping active cyber attacks.
- Suggesting ways to improve security protection.
- Reporting policy violations to the correct people or teams.

A **Microsoft Security Analyst** is still a SOC Analyst, but they specifically work with Microsoft security technologies and environments.

Examples:

* Microsoft Sentinel
* Microsoft Defender
* Microsoft Entra ID

## SOC Analyst Levels and Responsibilities

A Security Operations Center (SOC) contains multiple analyst levels.  
Each level has different responsibilities based on skill and experience.

| SOC Level | Main Responsibility | Description |
|---|---|---|
| SOC Level 1 Analyst | Monitoring & Triage | Monitors alerts, reviews logs, identifies suspicious activity, and escalates serious incidents to higher levels. |
| SOC Level 2 Analyst | Incident Response & Threat Hunting | Investigates security incidents, responds to attacks, performs deeper analysis, and hunts for hidden threats. |
| SOC Level 3 Analyst | Advanced Threat Hunting & Security Analysis | Handles advanced threats, malware analysis, threat intelligence, vulnerability management, and improves detection rules. |


## Simple Explanation

- **Level 1 (L1)** → First line of defense. Watches alerts and monitors systems.
- **Level 2 (L2)** → Investigates and responds to threats.
- **Level 3 (L3)** → Handles advanced attacks and improves overall security operations.

---

# TASK 2 : Introduction to Microsoft Sentinel

### Q1) Microsoft Sentinel is a combination of two security concepts, namely SIEM and which other one?
> SOAR

### Q2) Creating security alerts and incidents is part of which security concept?
>SIEM

### Q3) By means of how many pillars does Microsoft Sentinel help us to perform security operations?
> 4

**Explaination :**

***SIEM*** 

SIEM stands for Security Information and Event Management. SIEM is a security system that collects and correlates logs from different devices, analyzes them for suspicious activity, and generates alerts for security teams.

***SOAR***

SOAR stands for Security Orchestration, Automation, and Response. SOAR acts like a SIEM by detecting threats and generating alerts, but it can also automate response actions such as blocking IPs, disabling accounts, creating tickets, and sending notifications.

***Microsoft Sentinel***

Microsoft Sentinel is a cloud-native SIEM and SOAR solution that can collect, detect, investigate, and respond to security threats.

`Collection:`

Sentinel uses Data Connectors to collect logs and security data from different sources.

`Detection:`

Sentinel uses Analytics Rules to detect suspicious activities and generate alerts.
An Analytics Rule is a rule that analyzes logs and creates alerts when suspicious activity is detected.

`Investigation:`

Sentinel helps analysts investigate incidents using dashboards, incidents, entities, and threat intelligence.

`Response:`

Sentinel uses Playbooks to automate response actions such as blocking IPs, disabling accounts, creating tickets, and sending notifications.

---

# TASK 3 How Microsoft Sentinel Works

### Q1) What is used to ingest data into Sentinel?
> data connectors

### Q2) Where are the ingested logs stored for further correlation and analysis?
> log analytics workspaces

### Q3) Workbooks are essentially _______ used for visualization.
> dashboards

### Q4) When SOC teams are flooded with security alerts and incidents, this is called?
> alert fatigue

### Q5) In Microsoft Sentinel, automation is done via automated workflows, known as?
> playbooks

### Q6) The output of running Analytics rules includes security alerts and?
> Incidents

**Explanation :**

Microsoft Sentinel works in four main phases: Collect, Detect, Investigate, and Respond.

`1. Collect`

Sentinel first collects logs and security data from different devices, applications, cloud services, and networks using Data Connectors. These logs are stored in Log Analytics Workspace, where analysts can search and analyze them using KQL (Kusto Query Language).

`2. Detect`

After collecting logs, Sentinel analyzes them to detect suspicious activities.
- Workbooks help visualize logs and security data through dashboards.
- Analytics Rules analyze logs and generate alerts when suspicious behavior is detected.
- Threat Hunting allows analysts to proactively search for hidden threats using hunting queries.

`3. Investigate`

When an alert is triggered, Sentinel creates an Incident for analysts to investigate.
Analysts can:
- Review alert details
- Analyze timelines
- Map related entities like users, IPs, and devices
- Add comments and assign incidents to other analysts

`4. Respond`

Sentinel uses Playbooks to automate security responses and reduce alert fatigue.
Playbooks can:
- Block malicious IPs
- Disable compromised accounts
- Send notifications
- Create tickets
- Perform automated remediation actions

These four phases help SOC analysts continuously monitor, detect, investigate, and respond to cyber threats efficiently.

---

# TASK 4 :  When To Use Microsoft Sentinel

Q1) Organizations use Microsoft Sentinel mainly because they need to _______ their cloud infrastructure.
> monitor

Q2) With Microsoft Sentinel, there is no need for server provisioning. This means it is?
> cloud-native

**Explanation :**

Microsoft Sentinel is a cloud-native SIEM and SOAR solution that helps organizations collect logs, detect threats, investigate incidents, and automate security responses across cloud and on-premises environments.

***Features :***
- Centralized security monitoring
- Real-time threat detection
- Automated response using playbooks
- Easy integration with Azure and other data sources

---
# Task 5: Conclusion 

### Q1 I understand how Microsoft Sentinel works!
> No answer needed
