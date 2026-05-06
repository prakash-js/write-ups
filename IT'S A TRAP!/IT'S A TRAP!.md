# TRAFFIC ANALYSIS EXERCISE : IT'S A TRAP! 


## LAN SEGMENT DETAILS FROM THE PCAP
* LAN segment range: 10.6.13[.]0/24 (10.6.13[.]0 through 10.6.13[.]255)
* Domain: massfriction[.]com
* Active Directory (AD) domain controller: 10.6.13[.]3 — WIN-DQL4WFWJXQ4
* AD environment name: MASSFRICTION
* LAN segment gateway: 10.6.13[.]1
* LAN segment broadcast address: 10.6.13[.]255

---

## Questions:

1) What is the IP address of the infected Windows client?

> 10[.]6[.]13[.]133

2) What is the mac address of the infected Windows client?

> 00:02:ba:54:95:22

3) What is the host name of the infected Windows client?

> DESKTOP-5AVE44C

4) What is the user account name from the infected Windows client?

> rgaines

---

## Explaination
Since the LAN segment details were already provided in the traffic capture, I used that information to understand the network layout and identify normal infrastructure IP addresses. Based on this, I excluded the domain-related IP, the default gateway IP, and the broadcast address to reduce unnecessary background traffic. I also filtered out SSDP traffic, because SSDP is used for normal UPnP device discovery inside a local network and does not indicate malicious behavior.

`ip.addr != 10.6.13.1 && ip.addr != 10.6.13.3 && ip.addr != 10.6.13.255 && !ssdp`

After applying these filters, I checked Statistics → Endpoints to identify which internal host was generating the most traffic. I observed that the IP address 10.6.13.133 had a much higher amount of data transfer compared to other hosts. Based on this unusual traffic volume, I suspected 10.6.13[.]133 as the infected system and continued my analysis focusing on this host.


<img width="452" height="266" alt="image" src="https://github.com/user-attachments/assets/7db30643-04bc-4f78-af61-1971d8ba3b8f" />


After identifying `10.6.13.133` as the suspected infected host, I updated the Wireshark display filter to focus only on this IP address by using

 `ip.addr == 10.6.13.133 && !ssdp`

 Then i started analyzing which protocols were consuming the most traffic from this host. To do this, I navigated to Statistics → Protocol Hierarchy, where I observed that TCP traffic carrying TLS accounted for the highest amount of data usage. HTTP traffic was the second highest, but it was much smaller compared to TLS traffic.


<img width="462" height="192" alt="image" src="https://github.com/user-attachments/assets/b7404c9e-82b2-4789-a439-1ddeba0be804" />


Based on this observation, I refined the filter further to focus on HTTP requests and TLS handshakes using the following filter:

`ip.addr == 10.6.13.133 && (http.request or tls.handshake.type eq 1)`

After applying this filter, the packet count was reduced to around 200 packets, making the traffic easier to analyze. I then attempted to exclude traffic related to common legitimate domains such as Google and Microsoft by using SNI-based exclusions, but this did not significantly reduce the packet count.

To continue the analysis, I sorted the packets in chronological order. Since most of the remaining traffic was TLS, I focused on the Server Name Indication (SNI) field, which reveals the domain name used during the TLS handshake. By reviewing the SNI values, it became easier to identify suspicious domains. For domains that did not appear legitimate or familiar, I verified them using VirusTotal to determine whether they were malicious or associated with known malware activity.

The first suspicious domain I identified was hillcoweb[.]com. At first, it appeared to be an unfamiliar and unknown domain, so I decided to verify it using VirusTotal. The VirusTotal results marked this domain as suspicious and malware
On VirusTotal, I was able to view detailed information about the domain, including detection results and reference links from security vendors and community reports. From these references, I learned that this domain has been associated with malicious activity and is commonly linked to payload delivery


<img width="538" height="140" alt="image" src="https://github.com/user-attachments/assets/68145b02-2959-40f6-9491-d0d5b32cdba5" />

<img width="553" height="81" alt="image" src="https://github.com/user-attachments/assets/fc2568cb-9455-4104-9c1f-2254c1a18cf4" />

<img width="554" height="417" alt="image" src="https://github.com/user-attachments/assets/9c4ebf5a-afa7-4bc9-af40-c3e930e9841d" />

From internet research, I learned that hillcoweb[.]com is part of the social-engineering stage of the attack. The website displays a fake system or update alert to mislead the user and instructs them to copy and execute a malicious command or script. The actual malware payload and command-and-control (C2) communication occur later through a different domain.

I continued my analysis by reviewing the PCAP file in chronological order to observe what network activity occurred after the hillcoweb request.

I observed new suspicious activity in the traffic capture after the hillcoweb[.]com interaction. The domain event-time-microsoft[.]org appeared shortly afterward and was flagged as malicious based on external reputation checks. This domain was involved in communication related to PowerShell activity, indicating that scripts were being sent from the infected host and responses were received from the server. During further research, I found references on ThreatFox, where event-time-microsoft[.]org is clearly documented and linked to hillcoweb[.]com, confirming that both domains are part of the same infection chain and ClickFix-style attack infrastructure.


<img width="524" height="160" alt="image" src="https://github.com/user-attachments/assets/14ab8453-7c77-47bb-b851-9a0a05365f30" />


<img width="528" height="233" alt="image" src="https://github.com/user-attachments/assets/14fbb99d-9f01-4481-92b3-05f4d8a50ddf" />


In addition, another domain, windows-msgas[.]com, was observed and was also marked as suspicious  by external reputation. Most of the HTTP traffic after this stage occurred between the infected host and windows-msgas[.]com. Although not all HTTP content was readable, I was able to identify first request  one HTTP stream containing clear text information that appeared to include system or device infromation details being sent from the host to the remote server. This behavior suggests post-infection activity involving data transmission from the infected system.

<img width="533" height="148" alt="image" src="https://github.com/user-attachments/assets/b63c3ba2-e095-4db8-b683-9e1d35ec5d1c" />

Among them, the domain windows-msgas[.]com was observed and was also marked as suspicious based on external reputation checks. Most of the HTTP traffic during this post-infection stage occurred between the infected host and windows-msgas[.]com. 

Although not all HTTP content was readable, I was able to clearly analyze the one HTTP transaction, which appeared as a single readable stream. This initial HTTP POST request contained clear-text system and device information sent from the infected host to a remote server.

The server then responded within the same HTTP session with a large, obfuscated PowerShell script, indicating delivery of a second-stage payload to the victim system. Following this exchange, multiple additional HTTP POST requests were observed;however, their contents were not readable, likely due to the use of the application/octet-stream content type, indicating binary or encoded data transmission.


<img width="520" height="76" alt="image" src="https://github.com/user-attachments/assets/be4fc799-7589-4273-9cbe-dec3a75e5a63" />


<img width="438" height="238" alt="image" src="https://github.com/user-attachments/assets/3b81236d-8af3-4084-b808-d9256635ca01" />


<img width="520" height="242" alt="image" src="https://github.com/user-attachments/assets/2f2254ec-0ec0-46b5-ba47-59701b45edc2" />


I observed that the HTTP Host header was set to eventdata-microsoft[.]live, a domain made to look like a Microsoft service, likely to make the malicious traffic appear legitimate and avoid detection.

From my understanding, the website Hillcoweb[.]com appears to be a payload delivery site. Based on public threat-intelligence resources, this activity matches a KongTuke malware campaign. In this type of attack, attackers compromise legitimate websites and use them to display fake CAPTCHA or verification pages. This deceptive technique is commonly referred to as ClickFix, where the victim is tricked into interacting with malicious content rather than being exploited directly.

During traffic analysis, I observed packets related to event-time-microsoft[.]org containing an obfuscated PowerShell script. In ClickFix-style attacks, victims are typically instructed to copy and paste a PowerShell command as part of a fake verification step. Based on this behavior, the script likely represents the initial user-executed stage, used to contact attacker-controlled infrastructure or prepare the system for further payload delivery.Additionally, VirusTotal community reports indicate that this URL is linked to Hillcoweb[.]com, further supporting its role within the same ClickFix-based payload delivery chain.

Continuing the analysis, I checked the next suspicious URL, varying-rentals-calgary-predict.trycloudflare[.]com, which helped connect the full story. While reviewing this domain on VirusTotal, I found IOC context linking it to the CORNFLAKE.V3 backdoor, which is also clearly documented in public threat-intelligence reports.

CORNFLAKE.V3 is a known backdoor malware with two variants, written in JavaScript and PHP, both of which retrieve payloads over HTTP. In this case, the observed traffic communicating with the varying-rentals-calgary-predict.trycloudflare[.]com  domain likely represents the infrastructure serving the backdoor.


During the same activity window, traffic to windows.php.net was also observed. This is significant because documented CORNFLAKE.V3 PHP campaigns use an in-memory PowerShell script to download a portable PHP runtime from windows.php.net, which is then used to execute the PHP-based backdoor locally. Although host-level execution artifacts are not visible in the PCAP, the network behavior closely aligns with this known technique.


After the PHP runtime is staged, the malware appears to communicate with command-and-control infrastructure using Microsoft-themed domains such as windows-msgas[.]com (104.21.112.1) and eventdata-microsoft[.]live. The use of Microsoft-like naming combined with Cloudflare-backed infrastructure is consistent with evasion techniques intended to blend malicious traffic into legitimate-looking network activity.


## POST INFECTION IOCs

During the analysis, the infected system was observed communicating with multiple domains that were flagged as malicious based on external reputation checks. These domains are likely part of the same infection infrastructure and were involved in payload delivery or command-and-control activity.


Hillcoweb[.]com (67.217.228.199)

dng-microsoftds[.]com (172.67.146.241)

 event-time-microsoft[.]org (104.21.24.186)

varying-rentals-calgary-predict[.]trycloudflare.com (104.16.230.132)

windows-msgas[.]com (104.21.112.1)

 eventdata-microsoft[.]live




    
