# CrashDump

## Scenario
A suspicious executable was identified running on one of the compromised endpoints. Initial triage suggests that this process may have been leveraged by the threat actor to establish a foothold on the system. To support further malware analysis and behavioral reconstruction, a user‑mode process dump of the suspected executable has been provided.

---
In this lab, we were provided with a .dmp (Dump) file for analysis. A dump file is a snapshot of a running process’s memory at a specific point in time. It may contain process memory, loaded DLLs, running threads, stack data, handles, and other runtime information. Dump files are commonly used in malware analysis, debugging, crash investigation, and digital forensics because they can reveal hidden or injected malicious code directly from memory.

A process dump can be generated manually in Windows using Task Manager. To create one:
- Open Task Manager
- Navigate to the Details tab
- Right-click the target process (e.g., notepad.exe)
- Select Create dump file

Windows will then save the generated .dmp file, which can later be analyzed using forensic and debugging tools such as Volatility or WinDbg.
---

## Task 1

### Provide the operating system version.
> 
