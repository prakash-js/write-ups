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
Windows will then save the generated .dmp file, which can later be analyzed using forensic and debugging tools such as Volatility or WinDbg

The provided .dmp file was analyzed using WinDbg. The dump file was loaded by navigating to File → Start Debugging → Open Dump File, then browsing and selecting the .dmp file. The target architecture was set to Auto Detect before loading the file.

---


## Task 1

### Provide the operating system version.
> 10.0.10240.16384

**Explaination :**

As an initial step, I opened the `update.dmp` file in WinDbg because the scenario mentioned a suspicious executable that may have been used by the attacker to establish a foothold on the compromised system. After loading the dump file, WinDbg suggested running the !analyze -v command for verbose analysis. I executed the command to perform an initial inspection of the dump file and gather debugging and process-related information from memory. From the analysis output, I identified the operating system version as `10.0.10240.16384` along with other system information.

## Task 2

Provide the full path of the malicious executable used to gain initial access.
> C:\Users\s1rx\Downloads\update.exe

**Explaination :**

After executing the !analyze -v command in WinDbg, I reviewed the analysis output and checked the MODULE_NAME: update section, which contained information related to the suspicious process. From this section, I identified the image path: `C:\Users\s1rx\Downloads\update.exe`

## Task 3

How many threads did the malicious process use?
> 6

**Explaination :**

To find the number of threads, I used the ~ command in the WinDbg command box. The output lists all threads starting from index 0, so the total count is the last index + 1. In this case, the last index was 5, giving us 6 threads in total.

## Task 4

- A named pipe is an IPC (Inter-Process Communication) channel used by processes to communicate with each other on the same system or across a network.

- To identify the named pipe used by the suspicious process, I first inspected the process handles in WinDbg using the command
<br>`!handle 0 f`

- This command displays detailed information about handles opened by the process, including files, events, registry keys, and possible IPC-related objects. I then used the search feature (Ctrl + S) to search for the keyword Pipe because named pipes are commonly associated with IPC communication in malware activity.

- During the review, I identified the handle
<br>`Handle 000000000000028c`

- I attempted to gather more metadata about the handle using
<br>`!handle 28c f`

- However, the above command did not reveal the expected named pipe information or object path. To continue the investigation, I tied to search the entire dump memory for the string pipe using
<br>`s -a 0 L?800000 "pipe"` 

This command searches the process memory for ASCII strings containing the keyword pipe.The value 0 was used to start the search from the beginning of the accessible process memory, and L?800000 defined the memory range to search. In this case, the 0x800000 value (approximately 8 MB) was manually selected to search a sufficiently large portion of the process memory for possible IPC-related strings without using an unnecessarily large search range.

The search returned multiple results. I reviewed each memory address using the command:
<br>`!address <output-address>`

to identify whether the memory region was associated with the suspicious update.exe process. After identifying the relevant address, I used the following command to display the complete ASCII string stored at that memory location:
<br> ```da 00000000`0044a9b4```

This revealed the full named pipe string used by the malicious process.


