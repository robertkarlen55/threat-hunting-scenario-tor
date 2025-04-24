<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/robertkarlen55/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "robertkarlen55" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `Apr 17, 2025 12:15:36 PM`. These events began at `Apr 17, 2025 11:50:48 AM. `.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "robertkarlenonboardi"  
| where InitiatingProcessAccountName == "robertkarlen55"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/890b9e37-021d-4a2c-af37-407e47dd2188)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.5.exe”. Based on the logs returned, at `Apr 17, 2025 11:45:48 AM`, an employee on the "robertkarlenonboardi" device ran the file `“tor-browser-windows-x86_64-portable-14.5.exe”` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "rkarlenonboardi"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName

```
![image](https://github.com/user-attachments/assets/ff314dc5-a7b7-44a8-9854-0c8cf1ced1e7)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "robertkarlen55" actually opened the TOR browser. There was evidence that they did open it at `Apr 17, 2025 11:43:40 PM`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName == "rkarlenonboardi"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/cde9b697-2f5f-4e62-a235-044b16c8190b)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `On Apr 17, 2025 11:40:40 PM `, an employee on the "robertkarlenonboardi" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\robertkarlen55\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "rkarlenonboardi"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/0b78f2ac-1521-4f93-9eb3-1be989254d6d)


---

Chronological Events
Detailed Timeline of TOR Usage

File Download- Tor Installer
Apr 17, 2025 11:38 AM – A file named EdgePushStorageWithConnectTokens was created under a Microsoft Edge-related directory. This suggests the user may have begun downloading files or setting up a browsing session, potentially as a precursor to TOR activity.


Apr 17, 2025 11:40 AM – Multiple JavaScript files (edge_tracking_page_validator.js, edge_confirmation_page_validator.js, edge_checkout_page_validator.js) were modified, possibly indicating the tampering of scripts used during the TOR browser download or spoofed setup.


Process Execution-Tor Browser Installation
Apr 17, 2025 11:45:48 AM – The user robertkarlen55 executed tor-browser-windows-x86_64-portable-14.5.exe from their Downloads folder using a silent install command, initiating installation of the TOR browser.


Process Execution-Tor Browser launch and File Creation
Apr 17, 2025 11:50:48 AM onward – TOR-related files began appearing on the Desktop, including the creation of the file tor-shopping-list-, indicating active use or testing of the browser.


Network Connection-Tor Network
Apr 17, 2025 12:05:05 PM – A network connection was established using tor.exe to IP address 82.197.160.67 over port 9001, a known TOR relay port, confirming successful and active TOR usage.


Additional Network Connections-Tor Browser Activity
Apr 17, 2025 11:43:40 PM – TOR-related processes including firefox.exe and tor.exe were executed again, indicating repeated use or reopening of the TOR browser well into the night.

---

Summary
On April 17, 2025, the employee robertkarlen55 on device rkarlenonboardi silently installed and actively used the TOR Browser:
Download and installation occurred during normal business hours.


TOR-related files and custom-named documents (e.g., tor-shopping-list-) appeared shortly after.


Network logs confirmed a successful connection to a known TOR entry node using port 9001 via the tor.exe process.


Usage continued later into the evening, suggesting sustained or repeated use.


---

## Response Taken

TOR usage was confirmed on the endpoint `rkarlenonboardi` by the user `robertkarlen55`. The device was isolated, and the user's direct manager was notified.

---
