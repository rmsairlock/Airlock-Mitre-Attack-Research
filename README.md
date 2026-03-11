# Mapping Airlock Digital Against the MITRE ATT&CK Framework

>**Author:** Rob Shiplo - Sr Research Engineer - Systems & Endpoint Security @ Airlock Digital
>
>**Published:** March 2026 | **Platform:** Windows | **ATT&CK Version:** Enterprise v18.1

---

## TL;DR

I mapped Airlock Digital's enforcement model against every Windows-applicable technique in the MITRE ATT&CK Enterprise framework - 472 techniques and sub-techniques, scored with a binary Yes/No model. No hedging, no inflated numbers. The result: Airlock directly controls an execution point in **209 techniques (44%)**. The remaining 263 are genuinely outside the scope of execution control - network protocols, identity operations, in-memory manipulation - and this post explains what covers each of those instead.

This post walks through the methodology, the results, and what it actually means for defenders building layered security architectures.

![ATT&CK Coverage by Tactic](airlock_mitre_coverage.png)

---

## Why I Did This

Large customers ask a reasonable question: *"Where does Airlock fit in the ATT&CK matrix?"*

Most vendors answer this with a heatmap that looks impressively green. I wanted to answer it honestly. Application allowlisting is execution control - it's not EDR, it's not a SIEM, it's not identity protection. It does one thing extremely well: controlling what is allowed to execute on an endpoint. The ATT&CK mapping should reflect exactly that - where Airlock's enforcement model intersects an attacker's execution chain, and where it doesn't.

I also wanted every "Yes" to come with a concrete answer: which Airlock control applies, and how you'd prove it in a lab.

---

## Methodology

### Scope

- **Platform:** Windows only. Airlock's Windows agent uses a kernel driver for authoritative allow/block decisions at file load time, with the bulk of policy logic in user mode. This is the most mature enforcement model and the one most customers deploy at scale.
- **Framework version:** MITRE ATT&CK Enterprise v18.1
- **Techniques evaluated:** 472 (all Windows-applicable techniques and sub-techniques)

### Scoring Model

I used a binary scoring model - **Yes** or **No** - because security architecture decisions are binary. When a customer asks "does Airlock cover this technique?", the answer should be concrete.

**Yes** means Airlock's enforcement model directly controls an execution point in the technique's attack chain. The untrusted payload, binary, DLL, script, or driver IS blocked. Each "Yes" includes:

- The specific enforcement mechanism (default-deny, script control, DLL control, blocklist metarule, browser extension control, or agent tamper protection)
- A test case describing how to validate coverage in a lab
- Known limitations where the control has boundaries

**No** means the technique doesn't involve file, script, or DLL execution that Airlock controls, and there is no specific binary that can be practically blocklisted to prevent it. These are typically network-level operations, identity-plane activity, in-memory manipulation, or pure API calls within already-trusted processes.

### What Counts as "Covered"

A technique is scored "Yes" if Airlock blocks execution at any point in the technique's attack chain. This includes scenarios where the trigger mechanism succeeds but the payload is blocked. For example:

- **Scheduled Task (T1053.005):** The attacker can create the scheduled task. When the task fires, the untrusted payload is blocked. This is a Yes - Airlock controls the execution point that matters.
- **Registry Run Keys (T1547.001):** The attacker can write the registry key. At next logon, the untrusted binary it points to is blocked. Yes.
- **Service Execution (T1569.002):** PsExec copies its service binary to the remote host. The binary is blocked on the target. Yes.

A technique is also scored "Yes" if a specific identifiable binary can be restricted via Airlock's blocklist metarule engine - even if that binary is a trusted, Microsoft-signed OS utility. The blocklist takes precedence over the allowlist, and the metarule engine supports conditional criteria including original filename, user/group membership, and logical AND/OR combinations. For example:

- **Clear Windows Event Logs (T1070.001):** `wevtutil.exe` is a trusted OS binary. Blocklist metarule: original filename "wevtutil" AND user NOT member of Administrators → blocked for non-admins. Yes.
- **Inhibit System Recovery (T1490):** `vssadmin.exe` and `bcdedit.exe` - critical ransomware precursor tools - can be blocklisted for non-admin users. Yes.
- **OS Credential Dumping (T1003):** Standalone tools like mimikatz are blocked by default-deny. Built-in tools like `procdump.exe` and `rundll32.exe` (for comsvcs.dll MiniDump) can be blocklisted via metarule for non-admins. Yes.

---

## Results

### Overall Coverage

| | Count | Percentage |
|:---|---:|---:|
| **Covered (Yes)** | 209 | 44% |
| **Not Covered (No)** | 263 | 56% |
| **Total** | 472 | 100% |

### Coverage by Tactic

| Tactic | Yes | No | Total | Coverage |
|:-------|----:|---:|------:|---------:|
| Execution | 23 | 4 | 27 | 85% |
| Persistence | 67 | 24 | 91 | 74% |
| Privilege Escalation | 47 | 28 | 75 | 63% |
| Lateral Movement | 10 | 7 | 17 | 59% |
| Defense Evasion | 77 | 88 | 165 | 47% |
| Discovery | 21 | 21 | 42 | 50% |
| Impact | 9 | 21 | 30 | 30% |
| Initial Access | 6 | 15 | 21 | 29% |
| Credential Access | 13 | 40 | 53 | 25% |
| Command and Control | 6 | 39 | 45 | 13% |
| Collection | 4 | 28 | 32 | 13% |
| Exfiltration | 0 | 17 | 17 | 0% |

---

## Where Airlock Is Strongest

### Execution (89% covered)

This is Airlock's home turf. Script control covers all major scripting interpreters - PowerShell, cmd/batch, VBScript, JavaScript, Python, AutoIT, Lua - with SHA-256 hashing at execution time. DLL control catches malicious libraries at load time. The only execution techniques Airlock doesn't cover are Native API calls inside already-running processes (T1106), IPC between trusted processes (T1559), and input injection (T1674) - all of which operate within trusted process context where no new file execution occurs.

### Persistence (74% covered)

Attackers establish persistence by registering something to execute later - a registry key pointing to a binary, a service configured to load a DLL, a scheduled task with a payload. Airlock doesn't prevent the registration, but it blocks the payload when it fires. Every DLL-loading persistence mechanism (Winlogon helpers, AppInit DLLs, AppCert DLLs, LSA extensions, port monitors, print processors, COM hijacking, netsh helpers) is directly controlled by DLL allowlisting.

### Defense Evasion (47% covered)

This is the largest tactic at 165 techniques, and it's where Airlock's strengths are most distinct from traditional security tools. Default-deny is inherently resistant to evasion techniques that defeat signature-based detection:

- **Obfuscation, packing, polymorphism:** Every variant has a unique hash that isn't in the allowlist. Blocked every time. This is a fundamental advantage over antivirus signatures.
- **Masquerading:** Airlock checks the SHA-256 hash of file content, not the filename. Renaming malware doesn't help. The blocklist metarule engine's original filename field catches renamed trusted tools.
- **LOLBIN proxy execution:** MSBuild, mshta, InstallUtil, regsvr32, rundll32, CMSTP, odbcconf - all controllable via predefined blocklist packages mapped to the LOLBAS project and MITRE ATT&CK techniques. DLLs loaded by these proxies must be trusted.
- **DLL hijacking:** Search order hijacking, sideloading, COR_PROFILER injection - the untrusted DLL is blocked at load regardless of how it got there.

The 87 "No" techniques in defense evasion are predominantly in-memory operations (process injection family), identity-level techniques (valid accounts, token manipulation), and pre-OS boot (firmware, bootkit).

### Lateral Movement (71% covered)

When an attacker moves laterally, they typically need to execute tools on the target. PsExec's service binary must be trusted on the target (and is covered by predefined blocklist rules). Tools copied via SMB admin shares must be trusted to execute. WinRM commands launching untrusted binaries are blocked. The pattern is consistent: the movement mechanism may succeed, but the execution on the remote host is controlled.

---

## Where Airlock Has No Role (By Design)

These are not gaps - they're scope boundaries. Airlock is execution control, not a replacement for the entire security stack.

### Exfiltration (0% covered)

Every exfiltration technique operates at the network layer - transferring data over C2 channels, alternative protocols, web services, physical media. No file execution is involved. This is network security, DLP, and CASB territory.

### Command and Control (87% not covered)

C2 is network protocol behavior - encoding, encryption, proxy chains, DNS tunneling. Airlock covers the 6 techniques that involve file execution: ingress tool transfer (downloaded tools must be trusted), remote access tools (must be allowlisted), and tunneling/proxy tools (must be trusted to run).

### Credential Access (74% not covered)

Most credential access techniques are identity-plane operations: Kerberos ticket manipulation, brute force, credential store access, MFA interception. The 14 covered techniques are where specific tools can be blocked - credential dumping tools via default-deny, and built-in utilities like `reg.exe` and `rundll32.exe` via blocklist metarules.

### Process Injection (all sub-techniques not covered)

Process injection operates entirely within trusted process memory - writing shellcode, hijacking threads, hollowing processes. There is no file on disk to hash. This is explicitly EDR and memory protection territory. Airlock's role in the kill chain is preventing the attacker from getting their injection tool onto the endpoint in the first place.

---

## The Blocklist Metarule Engine

One of the most impactful capabilities in the mapping is the blocklist metarule engine. Beyond blocking known-bad hashes, the metarule engine allows conditional restrictions on trusted, Microsoft-signed operating system utilities using criteria like original filename and Active Directory group membership.

This is what moves techniques from "not covered" to "covered." A practical example:

**PowerShell restriction for non-administrators:**

```
Criteria:  Original filename contains "powershell"
           AND user is NOT a member of Built-in Administrators
Result:    Standard users cannot launch PowerShell.
           Administrators retain access for legitimate operations.
```

The same pattern applies to `cmd.exe`, `reg.exe`, `wmic.exe`, `netsh.exe`, `vssadmin.exe`, `certutil.exe`, `msbuild.exe`, and dozens of other utilities that attackers use for living-off-the-land techniques. Airlock ships predefined blocklist packages for Microsoft Recommended Block Rules, Microsoft Recommended Driver Block Rules, and LOLBAS-mapped packages that customers can import and deploy after an audit period.

---

## How To Use This Mapping

### For Security Architects

The accompanying CSV and ATT&CK Navigator layer provide technique-level detail. Load the Navigator JSON into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage. Overlay it with your EDR, SIEM, and identity protection layers to identify gaps and redundancies.

### For Detection Engineers

Every "Yes" technique includes a test case. These are reproducible validation scenarios - drop an unsigned binary, configure a blocklist metarule, fire a scheduled task - that confirm enforcement in your environment. Use them during deployment validation and periodic control testing.

### For Security Operations

The "No" techniques tell you what to monitor. Process injection, in-memory execution, credential access via trusted tools - these need behavioral detection from your EDR. Airlock's external logging (Syslog, Splunk, Graylog, CEF) provides file execution telemetry that complements EDR behavioral data.

---

## Defense-in-Depth Positioning

Allowlisting eliminates the attacker's ability to run new tools. Once attackers are forced into memory-only techniques, they become noisier and more detectable. The recommended pairing:

| Layer | What It Covers | Complements Airlock For |
|:------|:---------------|:-----------------------|
| **Airlock Digital** | Execution control - binaries, scripts, DLLs, drivers, browser extensions | Everything that touches disk |
| **EDR** | Behavioral detection, memory protection, process monitoring | In-memory injection, API abuse, behavioral anomalies |
| **Credential Protection** | LSASS hardening, Credential Guard, PAM | Credential theft via trusted tools |
| **Identity & Access** | MFA, conditional access, least privilege | Account compromise, lateral movement access |
| **Network Security** | Firewall, proxy, NDR, DNS filtering | C2 channels, exfiltration, network-based attacks |

---

*This mapping represents Airlock Digital's enforcement model as of v6.1.x on Windows, with enforcement mode active, script control enabled for all script types, DLL/library control enabled, and browser extension control enabled. Individual coverage depends on policy configuration - particularly publisher trust scope, path rule breadth, and blocklist rule deployment. Customers are encouraged to validate coverage using the provided test cases in their own environments.*
