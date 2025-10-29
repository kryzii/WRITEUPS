---
title:HTB: Conersor
date: 2025-10-28 00:00 +0800
categories: [HTB]
tags: []
image:
---

## Unfinished Writeup

## Tools
- nmap
- searchsploit
- dirsearch
- 
  
## Recon

Nmap scan result:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ cat nmap-scan.txt 
# Nmap 7.95 scan initiated Mon Oct 27 19:05:46 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80 -O -sCV -oN nmap-scan2.txt 10.10.11.92
Nmap scan report for 10.10.11.92
Host is up, received echo-reply ttl 63 (0.016s latency).
Scanned at 2025-10-27 19:05:46 +08 for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9JqBn+xSQHg4I+jiEo+FiiRUhIRrVFyvZWz1pynUb/txOEximgV3lqjMSYxeV/9hieOFZewt/ACQbPhbR/oaE=
|   256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIR1sFcTPihpLp0OemLScFRf8nSrybmPGzOs83oKikw+
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=10/27%OT=22%CT=%CU=40718%PV=Y%DS=2%DC=I%G=N%TM=68FF521
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=9)OPS(
OS:O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11
OS:NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 28.572 days (since Mon Sep 29 05:21:35 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 27 19:05:58 2025 -- 1 IP address (1 host up) scanned in 11.95 seconds
```

## Initial Enumeration

In the first reconnaissance phase we find that `port 80` redirected to **conversor.htb**. We added those to `/etc/hosts`

We searched for known exploits using **searchsploit** based on the Nmap results, and we did find known vuln:

```
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ searchsploit Apache 2.4.52 
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution       | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner     | php/remote/29316.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                   | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow  | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflo | unix/remote/47080.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflo | unix/remote/764.c
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal   | linux/webapps/39642.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing                     | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                   | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)             | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Up | jsp/webapps/42966.py
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Up | windows/webapps/42953.txt
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)          | linux/dos/36906.txt
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Cod | linux/remote/34.pl
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
But still, nothing interesting from known vuln. We found that it uses **flask** from **[404 error page](https://0xdf.gitlab.io/cheatsheets/404)**

<img width="1182" height="207" alt="image" src="https://github.com/user-attachments/assets/2d54548c-71fe-4a85-982c-207bd4058929" />

Because there were no valid credentials or obvious SSH exploits, we focused on the manual discovery for web service on **port 80** for now. 

## Discovery

Here is **dirsearch** result:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ dirsearch -u conversor.htb
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                        
 (_||| _) (/_(_|| (_| )                                                                                 
                                                                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/HTB/Conversor/reports/_conversor.htb/_25-10-28_17-33-38.txt

Target: http://conversor.htb/

[17:33:39] Starting:                                                                                    
[17:33:46] 200 -    0B  - /about                                            
[17:33:57] 404 -  275B  - /javascript/tiny_mce                              
[17:33:57] 301 -  319B  - /javascript  ->  http://conversor.htb/javascript/ 
[17:33:57] 404 -  275B  - /javascript/editors/fckeditor
[17:33:58] 200 -  722B  - /login                                            
[17:34:05] 200 -  726B  - /register                                         
[17:34:06] 403 -  278B  - /server-status/                                   
[17:34:06] 403 -  278B  - /server-status                                    
                                                                             
Task Completed                      
```

Nothing much, from **dirsearch**

Need to registered, logged in to **authenticated** before we can do a further discovery:

<img width="1124" height="526" alt="image" src="https://github.com/user-attachments/assets/23adde21-9200-48b7-b33a-df26f436a9c0" />

Once logged in, the dashboard had a upload functions file with`.xml` and `.xslt` to beautify printed **nmap** scan results as `.html`

<img width="1325" height="719" alt="image" src="https://github.com/user-attachments/assets/90322b41-a3c6-44fd-8f71-673e2672f58a" />

in **About** section it shown all developers and also copy of source code 

<img width="1405" height="778" alt="image" src="https://github.com/user-attachments/assets/18bcebd9-08b9-4516-b840-a1675ea97496" />

