---
title:HTB: Editor
date: 2025-09-30 00:00 +0800
categories: [HTB]
tags: []
image:
---
<img width="696" height="240" alt="Screenshot 2025-10-15 012413" src="https://github.com/user-attachments/assets/e37b5d08-83ab-484b-bc3b-88503d206a55" />

## Recon

nmap scan result:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Editor]
└─$ sudo nmap -sCV -T4 -p- -vv -oN nmap-scan.txt editor.htb 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-15 01:21 +08
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 01:21
Completed NSE at 01:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 01:21
Completed NSE at 01:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 01:21
Completed NSE at 01:21, 0.00s elapsed
Initiating Ping Scan at 01:21
Scanning editor.htb (10.10.11.80) [4 ports]
Completed Ping Scan at 01:21, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 01:21
Scanning editor.htb (10.10.11.80) [65535 ports]
Discovered open port 22/tcp on 10.10.11.80
Discovered open port 8080/tcp on 10.10.11.80
Discovered open port 80/tcp on 10.10.11.80
Completed SYN Stealth Scan at 01:21, 8.17s elapsed (65535 total ports)
Initiating Service scan at 01:21                                                                                                                                                                                   
Scanning 3 services on editor.htb (10.10.11.80)                                                                                                                                                                    
Completed Service scan at 01:21, 6.05s elapsed (3 services on 1 host)                                                                                                                                              
NSE: Script scanning 10.10.11.80.                                                                                                                                                                                  
NSE: Starting runlevel 1 (of 3) scan.                                                                                                                                                                              
Initiating NSE at 01:21                                                                                                                                                                                            
Completed NSE at 01:21, 0.67s elapsed                                                                                                                                                                              
NSE: Starting runlevel 2 (of 3) scan.                                                                                                                                                                              
Initiating NSE at 01:21                                                                                                                                                                                            
Completed NSE at 01:21, 0.05s elapsed                                                                                                                                                                              
NSE: Starting runlevel 3 (of 3) scan.                                                                                                                                                                              
Initiating NSE at 01:21                                                                                                                                                                                            
Completed NSE at 01:21, 0.00s elapsed                                                                                                                                                                              
Nmap scan report for editor.htb (10.10.11.80)                                                                                                                                                                      
Host is up, received echo-reply ttl 63 (0.013s latency).                                                                                                                                                           
Scanned at 2025-10-15 01:21:35 +08 for 15s                                                                                                                                                                         
Not shown: 65532 closed tcp ports (reset)                                                                                                                                                                          
PORT     STATE SERVICE REASON         VERSION                                                                                                                                                                      
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)                                                                                                                
| ssh-hostkey:                                                                                                                                                                                                     
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)                                                                                                                                                    
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=                                                 
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)                                                                                                                                                  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM                                                                                                                                 
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)                                                                                                                                                        
|_http-title: Editor - SimplistCode Pro                                                                                                                                                                            
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/ 
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/ 
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/ 
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/ 
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/ 
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/ 
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/ 
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/ 
|_/xwiki/bin/logout/
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
|_http-open-proxy: Proxy might be redirecting requests
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Jetty(10.0.20)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_http-server-header: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 01:21
Completed NSE at 01:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 01:21
Completed NSE at 01:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 01:21
Completed NSE at 01:21, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.26 seconds
           Raw packets sent: 65616 (2.887MB) | Rcvd: 65536 (2.621MB)

```
