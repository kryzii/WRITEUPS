<img width="495" height="540" alt="image" src="https://github.com/user-attachments/assets/a12f938d-6033-4c0f-a9a3-e11704e68b1f" />

# Challenge 

Upon viewing new instances, we would guess that this is typical Upload Insecure Files challenge. 

<img width="430" height="254" alt="image" src="https://github.com/user-attachments/assets/3ae82837-5644-4596-a6cb-bf3ee20d4203" />

Before going further. There are source code atttached for this challenge called chall.zip. 

<img width="475" height="201" alt="image" src="https://github.com/user-attachments/assets/78aab5fc-2457-4a72-8c99-5a58e4dce7ec" />

and here is the content of app.py
```
from flask import Flask, request, redirect, render_template, make_response, url_for
app = Flask(__name__)
from hashlib import sha256
import os
def allowed(name):
    if name.split('.')[1] in ['jpg','jpeg','png','svg']:
        return True
    return False

@app.route('/',methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed(file.filename):
            filename = file.filename
            hash = sha256(os.urandom(32)).hexdigest()
            filepath = f'./static/uploads/{hash}.{filename.split(".")[1]}'
            file.save(filepath)
            return redirect(f'/render/{hash}.{filename.split(".")[1]}')
    return render_template('upload.html')

@app.route('/render/<path:filename>')
def render(filename):
    return render_template('display.html', filename=filename)

@app.route('/developer')
def developer():
    cookie = request.cookies.get("developer_secret_cookie")
    correct = open('./static/uploads/secrets/secret_cookie.txt').read()
    if correct == '':
        c = open('./static/uploads/secrets/secret_cookie.txt','w')
        c.write(sha256(os.urandom(16)).hexdigest())
        c.close()
    correct = open('./static/uploads/secrets/secret_cookie.txt').read()
    if cookie == correct:
        c = open('./static/uploads/secrets/secret_cookie.txt','w')
        c.write(sha256(os.urandom(16)).hexdigest())
        c.close()
        return f"Welcome! There is currently 1 unread message: {open('flag.txt').read()}"
    else:
        return "You are not a developer!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)                                                                             
```

1. A hidden route ``/developer`` checks for a secret cookie: ``developer_secret_cookie``
2. The value of the cookie is stored in a local file: ``./static/uploads/secrets/secret_cookie.txt``
3. If the user provides the correct cookie: The secret is rotated (replaced with a new random hash) and the server returns the flag from flag.txt.

## Solution 

<img width="469" height="150" alt="image" src="https://github.com/user-attachments/assets/afc9e7a7-ba2f-4d89-b1b7-6bfc5a064dfd" />

1. Visit the hidden route ``play.scriptsorcerers.xyz:10055/developer`` to make sure it render new developer secret cookies

<img width="544" height="566" alt="image" src="https://github.com/user-attachments/assets/87d94d84-7839-4742-96b6-5b164c628fd1" />

2. Get cookie value that is stored in a local file: ``play.scriptsorcerers.xyz:10055/static/uploads/secrets/secret_cookie.txt``

## Flag

<img width="678" height="146" alt="image" src="https://github.com/user-attachments/assets/9a10fefd-527b-47a2-b601-86aad62e2220" />

Visit the ``play.scriptsorcerers.xyz:10055/developer`` with a valid 16 random sha256 hash value of developer_secret_cookie.

Welcome! There is currently 1 unread message: 

```
scriptCTF{my_c00k135_4r3_n0t_s4f3!_00352677a686}
```
