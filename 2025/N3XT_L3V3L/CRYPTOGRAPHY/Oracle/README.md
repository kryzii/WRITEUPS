<img width="579" height="494" alt="Screenshot 2025-08-27 182710" src="https://github.com/user-attachments/assets/af028636-9446-4420-9702-86afe676f063" />

# Challenge

I am not deep into cryptography. I searched for ready-made padding-oracle tools. From `chall.py` I saw the server prints a ciphertext and answers only “Valid Padding” or “Invalid Padding” to hex input, and it uses raw TCP. Most popular tools (PadBuster, padding-oracle-attacker) expect HTTP, so they were not a direct fit. I asked ChatGPT to adapt an existing CTF tool. We used [mpgn/Padding-oracle-attack (Python)](https://github.com/mpgn/Padding-oracle-attack) because it lets you swap the oracle layer. I replaced two small functions to speak TCP, ran the attack, and recovered the plaintext and flag.

## Solution 

Here is the final script

```
#! /usr/bin/python3
import argparse
import re
import sys
from itertools import cycle

# ===== CUSTOM ORACLE FOR RAW TCP (N3xtCTF) =====
import socket

TARGET_HOST = "185.207.251.177"
TARGET_PORT = 1600

class _NoopConn:
    def close(self):  # mpgn core calls .close(); nothing to close here
        pass

def test_validity(response, error):
    """
    Our TCP oracle returns text that contains either:
        "Valid Padding"  or  "Invalid Padding"
    mpgn expects: return 1 for VALID, 0 for INVALID.
    We use the --error argument as the INVALID indicator string.
    """
    if isinstance(response, bytes):
        response = response.decode("utf-8", "ignore")
    return 0 if error in response else 1

def call_oracle(host, cookie, url, post, method, up_cipher):
    """
    Ignore HTTP params. Connect to TCP, send hex + newline,
    read until we see a decision. Return (conn_like, response_text).
    """
    s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=8)
    s.settimeout(5.0)
    try:
        # drain banner/prompt
        try:
            _ = s.recv(8192)
        except socket.timeout:
            pass

        # send crafted ciphertext
        s.sendall((up_cipher + "\n").encode())

        # read until decision appears
        buf = b""
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"Valid Padding" in buf or b"Invalid Padding" in buf:
                break

        resp_text = buf.decode("utf-8", "ignore")
        return _NoopConn(), resp_text
    finally:
        try:
            s.close()
        except:
            pass
# ===== END CUSTOM ORACLE =====

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

def block_search_byte(size_block, i, pos, l):
    hex_char = hex(pos).split("0x")[1]
    return (
        "00" * (size_block - (i + 1))
        + ("0" if len(hex_char) % 2 != 0 else "")
        + hex_char
        + "".join(l)
    )

def block_padding(size_block, i):
    l = []
    for t in range(0, i + 1):
        l.append(
            ("0" if len(hex(i + 1).split("0x")[1]) % 2 != 0 else "")
            + (hex(i + 1).split("0x")[1])
        )
    return "00" * (size_block - (i + 1)) + "".join(l)

def hex_xor(s1, s2):
    b = bytearray()
    for c1, c2 in zip(bytes.fromhex(s1), cycle(bytes.fromhex(s2))):
        b.append(c1 ^ c2)
    return b.hex()

def run(cipher, size_block, host, url, cookie, method, post, error):
    cipher = cipher.upper()
    found = False
    valide_value = []
    result = []
    len_block = size_block * 2
    cipher_block = split_len(cipher, len_block)

    if len(cipher_block) == 1:
        print("[-] Abort there is only one block")
        sys.exit()

    # for each cipher_block
    for block in reversed(range(1, len(cipher_block))):
        if len(cipher_block[block]) != len_block:
            print("[-] Abort length block doesn't match the size_block")
            break
        print("[+] Search value block : ", block, "\n")

        # for each byte of the block
        for i in range(0, size_block):
            # test each byte max 255
            for ct_pos in range(0, 256):
                # 1 xor 1 = 0 or valid padding need to be checked
                if ct_pos != i + 1 or (
                    len(valide_value) > 0 and int(valide_value[-1], 16) == ct_pos
                ):

                    bk = block_search_byte(size_block, i, ct_pos, valide_value)
                    bp = cipher_block[block - 1]
                    bc = block_padding(size_block, i)

                    tmp = hex_xor(bk, bp)
                    cb = hex_xor(tmp, bc).upper()

                    up_cipher = cb + cipher_block[block]

                    # call the oracle
                    connection, response = call_oracle(
                        host, cookie, url, post, method, up_cipher
                    )

                    # DO NOT print response.status (not HTTP)
                    exe = re.findall("..", cb)
                    discover = ("").join(exe[size_block - i : size_block])
                    current = ("").join(exe[size_block - i - 1 : size_block - i])
                    find_me = ("").join(exe[: -i - 1])
                    sys.stdout.write(
                        f"\r[+] Test [Byte {ct_pos:03d}/256 - Block {block} ]: \033[31m{find_me}\033[33m{current}\033[36m{discover}\033[0m"
                    )
                    sys.stdout.flush()

                    if test_validity(response, error):
                        found = True
                        try:
                            connection.close()
                        except:
                            pass

                        value = re.findall("..", bk)
                        valide_value.insert(0, value[size_block - (i + 1)])

                        print("")
                        print("[+] Block M_Byte : %s" % bk)
                        print("[+] Block C_{i-1}: %s" % bp)
                        print("[+] Block Padding: %s" % bc)
                        print("")

                        bytes_found = "".join(valide_value)
                        if (
                            i == 0
                            and int(bytes_found, 16) > size_block
                            and block == len(cipher_block) - 1
                        ):
                            print(
                                "[-] Error decryption failed the padding is > "
                                + str(size_block)
                            )
                            sys.exit()

                        print("\033[36m\033[1m[+]\033[0m Found", i + 1, "bytes :", bytes_found)
                        print("")
                        break

            if found == False:
                # assume padding is 01 for the last byte of last block (padding block)
                if len(cipher_block) - 1 == block and i == 0:
                    value = re.findall("..", bk)
                    valide_value.insert(0, "01")
                    print("")
                    print("[-] No padding found, but maybe the padding is length 01 :)")
                    print("[+] Block M_Byte : %s" % bk)
                    print("[+] Block C_{i-1}: %s" % bp)
                    print("[+] Block Padding: %s" % bc)
                    print("")
                    bytes_found = "".join(valide_value)
                else:
                    print("\n[-] Error decryption failed")
                    result.insert(0, "".join(valide_value))
                    hex_r = "".join(result)
                    print("[+] Partial Decrypted value (HEX):", hex_r.upper())
                    padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
                    try:
                        ascii_part = bytes.fromhex(hex_r[0 : -(padding * 2)]).decode()
                    except:
                        ascii_part = bytes.fromhex(hex_r[0 : -(padding * 2)]).decode("latin1")
                    print("[+] Partial Decrypted value (ASCII):", ascii_part)
                    sys.exit()
            found = False

        result.insert(0, "".join(valide_value))
        valide_value = []

    print("")
    hex_r = "".join(result)
    print("[+] Decrypted value (HEX):", hex_r.upper())
    padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
    try:
        ascii_full = bytes.fromhex(hex_r[0 : -(padding * 2)]).decode()
    except:
        ascii_full = bytes.fromhex(hex_r[0 : -(padding * 2)]).decode("latin1")
    print("[+] Decrypted value (ASCII):", ascii_full)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exploit of Padding Oracle Attack (TCP-adapted)")
    parser.add_argument("-c", "--cipher", required=True, help="cipher you want to decrypt (hex IV||C...)")
    parser.add_argument("-l","--length_block_cipher", required=True, type=int, help="length of a block cipher: 8,16")
    parser.add_argument("--host", required=True, help="dummy (ignored)")
    parser.add_argument("-u", "--urltarget", required=True, help="dummy (ignored)")
    parser.add_argument("--error", required=True, help="INVALID indicator, e.g. 'Invalid Padding'")
    parser.add_argument("--cookie", default="", help="ignored for TCP")
    parser.add_argument("--method", default="GET", help="ignored for TCP")
    parser.add_argument("--post", default="", help="ignored for TCP")
    args = parser.parse_args()

    run(
        args.cipher,
        args.length_block_cipher,
        args.host,
        args.urltarget,
        args.cookie,
        args.method,
        args.post,
        args.error,
    )

```

```
┌──(kali㉿kali)-[~/Desktop/ctf/N3xtCTF/Padding-oracle-attack]
└─$ python3 exploit_tcp.py \
  -c bf27aaf4b8e66094f6bce5717cf2889a9cf304412717053cd1011fc8b738d2b7bbeca475cfca263e74c18716fbca722d82ff7382864443b9201f276a19517d5390da90e67cd42be2977d3571d1da1828 \
  -l 16 \
  --host dummy \
  -u / \
  --error "Invalid Padding"

[+] Search value block :  4 

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F276A19517D5E
[+] Block M_Byte : 0000000000000000000000000000000c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000000000000000001

[+] Found 1 bytes : 0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F276A1951735D
[+] Block M_Byte : 00000000000000000000000000000c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000000000000000202

[+] Found 2 bytes : 0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F276A195E725C
[+] Block M_Byte : 000000000000000000000000000c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000000000000030303

[+] Found 3 bytes : 0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F276A1159755B
[+] Block M_Byte : 0000000000000000000000000c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000000000004040404

[+] Found 4 bytes : 0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F27631058745A
[+] Block M_Byte : 00000000000000000000000c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000000000505050505

[+] Found 5 bytes : 0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F2D60135B7759
[+] Block M_Byte : 000000000000000000000c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000000060606060606

[+] Found 6 bytes : 0c0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B920142C61125A7658
[+] Block M_Byte : 0000000000000000000c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000007070707070707

[+] Found 7 bytes : 0c0c0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9241B236E1D557957
[+] Block M_Byte : 00000000000000000c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000000808080808080808

[+] Found 8 bytes : 0c0c0c0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443BC251A226F1C547856
[+] Block M_Byte : 000000000000000c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000000090909090909090909

[+] Found 9 bytes : 0c0c0c0c0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864445BF2619216C1F577B55
[+] Block M_Byte : 0000000000000c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 0000000000000a0a0a0a0a0a0a0a0a0a

[+] Found 10 bytes : 0c0c0c0c0c0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864344BE2718206D1E567A54
[+] Block M_Byte : 00000000000c0c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000000000b0b0b0b0b0b0b0b0b0b0b

[+] Found 11 bytes : 0c0c0c0c0c0c0c0c0c0c0c

[+] Test [Byte 012/256 - Block 4 ]: 82FF7382864443B9201F276A19517D53
[+] Block M_Byte : 000000000c0c0c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 000000000c0c0c0c0c0c0c0c0c0c0c0c

[+] Found 12 bytes : 0c0c0c0c0c0c0c0c0c0c0c0c

[+] Test [Byte 125/256 - Block 4 ]: 82FF73F2874542B8211E266B18507C52
[+] Block M_Byte : 0000007d0c0c0c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 0000000d0d0d0d0d0d0d0d0d0d0d0d0d

[+] Found 13 bytes : 7d0c0c0c0c0c0c0c0c0c0c0c0c

[+] Test [Byte 115/256 - Block 4 ]: 82FF0EF1844641BB221D25681B537F51
[+] Block M_Byte : 0000737d0c0c0c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 00000e0e0e0e0e0e0e0e0e0e0e0e0e0e

[+] Found 14 bytes : 737d0c0c0c0c0c0c0c0c0c0c0c0c

[+] Test [Byte 100/256 - Block 4 ]: 82940FF0854740BA231C24691A527E50
[+] Block M_Byte : 0064737d0c0c0c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f

[+] Found 15 bytes : 64737d0c0c0c0c0c0c0c0c0c0c0c0c

[+] Test [Byte 110/256 - Block 4 ]: FC8B10EF9A585FA53C033B76054D614F
[+] Block M_Byte : 6e64737d0c0c0c0c0c0c0c0c0c0c0c0c
[+] Block C_{i-1}: 82FF7382864443B9201F276A19517D53
[+] Block Padding: 10101010101010101010101010101010

[+] Found 16 bytes : 6e64737d0c0c0c0c0c0c0c0c0c0c0c0c

[+] Search value block :  3 

[+] Test [Byte 051/256 - Block 3 ]: BBECA475CFCA263E74C18716FBCA721F
[+] Block M_Byte : 00000000000000000000000000000033
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000000000000000001

[+] Found 1 bytes : 33

[+] Test [Byte 103/256 - Block 3 ]: BBECA475CFCA263E74C18716FBCA171C
[+] Block M_Byte : 00000000000000000000000000006733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000000000000000202

[+] Found 2 bytes : 6733

[+] Test [Byte 051/256 - Block 3 ]: BBECA475CFCA263E74C18716FBFA161D
[+] Block M_Byte : 00000000000000000000000000336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000000000000030303

[+] Found 3 bytes : 336733

[+] Test [Byte 108/256 - Block 3 ]: BBECA475CFCA263E74C1871693FD111A
[+] Block M_Byte : 0000000000000000000000006c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000000000004040404

[+] Found 4 bytes : 6c336733

[+] Test [Byte 095/256 - Block 3 ]: BBECA475CFCA263E74C1874C92FC101B
[+] Block M_Byte : 00000000000000000000005f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000000000505050505

[+] Found 5 bytes : 5f6c336733

[+] Test [Byte 051/256 - Block 3 ]: BBECA475CFCA263E74C1B24F91FF1318
[+] Block M_Byte : 00000000000000000000335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000000060606060606

[+] Found 6 bytes : 335f6c336733

[+] Test [Byte 114/256 - Block 3 ]: BBECA475CFCA263E74B4B34E90FE1219
[+] Block M_Byte : 00000000000000000072335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000007070707070707

[+] Found 7 bytes : 72335f6c336733

[+] Test [Byte 052/256 - Block 3 ]: BBECA475CFCA263E48BBBC419FF11D16
[+] Block M_Byte : 00000000000000003472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000000808080808080808

[+] Found 8 bytes : 3472335f6c336733

[+] Test [Byte 095/256 - Block 3 ]: BBECA475CFCA266849BABD409EF01C17
[+] Block M_Byte : 000000000000005f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000000090909090909090909

[+] Found 9 bytes : 5f3472335f6c336733

[+] Test [Byte 121/256 - Block 3 ]: BBECA475CFCA556B4AB9BE439DF31F14
[+] Block M_Byte : 000000000000795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 0000000000000a0a0a0a0a0a0a0a0a0a

[+] Found 10 bytes : 795f3472335f6c336733

[+] Test [Byte 051/256 - Block 3 ]: BBECA475CFF2546A4BB8BF429CF21E15
[+] Block M_Byte : 000000000033795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000000000b0b0b0b0b0b0b0b0b0b0b

[+] Found 11 bytes : 33795f3472335f6c336733

[+] Test [Byte 104/256 - Block 3 ]: BBECA475ABF5536D4CBFB8459BF51912
[+] Block M_Byte : 000000006833795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 000000000c0c0c0c0c0c0c0c0c0c0c0c

[+] Found 12 bytes : 6833795f3472335f6c336733

[+] Test [Byte 116/256 - Block 3 ]: BBECA40CAAF4526C4DBEB9449AF41813
[+] Block M_Byte : 000000746833795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 0000000d0d0d0d0d0d0d0d0d0d0d0d0d

[+] Found 13 bytes : 746833795f3472335f6c336733

[+] Test [Byte 095/256 - Block 3 ]: BBECF50FA9F7516F4EBDBA4799F71B10
[+] Block M_Byte : 00005f746833795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 00000e0e0e0e0e0e0e0e0e0e0e0e0e0e

[+] Found 14 bytes : 5f746833795f3472335f6c336733

[+] Test [Byte 115/256 - Block 3 ]: BB90F40EA8F6506E4FBCBB4698F61A11
[+] Block M_Byte : 00735f746833795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f

[+] Found 15 bytes : 735f746833795f3472335f6c336733

[+] Test [Byte 104/256 - Block 3 ]: C38FEB11B7E94F7150A3A45987E9050E
[+] Block M_Byte : 68735f746833795f3472335f6c336733
[+] Block C_{i-1}: BBECA475CFCA263E74C18716FBCA722D
[+] Block Padding: 10101010101010101010101010101010

[+] Found 16 bytes : 68735f746833795f3472335f6c336733

[+] Search value block :  2 

[+] Test [Byte 116/256 - Block 2 ]: 9CF304412717053CD1011FC8B738D2C2
[+] Block M_Byte : 00000000000000000000000000000074
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000000000000000001

[+] Found 1 bytes : 74

[+] Test [Byte 121/256 - Block 2 ]: 9CF304412717053CD1011FC8B738A9C1
[+] Block M_Byte : 00000000000000000000000000007974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000000000000000202

[+] Found 2 bytes : 7974

[+] Test [Byte 109/256 - Block 2 ]: 9CF304412717053CD1011FC8B756A8C0
[+] Block M_Byte : 000000000000000000000000006d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000000000000030303

[+] Found 3 bytes : 6d7974

[+] Test [Byte 095/256 - Block 2 ]: 9CF304412717053CD1011FC8EC51AFC7
[+] Block M_Byte : 0000000000000000000000005f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000000000004040404

[+] Found 4 bytes : 5f6d7974

[+] Test [Byte 116/256 - Block 2 ]: 9CF304412717053CD1011FB9ED50AEC6
[+] Block M_Byte : 0000000000000000000000745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000000000505050505

[+] Found 5 bytes : 745f6d7974

[+] Test [Byte 048/256 - Block 2 ]: 9CF304412717053CD10129BAEE53ADC5
[+] Block M_Byte : 0000000000000000000030745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000000060606060606

[+] Found 6 bytes : 30745f6d7974

[+] Test [Byte 110/256 - Block 2 ]: 9CF304412717053CD16828BBEF52ACC4
[+] Block M_Byte : 0000000000000000006e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000007070707070707

[+] Found 7 bytes : 6e30745f6d7974

[+] Test [Byte 095/256 - Block 2 ]: 9CF304412717053C866727B4E05DA3CB
[+] Block M_Byte : 00000000000000005f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000000808080808080808

[+] Found 8 bytes : 5f6e30745f6d7974

[+] Test [Byte 051/256 - Block 2 ]: 9CF3044127170506876626B5E15CA2CA
[+] Block M_Byte : 00000000000000335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000000090909090909090909

[+] Found 9 bytes : 335f6e30745f6d7974

[+] Test [Byte 114/256 - Block 2 ]: 9CF3044127177D05846525B6E25FA1C9
[+] Block M_Byte : 00000000000072335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 0000000000000a0a0a0a0a0a0a0a0a0a

[+] Found 10 bytes : 72335f6e30745f6d7974

[+] Test [Byte 052/256 - Block 2 ]: 9CF3044127287C04856424B7E35EA0C8
[+] Block M_Byte : 00000000003472335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000000000b0b0b0b0b0b0b0b0b0b0b

[+] Found 11 bytes : 3472335f6e30745f6d7974

[+] Test [Byte 095/256 - Block 2 ]: 9CF30441742F7B03826323B0E459A7CF
[+] Block M_Byte : 000000005f3472335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 000000000c0c0c0c0c0c0c0c0c0c0c0c

[+] Found 12 bytes : 5f3472335f6e30745f6d7974

[+] Test [Byte 115/256 - Block 2 ]: 9CF3043F752E7A02836222B1E558A6CE
[+] Block M_Byte : 000000735f3472335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 0000000d0d0d0d0d0d0d0d0d0d0d0d0d

[+] Found 13 bytes : 735f3472335f6e30745f6d7974

[+] Test [Byte 051/256 - Block 2 ]: 9CF3393C762D7901806121B2E65BA5CD
[+] Block M_Byte : 000033735f3472335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 00000e0e0e0e0e0e0e0e0e0e0e0e0e0e

[+] Found 14 bytes : 33735f3472335f6e30745f6d7974

[+] Test [Byte 108/256 - Block 2 ]: 9C90383D772C7800816020B3E75AA4CC
[+] Block M_Byte : 006c33735f3472335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f

[+] Found 15 bytes : 6c33735f3472335f6e30745f6d7974

[+] Test [Byte 099/256 - Block 2 ]: EF8F27226833671F9E7F3FACF845BBD3
[+] Block M_Byte : 636c33735f3472335f6e30745f6d7974
[+] Block C_{i-1}: 9CF304412717053CD1011FC8B738D2B7
[+] Block Padding: 10101010101010101010101010101010

[+] Found 16 bytes : 636c33735f3472335f6e30745f6d7974

[+] Search value block :  1 

[+] Test [Byte 052/256 - Block 1 ]: BF27AAF4B8E66094F6BCE5717CF288AF
[+] Block M_Byte : 00000000000000000000000000000034
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000000000000000001

[+] Found 1 bytes : 34

[+] Test [Byte 114/256 - Block 1 ]: BF27AAF4B8E66094F6BCE5717CF2F8AC
[+] Block M_Byte : 00000000000000000000000000007234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000000000000000202

[+] Found 2 bytes : 7234

[+] Test [Byte 048/256 - Block 1 ]: BF27AAF4B8E66094F6BCE5717CC1F9AD
[+] Block M_Byte : 00000000000000000000000000307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000000000000030303

[+] Found 3 bytes : 307234

[+] Test [Byte 095/256 - Block 1 ]: BF27AAF4B8E66094F6BCE57127C6FEAA
[+] Block M_Byte : 0000000000000000000000005f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000000000004040404

[+] Found 4 bytes : 5f307234

[+] Test [Byte 103/256 - Block 1 ]: BF27AAF4B8E66094F6BCE51326C7FFAB
[+] Block M_Byte : 0000000000000000000000675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000000000505050505

[+] Found 5 bytes : 675f307234

[+] Test [Byte 110/256 - Block 1 ]: BF27AAF4B8E66094F6BC8D1025C4FCA8
[+] Block M_Byte : 000000000000000000006e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000000060606060606

[+] Found 6 bytes : 6e675f307234

[+] Test [Byte 049/256 - Block 1 ]: BF27AAF4B8E66094F68A8C1124C5FDA9
[+] Block M_Byte : 000000000000000000316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000007070707070707

[+] Found 7 bytes : 316e675f307234

[+] Test [Byte 100/256 - Block 1 ]: BF27AAF4B8E660949A85831E2BCAF2A6
[+] Block M_Byte : 000000000000000064316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000000808080808080808

[+] Found 8 bytes : 64316e675f307234

[+] Test [Byte 100/256 - Block 1 ]: BF27AAF4B8E660F99B84821F2ACBF3A7
[+] Block M_Byte : 000000000000006464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000000090909090909090909

[+] Found 9 bytes : 6464316e675f307234

[+] Test [Byte 052/256 - Block 1 ]: BF27AAF4B8E65EFA9887811C29C8F0A4
[+] Block M_Byte : 000000000000346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 0000000000000a0a0a0a0a0a0a0a0a0a

[+] Found 10 bytes : 346464316e675f307234

[+] Test [Byte 112/256 - Block 1 ]: BF27AAF4B89D5FFB9986801D28C9F1A5
[+] Block M_Byte : 000000000070346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000000000b0b0b0b0b0b0b0b0b0b0b

[+] Found 11 bytes : 70346464316e675f307234

[+] Test [Byte 123/256 - Block 1 ]: BF27AAF4CF9A58FC9E81871A2FCEF6A2
[+] Block M_Byte : 000000007b70346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 000000000c0c0c0c0c0c0c0c0c0c0c0c

[+] Found 12 bytes : 7b70346464316e675f307234

[+] Test [Byte 116/256 - Block 1 ]: BF27AA8DCE9B59FD9F80861B2ECFF7A3
[+] Block M_Byte : 000000747b70346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 0000000d0d0d0d0d0d0d0d0d0d0d0d0d

[+] Found 13 bytes : 747b70346464316e675f307234

[+] Test [Byte 120/256 - Block 1 ]: BF27DC8ECD985AFE9C8385182DCCF4A0
[+] Block M_Byte : 000078747b70346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 00000e0e0e0e0e0e0e0e0e0e0e0e0e0e

[+] Found 14 bytes : 78747b70346464316e675f307234

[+] Test [Byte 051/256 - Block 1 ]: BF1BDD8FCC995BFF9D8284192CCDF5A1
[+] Block M_Byte : 003378747b70346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f

[+] Found 15 bytes : 3378747b70346464316e675f307234

[+] Test [Byte 110/256 - Block 1 ]: C104C290D38644E0829D9B0633D2EABE
[+] Block M_Byte : 6e3378747b70346464316e675f307234
[+] Block C_{i-1}: BF27AAF4B8E66094F6BCE5717CF2889A
[+] Block Padding: 10101010101010101010101010101010

[+] Found 16 bytes : 6e3378747b70346464316e675f307234


[+] Decrypted value (HEX): 6E3378747B70346464316E675F307234636C33735F3472335F6E30745F6D797468735F746833795F3472335F6C3367336E64737D0C0C0C0C0C0C0C0C0C0C0C0C
[+] Decrypted value (ASCII): n3xt{p4dd1ng_0r4cl3s_4r3_n0t_myths_th3y_4r3_l3g3nds}
```
## Flag 

```
n3xt{p4dd1ng_0r4cl3s_4r3_n0t_myths_th3y_4r3_l3g3nds}
```
