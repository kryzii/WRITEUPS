![image](https://github.com/user-attachments/assets/1a29d56d-1b3c-45eb-b71a-5942f6511ac1)

## Challenge

For this challenge, its the second version from [My First CTF](https://github.com/Kr3yzi/CTF-WRITEUPS/blob/main/NAHAMCON%202025/WEB/MY%20FIRST%20CTF/README.md).
The only difference is we are given wordlist.txt. Same as before, but without the flag.txt endpoint.

![image](https://github.com/user-attachments/assets/2a7b8d18-0f0f-49be-9960-ea990927c14b)

## Solution 

Soooo my guess, its Burp Intruder time! Oh before we forget, last time. It's encrypted in ROT1. But this, i cant risk my time to guess which ROT.  
I ask cursor to provide me with a script that:
- Encrypt the wordlist.txt content to all ROT
- Generated updated wordlist with all possible ROT encrypted
  
After that, by using Burpsuite. We simply send the GET request to burp intruder

![image](https://github.com/user-attachments/assets/36ba7e1c-dab3-43f8-ad8b-43b65435c5f5)

Add position for our payload

![image](https://github.com/user-attachments/assets/24d8e0a8-9f30-45d9-8193-69416ca54d52)

Use our ROT encrypted wordlist for it.

![image](https://github.com/user-attachments/assets/5f3475ab-dc54-4811-b050-2aaf31269235)

We will then get a single request where the status code is different from others

![image](https://github.com/user-attachments/assets/b45b616c-a629-4e79-9876-8be987d8c78e)

Upon visiting the endpoint, we will be redirected and getting error that says:

![image](https://github.com/user-attachments/assets/52f42408-3aec-41ad-ade8-958843ac2592)

We then need to bruteforce once more time with our current wordlist. But this time, its for our parameter. 
So, the position for the payload to be bruteforce is:
```
GET /fgdwi/?§a§=meow
```
![image](https://github.com/user-attachments/assets/c554f960-96e2-466d-8852-6e672260dcf3)

Why, does the payload needed to have **?§a§=meow** it's because the error says that missing parameter and not value. 
So the value could be anything else other than "*meow*" it could be "*dog*" or even "*cat*". Also, fgdwi = debug decrypt by ROT2.
So for better understanding, After finding out the parameter and it does gave an error that says the value is missing or incorrect. 
That's when we need to have a correct value for it instead.

## Flag

After we are done with the intruder, we can find only one request that has a different length from others. Reviewing the response we will get the flag:   

![image](https://github.com/user-attachments/assets/f05b1f88-7ef2-44ed-a2f4-8982106b64e0)

```
flag{9078bae810c524673a331aeb58fb0ebc}
```
