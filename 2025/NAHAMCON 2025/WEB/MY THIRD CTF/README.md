![image](https://github.com/user-attachments/assets/fe08129e-5474-4a0f-ba58-18774cc9033a)

## Challenge

For this challenge, its the third version from [My First CTF](https://github.com/Kr3yzi/CTF-WRITEUPS/tree/main/2025/NAHAMCON%202025/WEB/MY%20FIRST%20CTF#readme) and [My Second CTF](https://github.com/Kr3yzi/CTF-WRITEUPS/tree/main/2025/NAHAMCON%202025/WEB/MY%20SECOND%20CTF#readme).
The only difference is we are given wordlist.txt same as the second one.

![image](https://github.com/user-attachments/assets/6e5eb0e1-d111-48c3-9e29-5fb570ce383e)

## Solution 

From the wordlist given,
I ask cursor to provide me with a script that:
- Encrypt the wordlist.txt content to all ROT
- Generated updated wordlist with all possible ROT encrypted

After that, by using Burpsuite. We simply send the GET request to burp intruder and add position for our payload

![image](https://github.com/user-attachments/assets/523dd72e-051e-4f39-bb2e-d9bff18ce541)

Using our ROT encrypted wordlist for it. We will then get a single request where the status code is different from others

![image](https://github.com/user-attachments/assets/65505e12-5915-4be4-9688-106b59b81e3e)

Upon visiting the endpoint, we will be redirected and getting error that says 403 Forbidden:

![image](https://github.com/user-attachments/assets/2893dd2e-c1ba-44a6-ba65-22c04ce1b2fa)

To bypass, simply bruteforce each of the directories multiple times with our wordlist payload till we got our final url. 
Here's the payload position for our intruder

![image](https://github.com/user-attachments/assets/5cf2968c-5926-4872-8b6f-1b3a9972856d) 
![image](https://github.com/user-attachments/assets/d8913b91-c459-43b7-b55b-657c23bb211d) ![image](https://github.com/user-attachments/assets/9364655c-f452-4784-a88c-1c12e24d256d)

http://challenge.nahamcon.com:30653/qbhf/oguucig/wrnhq/lewl/

## Flag

![image](https://github.com/user-attachments/assets/11d42284-be7a-4ef5-932d-c745e2488e4e)
![image](https://github.com/user-attachments/assets/8f98b501-cf41-4c2b-8299-a1933e76641c)

```
flag{afd87cae63c08a57db7770b4e52081d3}
```

