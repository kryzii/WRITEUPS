<img width="501" height="435" alt="image" src="https://github.com/user-attachments/assets/f4dc67ca-3db5-44e5-b4c8-dc79a514dc93" />

# Challenges

We are given disk image called ``stick.img``

## Solution 

<img width="654" height="375" alt="image" src="https://github.com/user-attachments/assets/0c688b73-ad31-415e-8b02-51b6047a8a93" />

1. I downloaded the ``stick.img`` file to linux after i dont find anything through FTK Imager or Forensics Toolkit

<img width="561" height="470" alt="image" src="https://github.com/user-attachments/assets/f79b912f-453a-42a6-83dc-f4b5a4ba6ca1" />

2. Then i simply check the file type and strings. There's flag.txt, and secret.gz.

<img width="510" height="235" alt="image" src="https://github.com/user-attachments/assets/03641b01-3a73-4516-afee-abd6550a3948" />
  
4. I tried to mount and directly check before i found out that the flag was actually hidden.

## Flag 

<img width="654" height="395" alt="image" src="https://github.com/user-attachments/assets/6ca8188b-7521-44dc-aed4-e08d7a6a614a" />

Use binwalk to extract the hidden file in the disk and eventually we will find the flag.txt

```
scriptCTF{1_l0v3_m461c_7r1ck5}
```
