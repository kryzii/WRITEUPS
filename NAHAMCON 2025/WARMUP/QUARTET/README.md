![image](https://github.com/user-attachments/assets/c6a7cf13-1ef9-40cb-8b4b-4939f7d5257e)

## Challenge

We're given four files name quartet.z01, quartet.z02,  quartet.z03, quartet.z04 and we are required to retrieve the contents to find the flag


## Solution 

.z01 - .z04 are chunks of splits archieve. Normally we also get quartet.zip, but in this case .zo1 is the first segment.

So to retrieve the content, we can use 7z and here's how to do it in kali
```
7z x quartet.z01
```
After that, we will be getting quartet.jpeg 

![quartet](https://github.com/user-attachments/assets/da981370-1b09-4623-a993-5963d7faf129)

Grep "flag" from the strings we will get the flag
```
strings quartet.jpeg | grep flag
```
![image](https://github.com/user-attachments/assets/b776a09e-2c88-4646-be87-5afadeb46757)

## Flag
```
flag{8f667b09d0e821f4e14d59a8037eb376}
```
