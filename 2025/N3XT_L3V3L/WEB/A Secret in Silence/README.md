<img width="936" height="698" alt="image" src="https://github.com/user-attachments/assets/570f0104-d10c-4358-bb8f-27d3ce36dd84" />

# Challenge 

We are given a login page where access levels are determined by a JWT token. The hint mentions that the secret key is exactly 8 digits long.

## Solution

1. **Login as Guest**  
   - After logging in, the browser stores a JWT token in cookies.
   - Decoding the token shows it is signed with `HS256`.
  
<img width="940" height="796" alt="image" src="https://github.com/user-attachments/assets/72e385b8-25f5-4789-8481-022adb34f317" />

<img width="940" height="345" alt="image" src="https://github.com/user-attachments/assets/6d3f938f-20f9-4f91-b68c-b84a6d5cd3ef" />

2. **Cracking the JWT Secret**  
   - Since the secret is 8 digits long, we use `hashcat` with mode `16500` (JWT HS256).
   - Command used:
     ```bash
     hashcat -m 16500 -a 3 <jwt_token> '?d?d?d?d?d?d?d?d'
     ```
   - This successfully recovers the secret: `49932332`.

<img width="940" height="1143" alt="image" src="https://github.com/user-attachments/assets/b7b9ee15-5991-423c-a195-d78fc766cc8a" />

<img width="919" height="587" alt="image" src="https://github.com/user-attachments/assets/36f2da3f-d604-42b9-9df7-8df76648bdd0" />

3. **Forging an Admin Token**  
   - With the cracked secret, we modify the payload:
     ```json
     {
       "user": "test",
       "isAdmin": true
     }
     ```
   - Sign the new token using the secret `49932332`.

<img width="940" height="564" alt="image" src="https://github.com/user-attachments/assets/5f48c45a-5e20-41fc-83fe-171b77e1cab5" />

## Flag 

4. **Accessing Admin Panel**  
   - Replace the cookie with the forged token.
   - Refreshing the page now shows access level **ADMIN**.
   - The flag is revealed.

<img width="940" height="833" alt="image" src="https://github.com/user-attachments/assets/03e798d6-cd4a-4c0b-8eab-0d128a76eec8" />

```
n3xt{jWt_brUt3f0rc3_1s_fun_r1ght?}
```
