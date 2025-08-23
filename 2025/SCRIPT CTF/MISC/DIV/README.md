<img width="497" height="713" alt="image" src="https://github.com/user-attachments/assets/4e90632c-470d-49fc-b609-0f6bc71212af" />

# Challenges

We are given a Python script challenge.

## Solution 

<img width="631" height="406" alt="image" src="https://github.com/user-attachments/assets/35de983b-d73f-43c7-8501-f0eb05953bbc" />

```
import os
import decimal
decimal.getcontext().prec = 50

secret = int(os.urandom(16).hex(),16)
num = input('Enter a number: ')

if 'e' in num.lower():
    print("Nice try...")
    exit(0)

if len(num) >= 10:
    print('Number too long...')
    exit(0)

fl_num = decimal.Decimal(num)
div = secret / fl_num

if div == 0:
    print(open('flag.txt').read().strip())
else:
    print('Try again...')
```

1. Looking at the code, the program generates a random secret integer and asks us for a number.  
2. It divides the secret by our input, and only if the result is exactly `0` will it print the flag.  
3. Normally, `secret / num` will never be `0` because the secret is a large random integer.  
4. However, `decimal.Decimal` accepts special values such as `Infinity`.  

## Flag

<img width="407" height="89" alt="image" src="https://github.com/user-attachments/assets/975431c0-70ed-42d2-b01b-12326698a51a" />

If we enter `Infinity`, the division `secret / Infinity` evaluates to `0`, which satisfies the condition.

```
scriptCTF{70_1nf1n17y_4nd_b3y0nd_55ea4f5a549c}
```
