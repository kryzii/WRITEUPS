
![Screenshot 2025-05-26 013748](https://github.com/user-attachments/assets/ec19a64a-e750-45f8-8ffc-f9afb2332d5c)

## Challenge

For this challenge, it consists seperation of 5 flags. But unfortunately, i was able to solved 4/5 :( 

- [Solution: Flag #1](https://github.com/Kr3yzi/CTF-WRITEUPS/new/main/2025/NAHAMCON%202025/WEB#solution-flag-1)
- [Solution: Flag #2](https://github.com/Kr3yzi/CTF-WRITEUPS/new/main/2025/NAHAMCON%202025/WEB#solution-flag-2)
- [Solution: Flag #3](https://github.com/Kr3yzi/CTF-WRITEUPS/new/main/2025/NAHAMCON%202025/WEB#solution-flag-3)
- [Solution: Flag #4](https://github.com/Kr3yzi/CTF-WRITEUPS/new/main/2025/NAHAMCON%202025/WEB#solution-flag-4)

![image](https://github.com/user-attachments/assets/b5e846fb-8dce-4d86-80ae-516b2749140b)

![image](https://github.com/user-attachments/assets/e3ca0624-3c5a-47cc-a643-e47b83a65721)

![image](https://github.com/user-attachments/assets/ee28034f-d135-4a97-9604-1d9b94e1e6ce)

![image](https://github.com/user-attachments/assets/459a2207-5f2a-48ca-9760-6fd9eda698e3)

## Solution: Flag #1

by using the wordlist and FUZZing by using intruder, i find this endpoint: 

``
/api/users
``
but, when trying to access ``/{id}`` it gave that an error:

![image](https://github.com/user-attachments/assets/309c439c-f2c4-488a-aaac-ac1b78b97e58)

How to bypass? by adding ``/{id}/log`` 

![image](https://github.com/user-attachments/assets/27e3b7cc-b599-4be1-a333-01dbcf989f18)


After that, we can simply bruteforce to find the right id for it from ``1 - 100``


```
/api/users/0/log
/api/users/1/log
...
/api/users/100/log
```

![image](https://github.com/user-attachments/assets/520f5d6b-3214-426f-8575-633ac9d50de8)

## Flag: Flag #1

``flag{31ef61815ae2b7209d0493b996608be5}``

## Solution: Flag #2

Log in as admin. From first flag we will get the admin details ``"username":"brian.1954"``
Then bruteforce the password with wordlist ``password.txt`` given

![image](https://github.com/user-attachments/assets/ef0a15f6-5ec5-41eb-99e5-c1384a902f17)

```
username : brian.1954
password : dallas
```

## Flag: Flag #2

After that, simply log in with the given username and password. The flag will be in the admin dashboard

![image](https://github.com/user-attachments/assets/1ff71d2b-aa29-4ef6-be8b-d840af0e8fba)

``flag{8a8b9661b3bd2baa2c74347a6c5cc0fc}``

## Solution: Flag #3

For this flag, in the ``/admin/messages/`` each message has it own ``{id}``
So, again we use intruder to bruteforce this

```
/admin/messages/0
/admin/messages/1
...
/admin/messages/1000
```

## Flag: Flag #3

We are seeing an extra message id which then provide us with the third flag:

![image](https://github.com/user-attachments/assets/a7249edc-17bf-4f80-bd28-eeae505596f5)
![image](https://github.com/user-attachments/assets/343cc492-0957-4f4e-aafe-5ddfeeefe87c)

``flag{3a5aed9baa7c7b3ba6cbe4a15425af3f}``

## Solution: Flag #4

From Flag #3 question we are given with ``666e8400-e29b-41d4-a716-446655440666``

![image](https://github.com/user-attachments/assets/3877cf65-4440-4906-8fee-4293567bdec3)

How to use this? Upon reviewing api-endpoints for each request. I find that in /collection

![Screenshot 2025-05-26 022134 copy](https://github.com/user-attachments/assets/b5b93eab-b713-44ec-a576-57f22bfb4f05)

We had json files that are storing the data of the fuzzies bear with GET request on api-endpoint called ``/api/fuzzies``

```json
[
    {
        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "name": "Original Fuzzy",
        "image": "\/images\/fuzzies\/original.png",
        "description": "The one that started it all! This classic bear features the signature soft, fuzzy fur that made Fuzzies famous. Perfect for cuddling and bedtime stories.",
        "hidden": false
    },
    {
        "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "name": "Cool Fuzzy",
        "image": "\/images\/fuzzies\/cool.png",
        "description": "The hippest bear in town! With its stylish sunglasses and laid-back attitude, this Fuzzy was every kid's best friend for summer adventures.",
        "hidden": false
    },
    {
        "id": "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
        "name": "Punk Fuzzy",
        "image": "\/images\/fuzzies\/punk.png",
        "description": "Rock out with this rebellious bear! With its spiky fur and edgy style, this Fuzzy was perfect for kids who wanted to stand out from the crowd.",
        "hidden": false
    },
    {
        "id": "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8g",
        "name": "Roller Fuzzy",
        "image": "\/images\/fuzzies\/roller.png",
        "description": "Skate into fun with this sporty bear! Designed for active kids who loved roller skating and outdoor adventures.",
        "hidden": false
    },
    {
        "id": "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8g9h",
        "name": "Sporty Fuzzy",
        "image": "\/images\/fuzzies\/sporty.png",
        "description": "The athletic bear that cheered on every game! Perfect for young sports enthusiasts who wanted a fuzzy mascot for their team.",
        "hidden": false
    },
    {
        "id": "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8g9h0i",
        "name": "Tie-Dye Fuzzy",
        "image": "\/images\/fuzzies\/tie-dye.png",
        "description": "Peace, love, and fuzzy hugs! This colorful bear brought the psychedelic 80s style to the world of plush toys.",
        "hidden": false
    },
    {
        "id": "g7h8i9j0-k1l2-4m3n-4o5p-6q7r8s9t0u1v",
        "name": "Zebra Fuzzy",
        "image": "\/images\/fuzzies\/zebra.png",
        "description": "A wild twist on the classic Fuzzy! With its unique striped pattern, this bear was perfect for kids who loved animals and adventure.",
        "hidden": false
    }
]
```

![image](https://github.com/user-attachments/assets/28ad0a2a-b95f-4c81-b92f-4306a65c7c08)

That's mean UUID we had before should be the id for fuzzies: 
```http://challenge.nahamcon.com:31526/api/fuzzies?id=666e8400-e29b-41d4-a716-446655440666```

## Flag: Flag #4
![image](https://github.com/user-attachments/assets/d5698c92-0c9f-4374-a609-714d2adf27a4)

``flag{e5f170b92990f73980b48af57f442e1f}``
