![Screenshot 2025-05-25 161440](https://github.com/user-attachments/assets/addde689-ac3c-4373-9a90-69ba06f118f1)
## Challenge

This challenge required us to queue and buy the tickets for the concert. And we can see that, there is jwt token for the queue. 

![Screenshot 2025-05-25 161937](https://github.com/user-attachments/assets/db94717d-a685-4059-a63f-e7fa44888fae) ![Screenshot 2025-05-25 162142](https://github.com/user-attachments/assets/4acffa24-0052-42eb-8fcb-b8c00a667396)

## Solution 

For the exploitation part, we are required to intercept by using Burpsuite. 

After the POST **/join_queue** request, we will be response with the token that represent for our queue time. 

![image](https://github.com/user-attachments/assets/5f8f4f1b-3120-4b0e-837f-3bdd6ee5fdf9)

First, we suppose to change the token (by using https://jwt.io/) to cut the queue time for buying the tickets from:

![Screenshot 2025-05-25 163128](https://github.com/user-attachments/assets/99c1409f-e491-4657-a3ed-125907440608)

to:

![Screenshot 2025-05-25 163142](https://github.com/user-attachments/assets/188c69a9-26ff-4138-b24d-cb6539129157)

Next, intercept the POST request to **/check_queue**, and change with our new token. 

After intercepting the **/check_queue** the response will give us an error that saying the *JWT_SECRET* for our jwt token is incorrect. 

![image](https://github.com/user-attachments/assets/e82c2358-9657-496e-bc75-6f1814b49202)

But, in the error it is actually included the correct *JWT_SECRET* which something that are not suppose to be expose:

```
"JWT_SECRET":"4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC"
```

So we can use the *JWT_SECRET* given and change our token with valid jwt secret and reintercept the request again with the working jwt token. 

Next, be sure to always change to our jwt token to each request such as **/purchase** and **/purchase?html=true**

![image](https://github.com/user-attachments/assets/5c51e150-8b5e-4493-abf5-ee9567b952c4)

![image](https://github.com/user-attachments/assets/e61c5c17-96a6-4023-a94e-ac0857c3c0f3)

## Flag

By then, we will be provided with pdf file with confirmation code as the flag/we can simply get those from the **/purchase?html=true** response

![Screenshot 2025-05-25 164145](https://github.com/user-attachments/assets/ff2e5718-8e87-47eb-8835-e8575c28dfd2)
![image](https://github.com/user-attachments/assets/b44c541e-17a4-48d5-8b13-61d9c182e664)

```
flag{b1bd4795215a7b81699487cc7e32d936}
```
