
## Challenge

This challenge required us to queue and but tickets for the concert.

But here is the challenge part, we required to skip the queue.

## Solution 

We can see that it is unsecure jwt token for the queue. 

For the exploitation part, we are required to intercept by using burpsuite. 

Do intercept the POST request to **http://challenge.nahamcon.com:31021/check_queue**, manipulate the jwt token. 

To change the jwt token, we can use https://jwt.io/ with payload to cut the queue.

After intercepting the **/check_queue** the response will give us an error that saying the JWT_SECRET for our jwt token is incorrect. 

But, in the error it is included the correct *JWT_SECRET*

```
"JWT_SECRET":"4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC"
```

So use the *JWT_SECRET* given and change our jwt token and reintercept the request again with the working jwt token. 

Next, be sure to always change to our jwt token to each request such as **/purchase** and **/purchase?html=true**

## Flag

By then, we will be provided with pdf file with confirmation code as the flag

```
flag{b1bd4795215a7b81699487cc7e32d936}
```
