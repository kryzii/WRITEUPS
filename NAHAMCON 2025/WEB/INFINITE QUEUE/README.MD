
## Challenge

This challenge required us to queue and but tickets for the concert.

But here is the challenge part, we required to skip the queue.

## Solution 

We can see that it is unsecure jwt token for the queue. 

For the exploitation part, we are needed to intercept the POST request to *http://challenge.nahamcon.com:31021/check_queue* with jwt token. And change with payload to cut the queue.



