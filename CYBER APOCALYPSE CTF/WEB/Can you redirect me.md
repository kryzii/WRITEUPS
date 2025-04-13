## Can you redirect me

Category: Web  

## Challenge
To get the flag, we need to satisfy this condition:
```js
if(new URL(final_url).hostname != "www.google.com"){
    res.status(200);
    res.send("<script>alert('FLAG{**REDACTED**}');history.back()</script>")
    return
}
```
This means the bot will only give the flag if the final redirect location is NOT www.google.com

But the first request checks:
```js
if(url.hostname != "www.google.com"){
    res.status(400);
    res.send("I ONLY trust GOOGLE");
    return
}
```

##Solution
Use Google open redirect with /amp/

![image](https://github.com/user-attachments/assets/4059a7ef-e8db-4ef1-b45e-98d8de7ededa)

Payload:
```
https://www.google.com/amp/httpforever.com
```
Final request:
```
/report?url=https://www.google.com/amp/httpforever.com
```
