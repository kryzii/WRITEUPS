Deprecated Site
100
CSG's left an old webpage up on accident. It's old and deprecated, maybe you should do us a favor and get rid of it?
74.207.229.59:20201

## How the app works:

![image](https://github.com/user-attachments/assets/d457bef0-561f-40c1-8248-97c3fb6e1e29) ![image](https://github.com/user-attachments/assets/68efbf29-939e-4ea1-8318-67d8d20904f8)

Nothing much, just simple text. I then proceed checking the source code. I find **script.js** that are empty.  At then check the **robots.txt** because I might find something there. 

![image](https://github.com/user-attachments/assets/0a12dc74-84c9-4531-8cdf-c5b547e60829) ![image](https://github.com/user-attachments/assets/9d2a6c05-0a76-452f-bf4c-f6499f61ba8b)

I then knew it, we might actually need to use simply request the flag by using DELETE method.  

![image](https://github.com/user-attachments/assets/8f3c0854-7ac0-44af-b8b3-4473b745b482)
```
curl -X DELETE http://74.207.229.59:20201/flag.txt
```

## Flag: 
```
texsaw{why_d0_i_del3t3ed}
```
