### The Gates of Broken Names
#### Description

<img width="525" height="243" alt="image" src="https://github.com/user-attachments/assets/a7e6224d-a833-4141-ba86-f18000d82027" />

#### Challenge

This challenge required us to signed up and logged in to authenticated.

<img width="1275" height="914" alt="image" src="https://github.com/user-attachments/assets/62ef6835-bc16-422f-bc68-643e29ee2b7a" />

<img width="1133" height="720" alt="image" src="https://github.com/user-attachments/assets/60c4d3e7-2a9b-46be-aaa9-bb3844b6c57d" />

Users can reviews other users **Publicly Published Chronicles** *(posts)*

<img width="1140" height="757" alt="image" src="https://github.com/user-attachments/assets/3ff8da88-1c78-4ec8-b444-b44902e8b97f" />

Create your **own Public/Private Chronicles**

<img width="951" height="750" alt="image" src="https://github.com/user-attachments/assets/53b973af-0a8f-4b44-829b-1fd9adf5bdc3" />

View your **own profile** 

<img width="902" height="271" alt="image" src="https://github.com/user-attachments/assets/ca2b8031-c9f4-4a2a-b173-029535e83591" />

#### Initial Discovery

There's a possible **[IDOR](https://portswigger.net/web-security/access-control/idor)** vulnerabilities, because we can see its `GET` api request from network logs

<img width="1493" height="482" alt="image" src="https://github.com/user-attachments/assets/988e3ae6-8db2-4df1-92e4-7c20ecc8c6fc" />

It's proven because of **Private** posts leaked too without requiring any authentication

<img width="1526" height="491" alt="image" src="https://github.com/user-attachments/assets/129d90e9-eed1-4ae2-907d-9f848c5c71ca" />

#### Solution

I used **[Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)** to solve this.

<img width="1238" height="598" alt="image" src="https://github.com/user-attachments/assets/117c47d9-6fe1-4bf8-b6a3-ffdfba66ddad" />

We can use **sniper attack** for attack type and use **numbers** as the payload type from ``1 - 210`` *(our recent postid is 211)*

<img width="847" height="612" alt="image" src="https://github.com/user-attachments/assets/cf13654a-e7be-47f6-bee3-c654ec2ed0fc" />

Add response filter `"is_private":1,` this could be if you want to play safe in most CTF *(Because not everytime it would give the flag directly)*

<img width="574" height="190" alt="image" src="https://github.com/user-attachments/assets/7405046f-c56f-4bcf-b2d5-ab99e07d717e" />

<img width="1473" height="678" alt="image" src="https://github.com/user-attachments/assets/0f1b1273-564b-4487-924c-9ca4cfc7b299" />

But a better regex that directly fetch flag is `HTB\` and be sure to check ``Regex``

<img width="571" height="191" alt="image" src="https://github.com/user-attachments/assets/c3da76ff-29e8-4082-85a5-ae42b71d3b26" />

<img width="1481" height="674" alt="image" src="https://github.com/user-attachments/assets/9e1f3fea-89d6-4d69-bdb9-9c6a5ead7b6d" />

#### Flag

```
HTB{br0k3n_n4m3s_r3v3rs3d_4nd_r3st0r3d_88ef1b19ab6c71c233c1f91bf1454a12}
```
