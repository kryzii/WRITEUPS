### The Wax-Circle Reclaimed

<img width="1148" height="900" alt="image" src="https://github.com/user-attachments/assets/d985d9b3-26a5-4b38-bd83-6df2b93fecc5" />

#### Description

<img width="509" height="729" alt="image" src="https://github.com/user-attachments/assets/f0ad3a80-236b-475d-8cf2-cdf117789013" />

#### Challenge

<img width="987" height="872" alt="image" src="https://github.com/user-attachments/assets/9d42e23b-b539-4ac0-b86a-c6af7a234938" />

<img width="1148" height="900" alt="image" src="https://github.com/user-attachments/assets/c47d299a-1ee9-4724-ab9c-78956eb44827" />

<img width="1081" height="915" alt="image" src="https://github.com/user-attachments/assets/14b85841-575a-47af-8004-b998f4a010c0" />

This question required us to authenticate with ``role: guardian`` and ``clearance_level: divine_authority`` to get the flag

<img width="1264" height="719" alt="image" src="https://github.com/user-attachments/assets/b551354f-cd24-437a-8a41-18ada2625a2e" />

#### Initial Discovery

Before i actually did the final solution, i thought this could be a typical weak JWT secret bruteforce questions. I used **[jwt_tool](https://github.com/ticarpi/jwt_tool)** for that. And waste quite some time there. But still failed to crack the secret. 

So i proceed to download and review source code given from the question:

```
// Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '24h';
const couchdbUrl = 'http://admin:waxcircle2025@127.0.0.1:5984';
```

From these code we find multiple key things, first. It used ``const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');``. It would be imposible to crack it with a rockyou wordlists. 

And there's the hardcoded couchdbUrl ``http://admin:waxcircle2025@127.0.0.1:5984``

So we can use the ``analyse-breach`` that will extract JSON data from any url included its internal couchdbUrl data. 

```
app.post('/api/analyze-breach', requireAuth, (req, res) => {
    const { data_source } = req.body;
    
    if (!data_source) return res.status(400).json({ error: 'Data source URL required' });
    
    try {
        axios.get(data_source, { timeout: 5000, maxRedirects: 0 })
            .then(response => {
                let data = response.data;
                
                if (typeof data !== 'string') {
                    data = JSON.stringify(data);
                }
                
                // Check if data exceeds 1000 bytes
                const dataSize = Buffer.byteLength(data, 'utf8');
                if (dataSize > 1000) {
                    // Concatenate the data to fit within 1000 bytes
                    const truncatedData = data.substring(0, Math.floor(1000 / Buffer.byteLength(data.charAt(0), 'utf8')));
                    res.json({ 
                        status: 'success', 
                        data: truncatedData, 
                        source: data_source,
                        truncated: true,
                        originalSize: dataSize,
                        truncatedSize: Buffer.byteLength(truncatedData, 'utf8')
                    });
                } else {
                    res.json({ 
                        status: 'success', 
                        data: data, 
                        source: data_source,
                        truncated: false,
                        size: dataSize
                    });
                }
            })
            .catch(error => res.status(500).json({ status: 'error', message: 'External API unavailable' }));
            
    } catch (error) {
        res.status(400).json({ status: 'error', message: 'Invalid URL format' });
    }
});
```

#### Solution

I then do a bit of research, and find [this](https://docs.couchdb.org/en/stable/json-structure.html)

```
// Wait for CouchDB to be ready
async function waitForCouchDB() {
    for (let i = 0; i < 30; i++) {
        try {
            const response = await axios.get(`${couchdbUrl}/_up`);
            if (response.status === 200) return;
        } catch (error) {
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
    throw new Error('CouchDB failed to start within expected time');
}
```
This actually proof that it's reachable and can leak its own databases.

<img width="993" height="548" alt="image" src="https://github.com/user-attachments/assets/9b1d134a-735f-4088-87c8-4132aff3237e" />

So we need to find users with **role: guardian** and also **clearance_level: divine_authority** and it should be **elin_croft** based from the ``server.js``

```
    for (let i = 1; i <= 1000; i++) {
        // Check if this is the position for elin_croft
        if (i === elinCroftPosition) {
            const elinPassword = generateSecurePassword(16);
            generatedUsers.push({
                _id: 'user_elin_croft',
                type: 'user',
                username: 'elin_croft',
                password: elinPassword,
                role: 'guardian',
                clearance_level: 'divine_authority'
            });
        }
```
Final payload should be ``http://admin:waxcircle2025@127.0.0.1:5984/users/user_elin_croft``

<img width="1120" height="630" alt="image" src="https://github.com/user-attachments/assets/1961f982-0c98-485d-8dc7-1e58ca490ab2" />

#### Flag

<img width="917" height="528" alt="image" src="https://github.com/user-attachments/assets/c2a99980-78b3-43ec-b7f2-3199f9befbaa" />

```
HTB{w4x_c1rcl3s_c4nn0t_h0ld_wh4t_w4s_n3v3r_b0und_970c9379f6805ba5edbe5ec11d20f076}
```
