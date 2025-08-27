<img width="600" height="416" alt="image" src="https://github.com/user-attachments/assets/78ddbe62-7563-49fc-ac7e-7ed98121ab6e" />

# Challenge

This challenge require us to type `flag.txt` to get flag. And the page sends what you type to `/check` and the server replies per-character with status: **"correct"** | **"incorrect"**

<img width="945" height="562" alt="image" src="https://github.com/user-attachments/assets/17628ed7-d00b-40e7-b173-d59fbd092e11" />

```js
        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ input: attemptString })
            });
            const data = await response.json();
            let incorrectCharsFound = false;

            data.validation.forEach((item, index) => {
                const input = inputs[index];
                input.classList.remove('correct', 'incorrect');
                if (item.status === 'correct') {
                    input.classList.add('correct');
                } else if (item.status === 'incorrect') {
                    input.classList.add('incorrect');
                    incorrectCharsFound = true;
                }
            });
            
            if (incorrectCharsFound) {
                 feedbackText.textContent = "Error: Incorrect filename.";
                 feedbackText.style.color = "#da3633";
            } else {
                 feedbackText.textContent = "Awaiting input...";
                 feedbackText.style.color = "#8b949e"; 
            }

            if (data.all_correct) {
                finalFlagEl.textContent = data.final_flag; 
                resultMessage.style.display = 'block';
                flagInputArea.style.display = 'none';
                feedbackText.style.display = 'none';
            }

        } catch (error) {
            console.error("Error communicating with server:", error);
            feedbackText.textContent = "Connection to validation server failed.";
        }
```

## Solution

So the plan is to use the `/check` endpoint as an oracle and brute-force each position with sets of confusable characters until it marks that position **“correct”**, then lock it in and move to the next position. You can solve it entirely from the browser console with this script:

```js
const endpoint = '/check';

// Expanded homoglyph candidates
const C = {
  'f': [
    'f','ƒ', // latin
    '𝒇','𝓯','𝔣','𝖋','𝘧','𝙛','𝗳','𝚏', // math variants
  ],
  'l': [
    'l', // ASCII
    'ⅼ', // U+217C small roman numeral fifty
    'ℓ', // U+2113 script l
    '𝑙','𝒍','𝓵','𝔩','𝖑','𝗅','𝗹','𝘭','𝙡','𝚕', // math l's
    'ӏ', // U+04CF Cyrillic small letter palochka
    'ı', // U+0131 dotless i
    'ǀ', // U+01C0 dental click (vertical bar)
    '｜', // U+FF5C fullwidth vertical line
    '∣', // U+2223 divides
    '¦'  // broken bar
  ],
  'a': [
    'a','ɑ','ɐ','ᴀ', // latin
    'а', // U+0430 Cyrillic small a
    '𝑎','𝒂','𝓪','𝔞','𝖆','𝗮','𝘢','𝙖','𝚊', // math
  ],
  'g': [
    'g' // looks ASCII in your screenshot
  ],
  '.': ['.'],
  't': [
    't','ţ','ť','ŧ','ƫ','ƭ','ʇ', // latin variants
    'т', // U+0442 Cyrillic small te
    '𝑡','𝒕','𝓽','𝔱','𝖙','𝗍','𝗧','𝘵','𝙩','𝚝' // math
  ],
  'x': [
    'x','×','✕','✖', // ASCII and math
    'х', // U+0445 Cyrillic small ha
    '𝑥','𝒙','𝔵','𝖝','𝗑','𝗫','𝘹','𝙭','𝚡' // math
  ],
};

const target = ['f','l','a','g','.','t','x','t']; // flag.txt
let attempt = target.slice();

async function tryPos(i){
  for (const ch of C[target[i]]) {
    attempt[i] = ch;
    const res = await fetch(endpoint, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({input: attempt.join('')})
    }).then(r=>r.json());

    if (res.validation[i].status === 'correct'){
      console.log(`pos ${i} locked as "${ch}" (U+${ch.codePointAt(0).toString(16).toUpperCase()})`);
      if (res.all_correct){
        console.log('🎉 FLAG:', res.final_flag);
      }
      return true;
    }
  }
  console.warn('No match at pos', i, '— expand the candidate set and retry.');
  return false;
}

(async () => {
  // Check all positions (the script will lock them in once correct)
  for (let i=0; i<target.length; i++) {
    await tryPos(i);
  }
})();
```
## Flag

<img width="1036" height="250" alt="image" src="https://github.com/user-attachments/assets/83985d6e-6aa8-43a7-9dd6-75e13c9982e1" />

<img width="940" height="718" alt="image" src="https://github.com/user-attachments/assets/8a5f210f-014a-4ebe-b7e4-db2d95aca4b7" />

```
n3xt{W3lc0m3_t0_th3_Un1c0d3_W0rld!}
```


