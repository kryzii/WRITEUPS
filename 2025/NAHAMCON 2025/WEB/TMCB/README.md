![Screenshot 2025-05-25 164726](https://github.com/user-attachments/assets/8de99c23-23ec-47ac-9901-a913eba42c37)
## Challenge

This challenge provided a frontend with 2,000,000 checkboxes and a WebSocket backend that tracks checked states server-side. The goal was to tick all 2 million checkboxes to reveal the flag.

![Screenshot 2025-05-25 165622](https://github.com/user-attachments/assets/31cb9004-1571-42db-9323-7e229466d8d1)

From this static/js/main.js
```js
document.addEventListener('DOMContentLoaded', () => {
    // Use native WebSocket
    let ws;
    let checkedBoxes = new Set();
    const TOTAL_CHECKBOXES = 2_000_000;
    const CHECKBOXES_PER_PAGE = 1000; // Smaller chunks for smoother loading
    let currentPage = 0;
    let isLoading = false;
    let hasMoreCheckboxes = true;
    
    const checkboxGrid = document.getElementById('checkbox-grid');
    const checkedCount = document.getElementById('checked-count');
    const flagContainer = document.getElementById('flag-container');
    const flagElement = document.getElementById('flag');
    const loadingOverlay = document.querySelector('.loading-overlay');
    const content = document.querySelector('.content');
    
    // Server-side state
    const SERVER_FLAG = window.SERVER_FLAG;
    const ALL_CHECKED = window.ALL_CHECKED;
    
    // If server says all checkboxes are checked, show flag immediately
    if (ALL_CHECKED && SERVER_FLAG) {
        showFlagDialog();
    }
    
    function connectWebSocket() {
        ws = new WebSocket('ws://' + window.location.host + '/ws');
        
        ws.onopen = function() {
            // Request initial state when connection is established
            ws.send(JSON.stringify({ action: 'get_state' }));
        };
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.checked) {
                try {
                    // Decode base64
                    const decoded = atob(data.checked);
                    // Convert to Uint8Array for pako
                    const compressed = new Uint8Array(decoded.length);
                    for (let i = 0; i < decoded.length; i++) {
                        compressed[i] = decoded.charCodeAt(i);
                    }
                    // Decompress using pako
                    const decompressed = pako.inflate(compressed, { to: 'string' });
                    // Parse JSON
                    const checkboxList = JSON.parse(decompressed);
                    
                    checkedBoxes = new Set(checkboxList);
                    updateUI();
                    
                    // Hide loading overlay and show content
                    if (loadingOverlay) {
                        loadingOverlay.style.display = 'none';
                    }
                    if (content) {
                        content.classList.add('loaded');
                    }
                    
                    // Load initial batch of checkboxes
                    loadMoreCheckboxes();
                } catch (e) {
                    console.error('Error processing compressed data:', e);
                }
            }
            if (data.error) {
                console.error('WebSocket error:', data.error);
            }
        };

        ws.onclose = function() {
            console.log('WebSocket closed, reconnecting...');
            setTimeout(connectWebSocket, 1000);
        };
    }

    function updateUI() {
        document.getElementById('checked-count').textContent = checkedBoxes.size.toLocaleString();
        
        // Show flag dialog if all checkboxes are checked
        if (checkedBoxes.size === TOTAL_CHECKBOXES && SERVER_FLAG) {
            showFlagDialog();
        } else {
            // Hide flag if not all checkboxes are checked
            flagContainer.style.display = 'none';
        }
    }

    function showFlagDialog() {
        flagElement.textContent = SERVER_FLAG;
        flagContainer.style.display = 'block';
        
        // Trigger confetti
        confetti({
            particleCount: 100,
            spread: 70,
            origin: { y: 0.6 }
        });
    }

    function loadMoreCheckboxes() {
        if (isLoading || !hasMoreCheckboxes) return;
        
        isLoading = true;
        const start = currentPage * CHECKBOXES_PER_PAGE;
        const end = Math.min(start + CHECKBOXES_PER_PAGE, TOTAL_CHECKBOXES);
        
        // Create a document fragment for better performance
        const fragment = document.createDocumentFragment();
        
        for (let i = start; i < end; i++) {
            const checkboxContainer = document.createElement('div');
            checkboxContainer.className = 'checkbox-container';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `checkbox-${i}`;
            checkbox.checked = checkedBoxes.has(i);
            
            checkbox.addEventListener('change', function() {
                const numbers = [i];
                if (this.checked) {
                    ws.send(JSON.stringify({
                        action: 'check',
                        numbers: numbers
                    }));
                } else {
                    ws.send(JSON.stringify({
                        action: 'uncheck',
                        numbers: numbers
                    }));
                }
            });
            
            checkboxContainer.appendChild(checkbox);
            fragment.appendChild(checkboxContainer);
        }
        
        // Append all new checkboxes at once
        checkboxGrid.appendChild(fragment);
        
        currentPage++;
        isLoading = false;
        
        // Check if we've reached the end
        if (end >= TOTAL_CHECKBOXES) {
            hasMoreCheckboxes = false;
        }
    }

    // Initial setup
    connectWebSocket();

    // Handle page navigation with debouncing
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (scrollTimeout) {
            clearTimeout(scrollTimeout);
        }
        
        scrollTimeout = setTimeout(function() {
            const scrollPosition = window.scrollY;
            const windowHeight = window.innerHeight;
            const documentHeight = document.documentElement.scrollHeight;
            
            // Load more when user is near the bottom
            if (scrollPosition + windowHeight >= documentHeight - 500) {
                loadMoreCheckboxes();
            }
        }, 100); // Debounce scroll events
    });
}); 
```
The challenge relied on client-side checkbox interactions, but used WebSocket messages to actually track progress on the server.

This means: you didn’t have to click UI checkboxes, you only needed to send the right messages. The WebSocket accepted raw JSON messages with no authentication, rate-limiting, or replay protection and anyone could: **Connect directly, Forge messages or even Automate the interaction**

## Solution

We scripted (by vibe-coding) a solution in the browser’s console that:

![image](https://github.com/user-attachments/assets/fee821f5-009f-4c10-833b-5407491694ad)

- Sent batches of 20,000 checkbox indices
- Used localStorage to track progress
- Automatically resumed if interrupted
- After sending all 2 million, the server would respond with the flag or set it in window.SERVER_FLAG

```js
let ws;
let index = parseInt(localStorage.getItem("progress") || "0", 10);
const total = 2_000_000;
const batchSize = 20000;
const delay = 250;
let reconnectAttempts = 0;

function connectWebSocket() {
  ws = new WebSocket("ws://" + window.location.host + "/ws");

  ws.onopen = () => {
    console.log(`✅ Connected. Resuming at index ${index}`);
    reconnectAttempts = 0;
    sendNextBatch();
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.flag) {
        console.log("🎉 FLAG:", data.flag);
        alert("🎉 FLAG: " + data.flag);
      } else {
        console.log("📩 Server response:", data);
      }
    } catch (e) {
      console.warn("⚠️ Non-JSON message:", event.data);
    }
  };

  ws.onclose = () => {
    console.warn("❌ WebSocket closed. Reconnecting...");
    reconnectAttempts++;
    const backoff = Math.min(2000 * reconnectAttempts, 10000);
    setTimeout(connectWebSocket, backoff);
  };

  ws.onerror = (err) => {
    console.error("🚨 WebSocket error:", err);
    ws.close();
  };
}

function sendNextBatch() {
  if (ws.readyState !== WebSocket.OPEN) {
    console.warn("⚠️ WebSocket not open. Skipping batch.");
    return;
  }

  if (index >= total) {
    console.log("✅ All 2 million checkboxes sent!");
    return;
  }

  const numbers = [];
  for (let i = index; i < Math.min(index + batchSize, total); i++) {
    numbers.push(i);
  }

  ws.send(JSON.stringify({ action: "check", numbers }));
  localStorage.setItem("progress", index);

  if (index % 100000 === 0) {
    console.log(`📦 Progress: ${index.toLocaleString()} / ${total.toLocaleString()}`);
  }

  console.log(`✅ Sent ${numbers.length} checkboxes: ${index} to ${index + numbers.length - 1}`);
  index += batchSize;

  setTimeout(sendNextBatch, delay);
}

connectWebSocket();
```

![Screenshot 2025-05-25 165654](https://github.com/user-attachments/assets/4c80670c-0054-4a91-8470-f5854744cbc9)

But, Due to network or timing issues, some final batches didn’t register. We resolved this by reset our progress in local storage and replaying the final 100,000 checkboxes and manually triggering a state check.

```js
const ws2 = new WebSocket("ws://" + window.location.host + "/ws");

ws2.onopen = () => {
  const numbers = [];
  for (let i = 1980000; i < 2000000; i++) {
    numbers.push(i);
  }

  ws2.send(JSON.stringify({
    action: "check",
    numbers
  }));

  console.log("✅ Final batch sent: 1,980,000 to 1,999,999");

  setTimeout(() => {
    ws2.send(JSON.stringify({ action: "get_state" }));
  }, 500);
};

ws2.onmessage = (event) => {
  try {
    const data = JSON.parse(event.data);
    console.log("📩 Server says:", data);
    if (data.flag) {
      alert("🎉 FLAG: " + data.flag);
    }
  } catch (e) {
    console.warn("⚠️ Could not parse message:", event.data);
  }
};
```

## Flag
Once the server verified all checkboxes were checked, it revealed the flag through the WebSocket or the DOM.

![Screenshot 2025-05-24 214523](https://github.com/user-attachments/assets/378188c5-4c2f-4e04-b432-69c6400f6ec4)

```
flag{7d798903eb2a1823803a243dde6e9d5b}
```
