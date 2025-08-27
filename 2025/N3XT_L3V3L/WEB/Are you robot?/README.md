# Challenge

<img width="934" height="564" alt="image" src="https://github.com/user-attachments/assets/1c32d1af-d561-4e40-90f4-5fe2cb389d9c" />

This challenge is quite simple. It's required us to verify by sliding the slider.

<img width="940" height="945" alt="image" src="https://github.com/user-attachments/assets/2d500b9f-0a2e-410f-8e23-40eb1da7183e" />

# Solution 

1) We just need to slide to get the first part of the flag.

<img width="940" height="940" alt="image" src="https://github.com/user-attachments/assets/1073c2f7-dd21-4e49-8ebe-1e21991a9b1e" />

First part of flag: `n3xt{dr4g_`

From the source code we can find that the challenge tend to simulate on how clickjacking work. Here's how the hidden iframe will then simulate that simple vulnerable verification might compromised us.

`index.html`
```
 <div class="slider-wrapper">
                <div class="slider-track">
                    <div class="slider-handle">></div>
                    <span class="slider-text">Slide to Verify</span>
                </div>
                
                <iframe class="hidden-frame" src="/file-manager"></iframe>
            </div>
```

`file-manager.html`
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Manager</title>
    <link rel="stylesheet" href="/static/main.css">
</head>
<body class="panel-body">
    <div class="file-manager">
        <div id="draggable-file" class="file-icon" draggable="true">
            📄 My-Secrets.zip
        </div>

        <div id="drop-zone" class="trash-icon">
            🗑️
        </div>
    </div>

    <script>
        const draggable = document.getElementById('draggable-file');
        const dropZone = document.getElementById('drop-zone');

        draggable.addEventListener('dragstart', (event) => {
            event.dataTransfer.setData('text/plain', event.target.id);
        });

        dropZone.addEventListener('dragover', (event) => {
            event.preventDefault();
        });

        dropZone.addEventListener('drop', async (event) => {
            event.preventDefault();
            
            draggable.style.display = 'none';
            dropZone.style.color = '#e74c3c'; 
            
            try {
                const response = await fetch('/delete-file', { method: 'POST' });
                const result = await response.json();
                window.parent.postMessage(result, '*');
            } catch (error) {
                console.error("Could not send request to server.");
            }
        });
    </script>
</body>
</html>
```

2) Next part of the flag at `robots.txt`

Second part of the flag: `{"flag":"4nd_dr0p_h1j4ck3d_succ3ssfully}"}`

<img width="759" height="284" alt="image" src="https://github.com/user-attachments/assets/13ad3b65-c07f-4002-be32-2331625cb9b8" />

## Flag

```
n3xt{dr4g_4nd_dr0p_h1j4ck3d_succ3ssfully}
```
