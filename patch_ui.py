import re

with open("dashboard/frontend/index.html", "r") as f:
    content = f.read()

# Replace document.getElementById('rawPayloads').innerText = JSON.stringify(config, null, 2);
content = content.replace("document.getElementById('rawPayloads').innerText = JSON.stringify(config, null, 2);", 
                          "document.getElementById('rawPayloads').innerText = config.raw_payloads || 'Raw payload extraction failed or no IKE packets present.';")

with open("dashboard/frontend/index.html", "w") as f:
    f.write(content)
