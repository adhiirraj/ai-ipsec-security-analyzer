with open("dashboard/backend/api.py", "r") as f:
    content = f.read()
    
content = content.replace("config[\"raw_payloads\"] = \"\n\".join(raw_payloads)", "config[\"raw_payloads\"] = \"\\n\".join(raw_payloads)")

with open("dashboard/backend/api.py", "w") as f:
    f.write(content)
