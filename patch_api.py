import re

with open("dashboard/backend/api.py", "r") as f:
    content = f.read()

replacement = """
    try:
        res = subprocess.run(
            [
                "tshark",
                "-r",
                pcap_path,
                "-Y",
                "isakmp",
                "-V",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        lines = res.stdout.splitlines()

        # Extract Raw Proposal Payloads
        raw_payloads = []
        in_proposal = False
        for line in lines:
            # We want to capture everything under "Payload: Proposal (2)"
            # until the next top-level "Payload: " that is not a Transform.
            stripped = line.strip()
            if stripped.startswith("Payload: Proposal (2)"):
                in_proposal = True
                raw_payloads.append(line)
            elif in_proposal:
                if stripped.startswith("Payload: ") and not stripped.startswith("Payload: Transform"):
                    in_proposal = False
                else:
                    raw_payloads.append(line)
                    
        config["raw_payloads"] = "\n".join(raw_payloads) if raw_payloads else "No ISAKMP proposals found in PCAP."

        for i, line in enumerate(lines):
"""

content = re.sub(r'    try:\n        res = subprocess\.run\([\s\S]*?for i, line in enumerate\(lines\):', replacement.strip(), content, count=1)

with open("dashboard/backend/api.py", "w") as f:
    f.write(content)
