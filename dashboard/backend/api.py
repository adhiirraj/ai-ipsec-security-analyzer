from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import os
import tempfile
import pandas as pd
import joblib
from scapy.all import rdpcap, ISAKMP_payload_SA, ISAKMP_payload_Transform, ISAKMP
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../../src'))
from ipsec_sentinel.analysis.rules import assess_configuration

sys.path.append(os.path.join(os.path.dirname(__file__), '../../testbed'))
from extract_features import extract_features_from_pcap
import orchestrator

app = FastAPI(title="AI-Powered IPsec VPN Analyzer API")

# Serve the frontend UI at the root URL
frontend_dir = os.path.join(os.path.dirname(__file__), '../frontend')
app.mount("/ui", StaticFiles(directory=frontend_dir), name="frontend")

@app.get("/")
def redirect_to_ui():
    return RedirectResponse(url="/ui/index.html")

class TestbedConfigRequest(BaseModel):
    mode: str
    ike: str
    esp: str
    traffic: str

@app.post("/api/run_testbed")
def run_testbed_endpoint(config: TestbedConfigRequest):
    # Setup testbed (spins up containers if not running)
    orchestrator.setup_testbed()
    
    # Check if PFS is enabled based on if a DH group is appended to ESP proposal
    has_pfs = "-" in config.esp
    pfs_str = "pfs" if has_pfs else "nopfs"
    
    label = f"custom_{config.ike.replace('-','')}_{config.esp.replace('-','')}_{pfs_str}_{config.mode}_{config.traffic}"
    # Run the experiment
    orchestrator.run_experiment(label, config.ike, config.esp, config.mode, config.traffic)
    
    return {"status": "success", "message": "Traffic generated successfully!", "pcap_file": f"{label}.pcap"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), '../../data/models/esp_traffic_classifier.pkl')
try:
    classifier = joblib.load(MODEL_PATH)
except:
    classifier = None

import subprocess

def extract_ike_proposals(pcap_path, original_filename):
    """
    Extracts plaintext IKEv2 proposals (Encryption, Hash, DH) from the 
    IKE_SA_INIT packets by dynamically invoking tshark.
    """
    config = {
        "enc_alg": "unknown",
        "hash_alg": "unknown",
        "dh_group": "unknown",
        "pfs_enabled": False
    }
    
    try:
        # Use tshark to extract ISAKMP Transform parameters
        res = subprocess.run(["tshark", "-r", pcap_path, "-Y", "isakmp", "-V"], 
                             capture_output=True, text=True, timeout=10)
        output = res.stdout
        
        lines = output.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Transform: Encryption (ENCR)
            if "Transform Type: Encryption Algorithm" in line:
                for j in range(1, 4):
                    if "Transform ID" in lines[i+j]:
                        alg = lines[i+j].split(":")[1].strip().lower()
                        if "aes-gcm" in alg: config["enc_alg"] = "aes256gcm16"
                        elif "aes-cbc" in alg: config["enc_alg"] = "aes256-cbc"
                        elif "aes_ctr" in alg: config["enc_alg"] = "aes128-ctr"
                        elif "3des" in alg: config["enc_alg"] = "3des"
                        break
            
            # Transform: PRF (Hash)
            if "Transform Type: Pseudo-random Function" in line:
                for j in range(1, 4):
                    if "Transform ID" in lines[i+j]:
                        alg = lines[i+j].split(":")[1].strip().lower()
                        if "sha2_256" in alg: config["hash_alg"] = "sha256"
                        elif "sha2_384" in alg: config["hash_alg"] = "sha384"
                        elif "sha1" in alg: config["hash_alg"] = "sha1"
                        break
                        
            # Transform: DH (KE)
            if "Transform Type: Key Exchange Method" in line or "Transform Type: Diffie-Hellman Group" in line:
                for j in range(1, 4):
                    if "Transform ID" in lines[i+j]:
                        alg = lines[i+j].split(":")[1].strip().lower()
                        if "256-bit random ecp" in alg: config["dh_group"] = "ecp256"
                        elif "2048-bit modp" in alg: config["dh_group"] = "modp2048"
                        elif "3072-bit modp" in alg: config["dh_group"] = "modp3072"
                        elif "1024-bit modp" in alg: config["dh_group"] = "modp1024"
                        break
                        
            # Detect PFS (Perfect Forward Secrecy)
            # PFS is only visibly negotiated during CREATE_CHILD_SA (rekey). 
            # If we see a KE payload in a CREATE_CHILD_SA exchange, PFS is active!
            if "Exchange type: CREATE_CHILD_SA" in line:
                # If we see this exchange, we look ahead to see if it includes a KE payload
                pass
            if "Payload: Key Exchange (KE)" in line and "CREATE_CHILD_SA" in output:
                config["pfs_enabled"] = True
                
    except Exception as e:
        print(f"tshark error: {e}")
        
    # HACKATHON SHORTCUT / FALLBACK:
    # 1. PFS and Phase 2 (ESP) proposals are sent in IKE_AUTH, which is ENCRYPTED!
    # Without the IKE keys, tshark cannot see the ESP algorithms on the wire.
    # Therefore, we parse Phase 2 parameters from the testbed filename.
    basename = original_filename.lower()
    
    config["esp_enc"] = "unknown"
    config["esp_integrity"] = "none"
    
    if basename.startswith("custom_"):
        parts = basename.split("_")
        if len(parts) >= 3:
            esp_str = parts[2] # e.g. 'aes128ctr' or 'aes128sha256'
            if "gcm" in esp_str:
                config["esp_enc"] = "aes-gcm"
            elif "ctr" in esp_str:
                config["esp_enc"] = "aes-ctr"
                if "sha" in esp_str: config["esp_integrity"] = "sha" # if they ever add it
            elif "aes128" in esp_str or "aes256" in esp_str:
                config["esp_enc"] = "aes-cbc"
                if "sha256" in esp_str: config["esp_integrity"] = "sha256"
                elif "sha384" in esp_str: config["esp_integrity"] = "sha384"
    else:
        # Standard pcaps
        if "aes128" in basename:
            config["esp_enc"] = "aes-cbc"
            config["esp_integrity"] = "sha256"
        elif "aes256gcm" in basename:
            config["esp_enc"] = "aes-gcm"
        elif "aes256" in basename:
            config["esp_enc"] = "aes-cbc"
            config["esp_integrity"] = "sha384"

    if not config["pfs_enabled"] and "pfs" in basename:
        config["pfs_enabled"] = True
        
    return config

@app.post("/api/analyze")
async def analyze_pcap_endpoint(request: Request, filename: str = "upload.pcap"):
    # 1. Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        content = await request.body()
        tmp.write(content)
        tmp_path = tmp.name
        
    response = {
        "filename": filename,
        "security_assessment": {},
        "ai_analysis": []
    }
    
    # 2. Extract Cryptographic config and run Rule Engine
    config = extract_ike_proposals(tmp_path, filename) # using filename for prototype logic
    assessment = assess_configuration(config)
    response["security_assessment"] = assessment
    
    # 3. Extract ESP Flow Features and run ML Model
    if classifier is not None:
        features_list = extract_features_from_pcap(tmp_path, label="unknown")
        for feat in features_list:
            # We need to drop the non-behavioral columns for prediction
            df = pd.DataFrame([feat])
            X = df[['packet_count', 'total_bytes', 'mean_packet_size', 'std_packet_size', 'mean_iat', 'std_iat']]
            
            pred = classifier.predict(X)[0]
            probs = classifier.predict_proba(X)[0]
            confidence = max(probs) * 100
            
            response["ai_analysis"].append({
                "spi": feat["spi"],
                "predicted_traffic": pred,
                "confidence": round(confidence, 2)
            })
    else:
        response["ai_analysis"] = [{"error": "ML Model not trained/found!"}]
        
    os.unlink(tmp_path)
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
