from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock
from tempfile import NamedTemporaryFile
import os
import subprocess
import sys

import joblib
import pandas as pd
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

sys.path.append(os.path.join(os.path.dirname(__file__), "../../src"))
from ipsec_sentinel.analysis.rules import assess_configuration

sys.path.append(os.path.join(os.path.dirname(__file__), "../../testbed"))
from extract_features import extract_features_from_pcap
import orchestrator


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = (BASE_DIR / "../frontend").resolve()

# Serialize testbed generation. One running VPN testbed cannot safely service
# two different proposal configurations at the same time.
TESTBED_LOCK = Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Docker/StrongSwan startup happens once at API startup, not once per PCAP.
    orchestrator.setup_testbed()
    yield
    # Deliberately leave containers running. This avoids another expensive
    # start/stop cycle during development or when uvicorn reloads.
    # Run `docker compose down` manually when finished.


app = FastAPI(
    title="AI-Powered IPsec VPN Analyzer API",
    lifespan=lifespan,
)

app.mount(
    "/ui",
    StaticFiles(directory=FRONTEND_DIR),
    name="frontend",
)


@app.get("/")
def redirect_to_ui():
    return RedirectResponse(url="/ui/index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "testbed": "ready",
    }


class TestbedConfigRequest(BaseModel):
    mode: str
    ike: str
    esp: str
    traffic: str
<<<<<<< HEAD
    duration: int = Field(default=15, ge=1, le=300)


@app.post("/api/run_testbed")
def run_testbed_endpoint(config: TestbedConfigRequest):
    with TESTBED_LOCK:
        pfs_str = "pfs" if orchestrator.esp_has_pfs(config.esp) else "nopfs"
=======
    ip_version: str

@app.post("/api/run_testbed")
def run_testbed_endpoint(config: TestbedConfigRequest):
    # Setup testbed (spins up containers if not running)
    orchestrator.setup_testbed()
    
    # Check if PFS is enabled based on if a DH group is appended to ESP proposal
    has_pfs = "-" in config.esp and not config.esp.endswith("none")
    pfs_str = "pfs" if has_pfs else "nopfs"
    
    label = f"custom_{config.ike.replace('-','')}_{config.esp.replace('-','')}_{pfs_str}_{config.mode}_{config.ip_version}_{config.traffic}"
    
    import io
    from contextlib import redirect_stdout
    
    f = io.StringIO()
    with redirect_stdout(f):
        # Run the experiment
        orchestrator.run_experiment(label, config.ike, config.esp, config.mode, config.traffic, config.ip_version)
    logs = f.getvalue()
    
    return {
        "status": "success", 
        "message": "Traffic generated successfully!", 
        "pcap_file": f"{label}.pcap",
        "logs": logs
    }
>>>>>>> dfb650830562787739650f13b6dd754e84907510

        label = (
            f"custom_"
            f"{config.ike.replace('-', '')}_"
            f"{config.esp.replace('-', '')}_"
            f"{pfs_str}_"
            f"{config.mode}_"
            f"{config.traffic}"
        )

        pcap_path = orchestrator.run_experiment(
            label,
            config.ike,
            config.esp,
            config.mode,
            config.traffic,
            config.duration,
        )

    return {
        "status": "success",
        "message": "Traffic generated successfully!",
        "pcap_file": pcap_path.name,
    }


MODEL_PATH = BASE_DIR / "../../data/models/esp_traffic_classifier.pkl"

try:
    classifier = joblib.load(MODEL_PATH)
except Exception:
    classifier = None


def extract_ike_proposals(pcap_path, original_filename):
    """
    Extract plaintext IKEv2 proposals from IKE_SA_INIT.
    Phase-2 information is recovered from the dataset filename because the
    relevant payload is encrypted in the current prototype.
    """
    config = {
        "enc_alg": "unknown",
        "hash_alg": "unknown",
        "dh_group": "unknown",
        "pfs_enabled": False,
        "esp_enc": "unknown",
        "esp_integrity": "none",
    }

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

        for i, line in enumerate(lines):
            line = line.strip()

            if "Transform Type: Encryption Algorithm" in line:
                for j in range(1, 4):
                    if i + j >= len(lines):
                        break
                    if "Transform ID" in lines[i + j]:
                        alg = lines[i + j].split(":", 1)[-1].strip().lower()
                        if "aes-gcm" in alg:
                            config["enc_alg"] = "aes256gcm16"
                        elif "aes-cbc" in alg:
                            config["enc_alg"] = "aes256-cbc"
                        elif "aes_ctr" in alg:
                            config["enc_alg"] = "aes128-ctr"
                        elif "3des" in alg:
                            config["enc_alg"] = "3des"
                        break

            if "Transform Type: Pseudo-random Function" in line:
                for j in range(1, 4):
                    if i + j >= len(lines):
                        break
                    if "Transform ID" in lines[i + j]:
                        alg = lines[i + j].split(":", 1)[-1].strip().lower()
                        if "sha2_256" in alg:
                            config["hash_alg"] = "sha256"
                        elif "sha2_384" in alg:
                            config["hash_alg"] = "sha384"
                        elif "sha1" in alg:
                            config["hash_alg"] = "sha1"
                        break

            if (
                "Transform Type: Key Exchange Method" in line
                or "Transform Type: Diffie-Hellman Group" in line
            ):
                for j in range(1, 4):
                    if i + j >= len(lines):
                        break
                    if "Transform ID" in lines[i + j]:
                        alg = lines[i + j].split(":", 1)[-1].strip().lower()
                        if "256-bit random ecp" in alg:
                            config["dh_group"] = "ecp256"
                        elif "2048-bit modp" in alg:
                            config["dh_group"] = "modp2048"
                        elif "3072-bit modp" in alg:
                            config["dh_group"] = "modp3072"
                        elif "1024-bit modp" in alg:
                            config["dh_group"] = "modp1024"
                        break

        output = res.stdout
        if "Exchange type: CREATE_CHILD_SA" in output and "Payload: Key Exchange (KE)" in output:
            config["pfs_enabled"] = True

    except Exception as exc:
        print(f"tshark error: {exc}")

    basename = original_filename.lower()

    if basename.startswith("custom_"):
        parts = basename.split("_")
        if len(parts) >= 3:
            esp_str = parts[2]

            if "gcm" in esp_str:
                config["esp_enc"] = "aes-gcm"
            elif "ctr" in esp_str:
                config["esp_enc"] = "aes-ctr"
                if "sha" in esp_str:
                    config["esp_integrity"] = "sha"
            elif "aes128" in esp_str or "aes256" in esp_str:
                config["esp_enc"] = "aes-cbc"
                if "sha256" in esp_str:
                    config["esp_integrity"] = "sha256"
                elif "sha384" in esp_str:
                    config["esp_integrity"] = "sha384"

    else:
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
    tmp_path = None

    try:
        with NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            content = await request.body()
            tmp.write(content)
            tmp_path = tmp.name

        response = {
            "filename": filename,
            "security_assessment": {},
            "ai_analysis": [],
        }

        config = extract_ike_proposals(tmp_path, filename)
        response["security_assessment"] = assess_configuration(config)

        if classifier is not None:
            features_list = extract_features_from_pcap(
                tmp_path,
                label="unknown",
            )

            if features_list:
                feature_columns = [
                    "packet_count",
                    "total_bytes",
                    "mean_packet_size",
                    "std_packet_size",
                    "mean_iat",
                    "std_iat",
                ]

                df = pd.DataFrame(features_list)
                X = df[feature_columns]

                predictions = classifier.predict(X)
                probabilities = classifier.predict_proba(X).max(axis=1) * 100.0

                response["ai_analysis"] = [
                    {
                        "spi": feat["spi"],
                        "predicted_traffic": pred,
                        "confidence": round(conf, 2),
                    }
                    for feat, pred, conf
                    in zip(features_list, predictions, probabilities)
                ]
        else:
            response["ai_analysis"] = [
                {"error": "ML Model not trained/found!"}
            ]

        return response

    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
    )

