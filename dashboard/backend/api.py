"""Dashboard API with conservative PCAP analysis and explicit testbed control."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from threading import Lock
from typing import Literal

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from ipsec_sentinel.analysis.rules import assess_configuration
from ipsec_sentinel.capture.reader import PcapError
from testbed import orchestrator


LOGGER = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = (BASE_DIR / "../frontend").resolve()
MODEL_PATH = PROJECT_ROOT / "data/models/esp_traffic_classifier.pkl"
TESTBED_LOCK = Lock()
_classifier: object | None = None
_model_checked = False


def _positive_environment_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


MAX_UPLOAD_BYTES = _positive_environment_int("IPSEC_SENTINEL_MAX_UPLOAD_BYTES", 32 * 1024 * 1024)


def _load_classifier() -> object | None:
    """Load the optional inference model once; never train at API import time."""

    global _classifier, _model_checked
    if _model_checked:
        return _classifier
    _model_checked = True
    if not MODEL_PATH.is_file():
        LOGGER.info("Optional ML model is absent: %s", MODEL_PATH)
        return None
    try:
        import joblib

        _classifier = joblib.load(MODEL_PATH)
    except Exception:  # noqa: BLE001 - malformed local model must not stop the API.
        LOGGER.exception("Could not load optional ML model from %s", MODEL_PATH)
        _classifier = None
    return _classifier


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Keep startup side-effect free: no Docker, VPN, capture, or model training."""

    LOGGER.info("Dashboard API started; testbed remains stopped until /api/run_testbed is called.")
    yield


app = FastAPI(title="AI-Powered IPsec VPN Analyzer API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("IPSEC_SENTINEL_CORS_ORIGINS", "http://localhost:8000").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
if FRONTEND_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    LOGGER.warning(
        "Frontend directory %s does not exist; /ui will not serve static files.", FRONTEND_DIR
    )



class TestbedConfigRequest(BaseModel):
    mode: Literal["tunnel", "transport"]
    ike: str = Field(min_length=3, max_length=160)
    esp: str = Field(min_length=3, max_length=160)
    traffic: Literal["voip", "web", "bulk", "icmp", "video", "whatsapp", "email"]
    ip_version: Literal["ipv4", "ipv6"] = "ipv4"
    duration: int = Field(default=15, ge=1, le=300)


@app.get("/")
def redirect_to_ui() -> RedirectResponse:
    return RedirectResponse(url="/ui/index.html")


@app.get("/api/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "testbed": "ready",
    }


class TestbedConfigRequest(BaseModel):
    mode: str
    ike: str
    esp: str
    traffic: str
    ip_version: str
    duration: int = Field(default=15, ge=1, le=300)


@app.post("/api/run_testbed")
def run_testbed_endpoint(config: TestbedConfigRequest) -> dict[str, str]:
    """Run a requested, real strongSwan experiment or return an actionable 503."""

    with TESTBED_LOCK:
        has_pfs = "-" in config.esp and not config.esp.endswith("none")
        pfs_str = "pfs" if has_pfs else "nopfs"

        label = (
            f"custom_"
            f"{config.ike.replace('-', '')}_"
            f"{config.esp.replace('-', '')}_"
            f"{pfs_str}_"
            f"{config.mode}_"
            f"{config.ip_version}_"
            f"{config.traffic}"
        )

        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            orchestrator.run_experiment(
                label,
                config.ike,
                config.esp,
                config.mode,
                config.traffic,
                config.duration,
                config.ip_version,
            )
        logs = f.getvalue()

    return {
        "status": "success",
        "message": "Traffic generated successfully!",
        "pcap_file": f"{label}.pcap",
        "logs": logs
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
                    "duration",
                    "packet_count",
                    "total_bytes",
                    "mean_packet_size",
                    "std_packet_size",
                    "min_packet_size",
                    "max_packet_size",
                    "packet_rate",
                    "byte_rate",
                    "forward_packets",
                    "backward_packets",
                    "forward_bytes",
                    "backward_bytes",
                    "direction_ratio"
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
                        "telemetry": {
                            "mean_packet_size": feat["mean_packet_size"],
                            "packet_rate": feat["packet_rate"],
                            "byte_rate": feat["byte_rate"],
                            "packet_count": feat["packet_count"],
                            "duration": feat["duration"]
                        }
                    }
                    for feat, pred, conf
                    in zip(features_list, predictions, probabilities)
                ]
                total_packets = sum(f["packet_count"] for f in features_list)
                total_duration = max(f["duration"] for f in features_list) if features_list else 0
            else:
                total_packets = 0
                total_duration = 0
                response["ai_analysis"] = [
                    {"error": "No valid ESP flows extracted for ML analysis."}
                ]
                
        else:
            response["ai_analysis"] = [
                {"error": "ML Model not trained/found!"}
            ]
            total_packets = 0
            total_duration = 0

        # Include PCAP metadata
        import os
        response["pcap_metadata"] = {
            "file_size_kb": round(os.path.getsize(tmp_path) / 1024, 2),
            "total_packets": total_packets,
            "duration_sec": total_duration
        }

        return response

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    configuration = report["observed_configuration"]
    assert isinstance(configuration, dict)
    return {
        "filename": Path(filename).name,
        "security_assessment": assess_configuration(configuration),
        "ai_analysis": predictions,
        "analysis": report,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("IPSEC_SENTINEL_API_HOST", "127.0.0.1"), port=8000)
