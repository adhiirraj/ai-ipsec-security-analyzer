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
        "model_available": MODEL_PATH.is_file(),
        "testbed": orchestrator.preflight(),
        "note": "The health endpoint does not start Docker or strongSwan.",
    }


@app.post("/api/run_testbed")
def run_testbed_endpoint(config: TestbedConfigRequest) -> dict[str, str]:
    """Run a requested, real strongSwan experiment or return an actionable 503."""

    with TESTBED_LOCK:
        try:
            pcap_path = orchestrator.run_experiment(
                label=orchestrator.build_label(
                    config.ike, config.esp, config.mode, config.traffic, config.ip_version
                ),
                ike_prop=config.ike,
                esp_prop=config.esp,
                mode=config.mode,
                traffic=config.traffic,
                duration=config.duration,
                ip_version=config.ip_version,
            )
        except orchestrator.TestbedError as error:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)) from error
    return {
        "status": "success",
        "message": "Testbed capture completed. Validate the returned PCAP before using it as a dataset.",
        "pcap_file": pcap_path.name,
    }


def _predict_traffic(pcap_path: Path, report: dict[str, object]) -> list[dict[str, object]]:
    if report["capture_kind"] != "pcap":
        return [{"error": "ML inference is disabled for educational ESP-style simulation captures."}]
    classifier = _load_classifier()
    if classifier is None:
        return [{"error": "ML model not trained or unavailable; analysis remains header-only."}]
    try:
        import pandas as pd
        from testbed.extract_features import extract_features_from_pcap

        features = extract_features_from_pcap(pcap_path, label="unknown")
        if not features:
            return []
        columns = [
            "packet_count",
            "total_bytes",
            "mean_packet_size",
            "std_packet_size",
            "mean_iat",
            "std_iat",
        ]
        frame = pd.DataFrame(features)[columns]
        predictions = classifier.predict(frame)
        probabilities = classifier.predict_proba(frame).max(axis=1) * 100.0
        return [
            {
                "spi": item["spi"],
                "predicted_traffic": str(prediction),
                "confidence": round(float(score), 2),
            }
            for item, prediction, score in zip(features, predictions, probabilities, strict=True)
        ]
    except Exception:  # noqa: BLE001 - optional model errors must remain visible to callers.
        LOGGER.exception("Optional ML inference failed for %s", pcap_path)
        return [{"error": "ML inference failed; inspect server logs and model compatibility."}]


@app.post("/api/analyze")
async def analyze_pcap_endpoint(request: Request, filename: str = "upload.pcap") -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Content-Length must be an integer.",
            ) from error
        if declared_size > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="PCAP upload is too large.")
    content = await request.body()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="PCAP upload is too large.")
    if not content:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PCAP upload is empty.")

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(delete=False, suffix=".pcap") as temporary_file:
            temporary_file.write(content)
            temporary_path = Path(temporary_file.name)
        report = analyze_pcap(temporary_path)
        predictions = _predict_traffic(temporary_path, report)
    except PcapError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error
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
