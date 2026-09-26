from __future__ import annotations

import numpy as np
from fastapi.testclient import TestClient

from dashboard.backend import api
from tests.helpers import ethernet_ipv4, native_esp, pcap_bytes


def test_health_and_analysis_endpoint_do_not_start_testbed() -> None:
    with TestClient(api.app) as client:
        health = client.get("/api/health")
        analysis = client.post("/api/analyze?filename=example.pcap", content=pcap_bytes([]))

    assert health.status_code == 200
    assert health.json()["testbed"]["starts_on_health_check"] is False
    assert analysis.status_code == 200
    assert analysis.json()["security_assessment"]["config"]["enc_alg"] == "unknown"


def test_analysis_endpoint_rejects_corrupt_capture() -> None:
    with TestClient(api.app) as client:
        response = client.post("/api/analyze", content=b"not a pcap")

    assert response.status_code == 422
    assert "unsupported capture format" in response.json()["detail"]


class _DeterministicClassifier:
    def predict(self, frame):
        return ["fixture" for _ in range(len(frame))]

    def predict_proba(self, frame):
        return np.array([[0.1, 0.9] for _ in range(len(frame))])


def test_optional_ml_inference_uses_fixture_without_retraining(monkeypatch) -> None:
    monkeypatch.setattr(api, "_classifier", _DeterministicClassifier())
    monkeypatch.setattr(api, "_model_checked", True)
    frames = [ethernet_ipv4(50, native_esp(0xAABBCCDD, sequence)) for sequence in range(1, 11)]

    with TestClient(api.app) as client:
        response = client.post("/api/analyze", content=pcap_bytes(frames))

    assert response.status_code == 200
    assert response.json()["ai_analysis"] == [
        {"spi": "0xaabbccdd", "predicted_traffic": "fixture", "confidence": 90.0}
    ]
