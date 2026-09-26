# IPsec-Sentinel AI

**AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**  
*(SIH 2026 / NTRO Problem Statement 26160)*

---

## What This Is

IPsec-Sentinel AI is a deterministic IPsec/ESP traffic analyser and rule-based
security assessment engine, backed by an optional ML traffic classifier.  It
also includes an educational custom ESP-style file-encryption simulator that is
clearly **not** real IKEv2 or ESP.

### Components

| Component | Description |
|---|---|
| `src/ipsec_sentinel/` | Core library: PCAP reader, IKEv2/ESP header parser, security assessment rules |
| `dashboard/backend/api.py` | FastAPI JSON API (analysis, security assessment, testbed control) |
| `dashboard/frontend/index.html` | Single-page HTML dashboard |
| `testbed/` | strongSwan Docker testbed orchestrator + traffic generators |
| `aes_ctr/` | **Educational** custom ESP-style file simulator (AES-256-CTR, X25519, HMAC-SHA256) — not real IKEv2 |

---

## System Requirements

- **Python ≥ 3.10, < 3.14**
- **Linux or WSL** (required for the live testbed; the analyzer and tests run on Windows)
- **Docker Engine with Compose V2 plugin** (testbed only)
- System packages for the testbed: `tcpdump`, `iperf3`, `curl`, `socat` (installed inside containers)

---

## Quick Start

### 1. Install Python dependencies

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate         # Linux / WSL
# .\.venv\Scripts\Activate.ps1   # Windows PowerShell

# Install the package in editable mode with all extras
pip install -e ".[all,dev]"
```

### 2. Run unit tests (no Docker required)

```bash
python -m pytest -m "not integration" -v
```

Expected: **15 tests pass**.

### 3. Start the dashboard API

```bash
uvicorn dashboard.backend.api:app --host 127.0.0.1 --port 8000
```

Open <http://localhost:8000/api/health> to verify the API is running.  
Open <http://localhost:8000/ui/index.html> for the web dashboard.

### 4. Analyse a PCAP from the command line

```bash
ipsec-sentinel path/to/capture.pcap
# Or: python -m ipsec_sentinel path/to/capture.pcap
```

---

## Live Testbed (Ubuntu/WSL with Docker)

> **Not available on Windows without WSL.**  Docker requires `NET_ADMIN` capability.

### Start the testbed

```bash
# Render swanctl configs and start containers
python -m testbed.orchestrator up

# Check readiness
python -m testbed.orchestrator preflight
```

### Run an experiment

```python
from testbed.orchestrator import run_experiment, build_label

label = build_label("aes256gcm16-prfsha256-ecp256", "aes256gcm16", "tunnel", "web", "ipv4")
pcap = run_experiment(
    label,
    ike_prop="aes256gcm16-prfsha256-ecp256",
    esp_prop="aes256gcm16",
    mode="tunnel",
    traffic="web",
    duration=15,
    ip_version="ipv4",
)
print("Captured:", pcap)
```

### Analyse the capture

```bash
ipsec-sentinel testbed/runtime/pcaps/<label>.pcap
```

### Tear down

```bash
python -m testbed.orchestrator down
```

---

## Retrain the Optional ML Classifier

> Requires real testbed captures in `testbed/runtime/pcaps/`.

```bash
# Extract ESP flow features
python testbed/extract_features.py

# Train the Random Forest classifier
python testbed/train_model.py
```

The dashboard automatically loads `data/models/esp_traffic_classifier.pkl`
on the next analysis request.

---

## Educational Simulator (aes_ctr/)

The `aes_ctr/` directory contains an educational custom file-encryption
simulator that wraps files in **custom ESP-style packets** with X25519 key
agreement and AES-256-CTR encryption.

> ⚠️ **This is NOT real IKEv2 or ESP.** The packets use a custom `ISIM`
> marker instead of IKEv2 headers and are detected and excluded by the
> analyzer accordingly.

```bash
# Encrypt a file tree into one PCAP
python aes_ctr/ipsec_multi.py encrypt ./my_files --out ./encrypted_output

# Decrypt/recover files from the PCAP
python aes_ctr/ipsec_multi.py recover encrypted_output/traffic.pcap \
    --receiver-key encrypted_output/receiver_private.pem \
    --out ./recovered_output \
    --mode decrypt
```

---

## Integration Tests

```bash
# Run live testbed integration test (requires Docker + NET_ADMIN)
IPSEC_SENTINEL_RUN_TESTBED=1 python -m pytest -m integration -v
```

---

## Configuration

All runtime paths and limits are controlled by environment variables:

| Variable | Default | Description |
|---|---|---|
| `IPSEC_SENTINEL_MAX_UPLOAD_BYTES` | `33554432` (32 MB) | Maximum PCAP upload size |
| `IPSEC_SENTINEL_MAX_PACKET_OBSERVATIONS` | `10000` | Max IKE messages retained per analysis |
| `IPSEC_SENTINEL_MAX_CAPTURED_PACKET_BYTES` | `16777216` (16 MB) | Max single packet length |
| `IPSEC_SENTINEL_CORS_ORIGINS` | `http://localhost:8000` | Comma-separated allowed CORS origins |
| `IPSEC_SENTINEL_API_HOST` | `127.0.0.1` | API bind address |
| `IPSEC_SENTINEL_TESTBED_RUNTIME_DIR` | `testbed/runtime` | Testbed runtime directory |
| `IPSEC_SENTINEL_PCAP_DIR` | `<RUNTIME_DIR>/pcaps` | Capture output directory |
| `IPSEC_SENTINEL_RUN_TESTBED` | (unset) | Set to `1` to enable Docker integration tests |

---

## Docs

- [`docs/priority0-audit.md`](docs/priority0-audit.md) — Confirmed defects and fixes
- [`docs/priority0-validation.md`](docs/priority0-validation.md) — Validation commands and results
- [`docs/implementation-plan.md`](docs/implementation-plan.md) — Original design notes
