# 🛡️ IPsec-Sentinel AI

**AI-Powered IPsec VPN Protocol Analyzer, Testbed, and Security Assessment Framework**  
*(Built for SIH 2026 / NTRO Problem Statement 26160)*

IPsec-Sentinel AI is a fully automated, end-to-end framework that not only analyzes IPsec traffic but actively generates, trains on, and evaluates VPN traffic using a mix of Machine Learning and Cryptographic Rule-Based engines.

## 🚀 Current State of the Project (Hackathon Final Prototype)

The framework has evolved into a complete, modular ecosystem:

1. **VPN Testbed Control Center (Docker + strongSwan)**: A fully automated UI to spin up IPsec tunnels with custom topologies (Tunnel/Transport), cryptography (AES-GCM, AES-CTR, 3DES, DH groups, PFS), and traffic types (VoIP, Web, Bulk, Video, ICMP). It generates synthetic traffic and outputs synchronized PCAPs.
2. **Machine Learning Pipeline (Random Forest)**: An AI engine that extracts behavioral metrics (packet size, inter-arrival time, byte counts) from encrypted ESP flows. It successfully predicts the *type* of traffic hidden inside the tunnel with high confidence without ever decrypting the payload.
3. **Cryptographic Rule Engine**: Automatically parses IKE_SA_INIT and IKE_AUTH negotiations using `tshark` to mathematically verify the strength of Phase 1 and Phase 2 algorithms against NIST/BSI standards. It severely penalizes weak ciphers (e.g. 3DES), lack of HMACs (e.g. AES-CTR without authentication), and disabled PFS (Perfect Forward Secrecy).
4. **Interactive Dashboard**: A sleek, Tailwind-styled web dashboard running on FastAPI that allows judges to visually interact with the Testbed, upload PCAPs, and view the AI's Security Score and Traffic Predictions in real-time.

## 📦 System Requirements

- **OS**: Linux (Arch, Debian/Ubuntu, Fedora)
- **Core Dependencies**: `docker`, `docker-compose`, `tshark` (Wireshark-CLI), `tcpdump`
- **Python (>=3.10)**: `fastapi`, `uvicorn`, `scapy`, `pandas`, `scikit-learn`, `joblib`

## 🛠️ Quick Installation

We have provided an automated installation script that detects your Linux distribution and installs all system and Python dependencies natively (bypassing PEP-668 restrictions safely).

```bash
# 1. Make the script executable
chmod +x install.sh

# 2. Run the installation script
bash install.sh
```

## 🖥️ Running the Dashboard

Once dependencies are installed, you can launch the AI Dashboard backend:

```bash
python3 dashboard/backend/api.py
```

Open your web browser and navigate to: **http://localhost:8000**

- **Analyzer Tab**: Upload PCAPs (like the ones generated in `testbed/pcaps/` or `testbed/external_pcaps/`) to see the Rule Engine and AI Classifier in action.
- **Testbed Tab**: Dynamically configure the VPN topology and launch traffic generation to build your own datasets!

## 🧠 Retraining the AI Model

If you use the Testbed to generate new traffic configurations, you can retrain the AI on the fly:

```bash
# 1. Extract behavioral ESP features from all generated PCAPs
python3 testbed/extract_features.py

# 2. Train the Random Forest Classifier on the new dataset
python3 testbed/train_model.py
```

The Dashboard will automatically use the newly trained model (`data/models/esp_traffic_classifier.pkl`) on the next analysis!

---

