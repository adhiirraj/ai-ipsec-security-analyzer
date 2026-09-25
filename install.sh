#!/bin/bash

echo "=============================================="
echo "🛡️  IPsec-Sentinel AI Setup Script 🛡️"
echo "=============================================="
echo "This script will install all system dependencies and Python modules required for the Dashboard, ML Pipeline, and Testbed."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Install System Dependencies
echo -e "\n[1/3] Checking system dependencies (Docker, tshark, tcpdump)..."
if command_exists pacman; then
    echo "Arch Linux detected. Installing system packages via pacman..."
    sudo pacman -Sy --needed docker docker-compose wireshark-cli tcpdump python python-pip
elif command_exists apt-get; then
    echo "Debian/Ubuntu detected. Installing system packages via apt..."
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose tshark tcpdump python3 python3-pip
elif command_exists dnf; then
    echo "Fedora/RHEL detected. Installing system packages via dnf..."
    sudo dnf install -y docker docker-compose wireshark tcpdump python3 python3-pip
else
    echo "⚠️  Unsupported package manager. Please manually install: docker, docker-compose, tshark, tcpdump."
fi

# Ensure Docker is running
echo "Starting Docker service..."
sudo systemctl enable --now docker

# 2. Install Python Dependencies
echo -e "\n[2/3] Installing Python modules (FastAPI, Scikit-learn, Scapy, Pandas)..."
# We use --break-system-packages to bypass PEP-668 on modern Linux distributions (like Arch)
pip install fastapi uvicorn pandas scikit-learn joblib scapy --break-system-packages

# 3. Final Checks
echo -e "\n[3/3] Verifying installation..."
echo -n "Python: "; python3 --version
echo -n "Tshark: "; tshark -v | head -n 1
echo -n "Docker: "; docker --version

echo -e "\n✅ Installation Complete!"
echo "To start the dashboard, run:"
echo "    python3 dashboard/backend/api.py"
echo "Then open http://localhost:8000 in your web browser."
