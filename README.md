# AI IPsec Security Analyzer

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security Standard: NIST SP 800-77](https://img.shields.io/badge/Compliance-NIST%20SP%20800--77-orange.svg)](https://csrc.nist.gov/pubs/sp/800/77/r1/final)

#### An intelligent, multi-layer security auditing and anomaly detection engine for IPsec VPN configurations, cryptographic negotiation parameters, and encrypted tunnel telemetry. IPsec-Sentinel AI is a deterministic IPsec/ESP traffic analyser and rule-based security assessment engine, backed by a ML classifier. It also includes an educational custom ESP-style file encryption simulator which is clearly not real IKEv2 or ESP
---

## Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Project Architecture](#-project-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
  - [1. CLI Configuration Audit](#1-cli-configuration-audit)
  - [2. Telemetry / Anomaly Detection](#2-telemetry--anomaly-detection)
  - [3. Python API Integration](#3-python-api-integration)
- [Supported Standards & Checks](#-supported-standards--checks)
- [Testing](#-testing)
- [Roadmap](#-roadmap)
- [License](#-license)

---

## Overview

IPsec configurations often suffer from configuration drift, legacy cipher retention, weak key-exchange policies, or aggressive negotiation modes vulnerable to offline cryptanalysis. 

**AI IPsec Security Analyzer** bridges the gap between static rule-based security auditing and dynamic traffic behavior monitoring:
1. **Static Analysis Layer:** Validates configuration semantics against industry-hardened compliance baselines.
2. **Behavioral AI Layer (`ipsec_sentinel`):** Employs unsupervised anomaly detection models to detect irregular ESP (Encapsulating Security Payload) sequence jumps, byte volume drift, and side-channel tunnel leakage.

---

## Key Features

- **Multi-Vendor Configuration Parsing:** Native support for parsing configuration files from StrongSwan (`ipsec.conf`, `swanctl.conf`), Libreswan, and Cisco IOS crypto maps.
- **Cryptographic Suite Auditing:**
  - Flags obsolete symmetric ciphers (e.g., DES, 3DES, Blowfish, RC4).
  - Flags insecure hashing algorithms (e.g., MD5, SHA-1).
  - Verifies Diffie-Hellman (DH) group strength (flags groups < 14 / 2048-bit).
  - Enforces authenticated encryption with associated data (AEAD, e.g., AES-GCM).
- **IKE Protocol Verification:**
  - Audits IKEv1 vs. IKEv2 adoption.
  - Flags risky IKEv1 Aggressive Mode when paired with Pre-Shared Keys (PSK).
  - Checks Perfect Forward Secrecy (PFS) settings and SA lifetime parameters.
- **ML-Based Telemetry Anomaly Detection:**
  - Unsupervised models (Isolation Forest / Autoencoder) score packet timing distributions, jitter, sequence increments, and burst ratios.
- **Standardized Risk Scoring & Export:**
  - Outputs reports in JSON, Markdown, or tabular CLI format with CVSS-aligned severity indicators (Critical, High, Medium, Low).

---

## Project Architecture

```text
ai-ipsec-security-analyzer/
├── config/                  # Default compliance baselines and security policies
├── data/                    # Sample configs, packet captures, and testing datasets
├── src/
│   └── ipsec_sentinel/      # Core analysis engine
│       ├── __init__.py
│       ├── analyzer.py      # Main pipeline orchestration
│       ├── parsers/         # File parsers (Strongswan, Cisco, etc.)
│       ├── models/          # Anomaly detection & statistical scoring models
│       ├── rules/           # Static heuristic and cryptographic rule sets
│       └── reporter.py      # Report formatters (CLI, JSON, Markdown)
├── tests/                   # Pytest test suite
├── .gitignore
├── requirements.txt         # Core dependencies
├── setup.py                 # Package setup
└── README.md
