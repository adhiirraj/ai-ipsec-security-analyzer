# IPsec-Sentinel-AI

AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework for SIH 2026 / NTRO (Problem Statement 26160).

The current vertical slice is a streaming, read-only PCAP analyzer. It identifies observable IPsec traffic (IKEv1, IKEv2, ESP, AH, and NAT-T ESP), records only header-level evidence, and emits a versioned JSON report. It never decrypts payloads, guesses unobservable negotiated values, fabricates ML predictions, or emits an arbitrary security score.

## Status

Milestones 1–2 are implemented: Python package scaffolding, classic PCAP/PCAPNG ingestion, link/IP/IPsec detection, a CLI, structured reporting, and tests. IKE Security Association parsing, ESP flow construction, feature extraction, rules, ML, API, dashboard, and testbed automation are deliberately pending.

## Quick start

Use Python 3.10–3.13. The current core has no third-party runtime requirement; install the development extras when package tooling and network access are available.

```powershell
py -3.12 -m pip install -e ".[protocol,data,dev]"
$env:PYTHONPATH = ".\\src"
py -3.12 -m ipsec_sentinel --pcap data/raw_pcaps/capture.pcap --output reports/analysis.json
```

After installation, the equivalent command is:

```text
ipsec-sentinel analyze data/raw_pcaps/capture.pcap --output reports/analysis.json
```

The analyzer accepts classic libpcap and common PCAPNG enhanced-packet captures. Packet data is read one record at a time; reports contain bounded, header-only IPsec observations.

## Output semantics

- `null`, `unknown`, or an empty list means the information was not observable or is not yet calculated.
- IKE versions are identified only from a structurally valid IKE header on UDP/500 or UDP/4500 with the required non-ESP marker.
- NAT-T ESP is identified only for UDP/4500 packets without that marker.
- The Milestone 2 report has no security score, findings, flow statistics, or ML prediction because those components do not exist yet.

See [the implementation plan](docs/implementation-plan.md) for scope, milestones, risks, and next steps.
