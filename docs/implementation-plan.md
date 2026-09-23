# Implementation plan

## Current repository state

Audited on 2026-09-22:

- The checkout contained only `README.md` and `LICENSE`; no Python source, dependency manifest, tests, PCAP fixtures, dataset, dashboard, API, or testbed configuration was present.
- The configured Git remote is `https://github.com/Protostar-2007/ai-ipsec-security-analyzer.git`. Git is not installed in this execution environment, so normal `git status` and history commands could not be run.
- Python 3.12.2 and 3.14.6 are available. No third-party packages (including Pydantic, pytest, Scapy, or dpkt) are installed. The initial reader consequently uses only the Python standard library and its tests use `unittest`.

## Target architecture

```text
PCAP / PCAPNG / live interface
             |
      capture.reader (streaming records)
             |
      parser.ipsec (observable header facts)
          /                      \\
IKE/SA extraction            ESP flow builder
        |                          |
security rule engine       feature extraction -> ML inference
          \\                      /
                  analysis pipeline
                         |
                JSON / PDF / API / dashboard
```

Deterministic parsing and statistical inference remain separate. The parser returns only directly observable header information. It must represent unavailable information as `null`/`unknown`; neither the rule engine nor the ML layer may turn absence of evidence into a finding or fact.

## Milestones

1. **Repository and project foundation** — package layout, configuration, documentation, test harness. **Complete.**
2. **PCAP ingestion** — streaming classic-PCAP/PCAPNG reader, link/IP parsing, IPsec detection, JSON CLI. **Complete.**
3. **IKE/IPsec parsing** — IKEv1/v2 payload chain; SA, proposal, transform, KE, Notify, and CHILD_SA extraction.
4. **ESP flows and features** — SPI-aware session builder, sequence provenance, versioned statistical features.
5. **Security rules** — declarative rule definitions, observability-aware findings, explainable configurable score.
6. **End-to-end CLI** — flows, features, rules, and technical JSON report.
7. **Dataset pipeline** — validated ground-truth metadata and capture/session-level split enforcement.
8. **Baseline ML** — reproducible Random Forest/XGBoost baseline and calibrated confidence handling.
9. **Evaluation and model versioning** — held-out capture-level metrics and model manifests.
10. **FastAPI**, 11. **dashboard**, 12. **testbed automation**, 13. **live capture**, 14. **containerization/demo**.

## Current milestone

Milestones 1–2 are complete. The working command is:

```text
python -m ipsec_sentinel --pcap capture.pcap --output reports/analysis.json
```

The report intentionally includes empty `security_associations`, `esp_flows`, findings, and ML predictions until their corresponding modules are implemented.

## Files created or modified in this increment

- Project metadata: `pyproject.toml`, `requirements.txt`, `.gitignore`, `.env.example`.
- Core package: `src/ipsec_sentinel/{capture,parser,analysis,config}` and CLI entry points.
- Tests: synthetic binary classic-PCAP and PCAPNG records created in temporary test directories; no JSON stand-ins for PCAP are used.
- Documentation: this plan and an expanded `README.md`.
- Data placeholders: `data/raw_pcaps`, `data/processed`, and `data/models`.

## Dependencies

The implemented core uses no third-party module so it can run in the current constrained environment. The package declares optional extras:

- `protocol`: Scapy for deeper protocol support/cross-validation in later parser milestones.
- `data`: Pydantic and pandas for validated dataset metadata and tabular feature work.
- `dev`: pytest, Ruff, and mypy.

Python 3.12 is the locally tested interpreter. Third-party dependencies are unavailable locally because no package index is configured; this is documented rather than hidden behind mocks.

## Testing strategy

- Unit tests manufacture valid binary PCAP/PCAPNG records in temporary directories and verify streaming ingestion, IKEv2 header detection, ESP/NAT-T ESP metadata, malformed-capture rejection, and CLI JSON output.
- Later parser tests will use reviewed, legally shareable packet fixtures and must assert unknown values explicitly.
- Dataset and ML tests will split by `capture_id`/`session_id`, not packets or flows, and record seed/configuration in every artifact.
- Integration tests must stay offline and never require a VPN, root networking privileges, tshark, or an external service.

## Risks and unknowns

- A PCAP cannot reveal encrypted ESP inner traffic, negotiated transforms carried only in missing/encrypted exchanges, PFS state, lifetime, or replay protection unless the required observable exchanges/fields exist.
- PCAPNG supports multiple interfaces and timestamp resolutions; the reader handles common interface-description and enhanced-packet blocks, but uncommon block types are skipped safely and should receive fixtures before expanding support.
- Deeper IKE payload parsing should be implemented against RFC 7296 (IKEv2) and RFC 2409 (IKEv1), with tests before security conclusions are made.
- TShark/Scapy, a reproducible StrongSwan testbed, and labelled independent PCAP sessions are not present. They are prerequisites for the parser-validation, dataset, and ML milestones.
