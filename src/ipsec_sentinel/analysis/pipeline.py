"""The Milestone 2 PCAP -> observable protocol facts -> JSON pipeline."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ipsec_sentinel.analysis.result import (
    FEATURE_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    AnalysisReport,
    IpsecDetectionReport,
    PcapReport,
)
from ipsec_sentinel.capture.reader import PcapReader
from ipsec_sentinel.config.settings import AnalysisSettings
from ipsec_sentinel.parser.ipsec import parse_packet
from ipsec_sentinel.parser.models import PacketObservation


_IPSEC_PROTOCOLS = frozenset({"IKEv1", "IKEv2", "ESP", "AH"})


def analyze_pcap(path: str | Path, settings: AnalysisSettings | None = None) -> AnalysisReport:
    """Analyze one capture without retaining raw payloads or all packets in RAM.

    ``packet_observations`` retains the first bounded set of IPsec-related
    header observations for provenance. Counts always include the complete
    capture, even after that report limit has been reached.
    """

    effective_settings = settings or AnalysisSettings.from_environment()
    capture_path = Path(path)
    reader = PcapReader(
        capture_path,
        max_captured_packet_bytes=effective_settings.max_captured_packet_bytes,
    )
    observations: list[PacketObservation] = []
    protocols: Counter[str] = Counter()
    packet_count = 0
    ipsec_packet_count = 0
    observations_truncated = False

    for packet in reader:
        packet_count += 1
        observation = parse_packet(packet)
        packet_protocols = _IPSEC_PROTOCOLS.intersection(observation.protocol_stack)
        if not packet_protocols:
            continue
        ipsec_packet_count += 1
        protocols.update(packet_protocols)
        if len(observations) < effective_settings.max_packet_observations:
            observations.append(observation)
        else:
            observations_truncated = True

    info = reader.info
    version_names = tuple(sorted(protocol for protocol in protocols if protocol.startswith("IKEv")))
    singular_ike_version = version_names[0] if len(version_names) == 1 else None
    return AnalysisReport(
        analysis_id=str(uuid4()),
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        schema_version=REPORT_SCHEMA_VERSION,
        pcap=PcapReport(
            filename=capture_path.name,
            capture_format=info.capture_format if info else None,
            link_types=info.link_types if info else (),
            timestamp_resolution=info.timestamp_resolution if info else None,
            packet_count=packet_count,
            ipsec_packet_count=ipsec_packet_count,
            observed_packet_count=len(observations),
            observations_truncated=observations_truncated,
        ),
        ipsec=IpsecDetectionReport(
            detected=ipsec_packet_count > 0,
            protocols=tuple(sorted(protocols)),
            ike_version=singular_ike_version,
            ike_versions=version_names,
        ),
        packet_observations=tuple(observations),
        # These schema locations are intentionally present but empty so API
        # consumers never mistake unimplemented analysis for a clean result.
        security_associations=(),
        esp_flows=(),
        features={
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "status": "not_computed",
            "reason": "ESP flow extraction is scheduled for Milestone 4.",
        },
        security_assessment={
            "status": "not_assessed",
            "score": None,
            "findings": [],
            "reason": "The transparent rule engine is scheduled for Milestone 5.",
        },
        ml={
            "status": "not_configured",
            "predictions": [],
            "reason": "No trained and evaluated model is available.",
        },
        limitations=(
            "Only outer headers and the IKE common header are parsed in this milestone.",
            "ESP payloads are not decrypted and no inner traffic type is inferred.",
            "Security Association, transform, PFS, lifetime, replay, mode, and cryptographic "
            "configuration values are unknown until their observable protocol evidence is parsed.",
        ),
    )
