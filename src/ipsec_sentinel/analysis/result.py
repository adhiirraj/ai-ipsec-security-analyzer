"""Versioned report schema for the initial, non-ML analysis vertical slice."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ipsec_sentinel.parser.models import PacketObservation


REPORT_SCHEMA_VERSION = "0.1.0"
FEATURE_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class PcapReport:
    filename: str
    capture_format: str | None
    link_types: tuple[int, ...]
    timestamp_resolution: str | None
    packet_count: int
    ipsec_packet_count: int
    observed_packet_count: int
    observations_truncated: bool


@dataclass(frozen=True, slots=True)
class IpsecDetectionReport:
    detected: bool
    protocols: tuple[str, ...]
    ike_version: str | None
    ike_versions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """JSON-safe report with an explicit boundary between facts and pending work."""

    analysis_id: str
    generated_at: str
    schema_version: str
    pcap: PcapReport
    ipsec: IpsecDetectionReport
    packet_observations: tuple[PacketObservation, ...]
    security_associations: tuple[object, ...]
    esp_flows: tuple[object, ...]
    features: dict[str, Any]
    security_assessment: dict[str, Any]
    ml: dict[str, Any]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Represent all tuples and dataclasses in API/JSON-friendly form."""

        return {
            "analysis_id": self.analysis_id,
            "generated_at": self.generated_at,
            "schema_version": self.schema_version,
            "pcap": {
                **asdict(self.pcap),
                "link_types": list(self.pcap.link_types),
            },
            "ipsec": {
                **asdict(self.ipsec),
                "protocols": list(self.ipsec.protocols),
                "ike_versions": list(self.ipsec.ike_versions),
            },
            "packet_observations": [item.to_dict() for item in self.packet_observations],
            "security_associations": list(self.security_associations),
            "esp_flows": list(self.esp_flows),
            "features": self.features,
            "security_assessment": self.security_assessment,
            "ml": self.ml,
            "limitations": list(self.limitations),
        }
