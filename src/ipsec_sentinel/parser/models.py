"""Typed, payload-free observations produced by the protocol parser."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class IKEHeaderObservation:
    """Fields visible in an unencrypted IKE common header.

    This does *not* assert that a proposal or transform was negotiated. Those
    claims require parsing the IKE payload chain in a later milestone.
    """

    version: str
    initiator_spi: str
    responder_spi: str
    exchange_type: int
    flags: int
    message_id: int
    declared_length: int


@dataclass(frozen=True, slots=True)
class ESPHeaderObservation:
    """The clear ESP header visible before encrypted ESP payload bytes."""

    spi: str
    sequence_number: int
    encapsulation: str = "ip"


@dataclass(frozen=True, slots=True)
class AHHeaderObservation:
    """The clear fields in an Authentication Header."""

    spi: str
    sequence_number: int
    next_header: int


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """Header-level evidence for one captured packet.

    The packet payload is intentionally excluded from reports to reduce data
    exposure and memory use. A packet may be truncated; in that case fields
    beyond the available bytes remain absent instead of being guessed.
    """

    frame_number: int
    timestamp: float | None
    captured_length: int
    original_length: int
    link_type: int
    protocol_stack: tuple[str, ...]
    ip_version: int | None
    source: str | None
    destination: str | None
    transport_protocol: int | None
    source_port: int | None = None
    destination_port: int | None = None
    ike: IKEHeaderObservation | None = None
    esp: ESPHeaderObservation | None = None
    ah: AHHeaderObservation | None = None
    parse_note: str | None = None

    @property
    def is_ipsec(self) -> bool:
        # The outer IP protocol number is evidence of ESP/AH even when the
        # capture is too short to expose the SPI and sequence number.
        return bool({"IKEv1", "IKEv2", "ESP", "AH"}.intersection(self.protocol_stack))

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible data without raw packet content."""

        value = asdict(self)
        value["protocol_stack"] = list(self.protocol_stack)
        return value