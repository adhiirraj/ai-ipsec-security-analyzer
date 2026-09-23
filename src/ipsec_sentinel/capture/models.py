"""Models at the capture-file boundary.

Raw packet bytes are deliberately transient: consumers should parse a record and
retain only the header-level evidence they need.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


CaptureFormat = Literal["pcap", "pcapng"]


@dataclass(frozen=True, slots=True)
class CaptureFileInfo:
    """Metadata discovered from a capture container, before packet parsing."""

    capture_format: CaptureFormat
    link_types: tuple[int, ...]
    timestamp_resolution: str


@dataclass(frozen=True, slots=True)
class RawPacket:
    """One packet record yielded by a capture reader.

    ``captured_length`` may be smaller than ``original_length`` when a capture
    has been snaplen-truncated. Parsers must not claim unavailable fields in
    that situation.
    """

    frame_number: int
    timestamp: float | None
    captured_length: int
    original_length: int
    link_type: int
    data: bytes
