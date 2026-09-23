"""Small, dependency-free settings for the initial analyzer slice."""

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_MAX_PACKET_OBSERVATIONS = 10_000
DEFAULT_MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024


def _positive_int(value: str, variable_name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{variable_name} must be a positive integer") from error
    if parsed <= 0:
        raise ValueError(f"{variable_name} must be a positive integer")
    return parsed


@dataclass(frozen=True, slots=True)
class AnalysisSettings:
    """Limits that keep an analysis bounded without discarding packet counts."""

    max_packet_observations: int = DEFAULT_MAX_PACKET_OBSERVATIONS
    max_captured_packet_bytes: int = DEFAULT_MAX_CAPTURED_PACKET_BYTES

    def __post_init__(self) -> None:
        if self.max_packet_observations <= 0:
            raise ValueError("max_packet_observations must be a positive integer")
        if self.max_captured_packet_bytes <= 0:
            raise ValueError("max_captured_packet_bytes must be a positive integer")

    @classmethod
    def from_environment(cls) -> "AnalysisSettings":
        """Read only explicit analyzer limits; no credentials are used in this slice."""

        observation_limit = os.getenv("IPSEC_SENTINEL_MAX_PACKET_OBSERVATIONS")
        if observation_limit is None:
            return cls()
        return cls(max_packet_observations=_positive_int(
            observation_limit, "IPSEC_SENTINEL_MAX_PACKET_OBSERVATIONS"
        ))
