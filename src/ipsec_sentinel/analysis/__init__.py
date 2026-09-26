"""Composition of capture ingestion and deterministic protocol observations."""

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from ipsec_sentinel.analysis.rules import assess_configuration, evaluate_algorithm

__all__ = ["analyze_pcap", "assess_configuration", "evaluate_algorithm"]
"""Rule-based security assessment module."""
