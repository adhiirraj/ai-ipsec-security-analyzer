"""Opt-in live integration coverage; never required for normal CI."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

import pytest

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from testbed import orchestrator


@pytest.mark.integration
def test_real_strongswan_tunnel_and_capture() -> None:
    if os.getenv("IPSEC_SENTINEL_RUN_TESTBED") != "1":
        pytest.skip("set IPSEC_SENTINEL_RUN_TESTBED=1 to run privileged Docker integration coverage")
    if not (shutil.which("docker") or shutil.which("docker-compose")):
        pytest.skip("Docker Compose is not installed")
    label = orchestrator.build_label("aes256gcm16-prfsha256-ecp256", "aes256gcm16", "tunnel", "web", "ipv4")
    try:
        capture = orchestrator.run_experiment(
            label, "aes256gcm16-prfsha256-ecp256", "aes256gcm16", "tunnel", "web", 3, "ipv4"
        )
        report = analyze_pcap(Path(capture))
        assert report["summary"].get("ikev2_packets", 0) > 0
        assert report["summary"].get("esp_security_associations", 0) > 0
    finally:
        orchestrator.teardown_testbed()
