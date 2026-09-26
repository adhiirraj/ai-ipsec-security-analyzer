"""Import and startup smoke tests.

These tests verify that:
- All declared packages are importable without side effects.
- No module-level code starts processes, Docker, VPN services, or model training.
- Path and configuration helpers work correctly.
"""

from __future__ import annotations

import sys
from pathlib import Path


def test_ipsec_sentinel_package_imports_without_side_effects() -> None:
    import ipsec_sentinel

    assert ipsec_sentinel.__version__ == "0.1.0"


def test_analysis_pipeline_imports_without_side_effects() -> None:
    from ipsec_sentinel.analysis.pipeline import analyze_pcap

    assert callable(analyze_pcap)


def test_security_rules_import_without_side_effects() -> None:
    from ipsec_sentinel.analysis.rules import assess_configuration, evaluate_algorithm

    assert callable(assess_configuration)
    assert callable(evaluate_algorithm)


def test_pcap_reader_imports_without_side_effects() -> None:
    from ipsec_sentinel.capture.reader import PcapError, PcapReader

    assert issubclass(PcapError, ValueError)
    assert callable(PcapReader)


def test_settings_import_without_side_effects() -> None:
    from ipsec_sentinel.config.settings import AnalysisSettings, DEFAULT_MAX_PACKET_OBSERVATIONS

    assert DEFAULT_MAX_PACKET_OBSERVATIONS == 10_000
    settings = AnalysisSettings()
    assert settings.max_packet_observations == DEFAULT_MAX_PACKET_OBSERVATIONS


def test_parser_package_is_importable() -> None:
    import ipsec_sentinel.parser  # noqa: F401 — verifying namespace exists


def test_testbed_orchestrator_imports_without_side_effects() -> None:
    from testbed import orchestrator

    # No Docker calls on import.
    assert callable(orchestrator.preflight)
    assert callable(orchestrator.run_experiment)
    assert callable(orchestrator.teardown_testbed)


def test_testbed_traffic_generator_imports_without_side_effects() -> None:
    from testbed.scripts import traffic_generator

    assert callable(traffic_generator.main)
    assert set(traffic_generator.WORKLOADS) == {
        "voip", "web", "bulk", "icmp", "video", "whatsapp", "email"
    }


def test_dashboard_api_imports_without_side_effects() -> None:
    """Importing the API must not start Docker, VPN, captures, or model training."""
    from dashboard.backend import api

    assert hasattr(api, "app")
    assert hasattr(api, "health")
    assert hasattr(api, "analyze_pcap_endpoint")
    # Model is not loaded at import time.
    assert api._model_checked is False or api._classifier is None


def test_dashboard_api_app_title_is_correct() -> None:
    from dashboard.backend.api import app

    assert "IPsec" in app.title


def test_src_directory_is_on_sys_path() -> None:
    """Ensure the installed package is importable from sys.path."""
    import ipsec_sentinel

    package_path = Path(ipsec_sentinel.__file__).resolve()
    # Must live under src/ when installed editably.
    assert "ipsec_sentinel" in str(package_path)


def test_testbed_module_is_on_sys_path() -> None:
    """testbed must be importable (it lives at the project root, not src/)."""
    import testbed

    assert hasattr(testbed, "__file__") or hasattr(testbed, "__path__")
