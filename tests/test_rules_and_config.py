from __future__ import annotations

from ipsec_sentinel.analysis.rules import assess_configuration
from ipsec_sentinel.config.settings import AnalysisSettings


def test_unknown_encrypted_fields_are_reported_as_unknown_not_weak() -> None:
    assessment = assess_configuration(
        {
            "enc_alg": "unknown",
            "hash_alg": "unknown",
            "dh_group": "unknown",
            "pfs_enabled": None,
            "esp_enc": "unknown",
            "esp_integrity": "unknown",
        }
    )

    assert assessment["score"] == 100
    assert assessment["config"]["pfs_enabled"] is None
    assert all(finding["severity"] != "HIGH" for finding in assessment["findings"])


def test_explicit_weak_configuration_has_traceable_findings() -> None:
    assessment = assess_configuration(
        {
            "enc_alg": "3des",
            "hash_alg": "sha1",
            "dh_group": "modp1024",
            "pfs_enabled": False,
            "esp_enc": "aes128-ctr",
            "esp_integrity": "none",
        }
    )

    assert assessment["risk_level"] == "CRITICAL"
    assert any(finding["evidence"]["category"] == "ESP integrity" for finding in assessment["findings"])


def test_analysis_settings_reads_both_bounded_limits(monkeypatch) -> None:
    monkeypatch.setenv("IPSEC_SENTINEL_MAX_PACKET_OBSERVATIONS", "12")
    monkeypatch.setenv("IPSEC_SENTINEL_MAX_CAPTURED_PACKET_BYTES", "2048")

    settings = AnalysisSettings.from_environment()

    assert settings.max_packet_observations == 12
    assert settings.max_captured_packet_bytes == 2048
