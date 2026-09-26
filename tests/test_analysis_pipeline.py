from __future__ import annotations

from pathlib import Path

import pytest

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from ipsec_sentinel.capture.reader import PcapError, PcapReader

from tests.helpers import ethernet_ipv4, ike_sa_init_response, native_esp, pcap_bytes, udp


def test_ikev2_response_is_structurally_identified_and_selected_proposal_is_observed(tmp_path: Path) -> None:
    capture = tmp_path / "ike.pcap"
    frame = ethernet_ipv4(17, udp(500, 500, ike_sa_init_response()))
    capture.write_bytes(pcap_bytes([frame]))

    report = analyze_pcap(capture)

    assert report["summary"]["ikev2_packets"] == 1
    assert report["observed_configuration"] == {
        "enc_alg": "aes256gcm16",
        "hash_alg": "sha256",
        "dh_group": "ecp256",
        "pfs_enabled": None,
        "esp_enc": "unknown",
        "esp_integrity": "unknown",
    }


def test_arbitrary_udp_500_is_not_misidentified_as_ike(tmp_path: Path) -> None:
    capture = tmp_path / "not-ike.pcap"
    capture.write_bytes(pcap_bytes([ethernet_ipv4(17, udp(500, 500, b"not an ike message"))]))

    report = analyze_pcap(capture)

    assert report["summary"].get("ikev2_packets", 0) == 0
    assert report["summary"]["udp_500_or_4500_non_ike"] == 1


def test_esp_flows_remain_directional_and_correlated_by_spi(tmp_path: Path) -> None:
    capture = tmp_path / "esp.pcap"
    frames = [
        ethernet_ipv4(50, native_esp(0x11111111, 1)),
        ethernet_ipv4(50, native_esp(0x11111111, 2)),
        ethernet_ipv4(50, native_esp(0x22222222, 1), b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x03"),
    ]
    capture.write_bytes(pcap_bytes(frames))

    report = analyze_pcap(capture)

    associations = report["esp_security_associations"]
    assert report["summary"]["esp_security_associations"] == 2
    assert {association["spi"] for association in associations} == {"0x11111111", "0x22222222"}
    assert next(item for item in associations if item["spi"] == "0x11111111")["packet_count"] == 2


def test_empty_and_truncated_captures_are_handled_without_guessing(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(pcap_bytes([]))
    assert analyze_pcap(empty)["summary"]["frames_total"] == 0

    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(pcap_bytes([]) + b"\x00")
    with pytest.raises(PcapError, match="truncated libpcap packet header"):
        list(PcapReader(truncated))


def test_educational_isim_capture_is_never_reported_as_real_ipsec(tmp_path: Path) -> None:
    capture = tmp_path / "isim.pcap"
    simulator_key_exchange = b"ISIM" + bytes([3, 1]) + b"x" * 52
    capture.write_bytes(
        pcap_bytes(
            [
                ethernet_ipv4(17, udp(500, 500, simulator_key_exchange)),
                ethernet_ipv4(50, native_esp(0x12345678, 1)),
            ]
        )
    )

    report = analyze_pcap(capture)

    assert report["capture_kind"] == "educational_custom_esp_style"
    assert report["esp_security_associations"] == []
    assert report["summary"]["educational_esp_style_flows"] == 1
