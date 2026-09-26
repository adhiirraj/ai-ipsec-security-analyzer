"""Deterministic, header-only IPsec observations from PCAP files.

This module deliberately does not decrypt ESP or infer algorithms, tunnel mode,
or inner applications from ciphertext.  It accepts an IKE packet only after
validating its IKEv2 header; UDP/500 alone is not evidence of IKE.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import struct
from typing import Any

from ipsec_sentinel.capture.reader import PcapReader
from ipsec_sentinel.config.settings import AnalysisSettings


_IKE_HEADER_LENGTH = 28
_IKE_EXCHANGES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
_IKE_ENCRYPTION = {
    3: "3des",
    11: "null",
    12: "aes-cbc",
    13: "aes-ctr",
    20: "aes-gcm-16",
}
_IKE_PRF = {2: "sha1", 5: "sha256", 6: "sha384", 7: "sha512"}
_IKE_INTEGRITY = {2: "sha1", 12: "sha256", 13: "sha384", 14: "sha512"}
_IKE_DH = {
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    19: "ecp256",
    20: "ecp384",
    21: "ecp521",
    31: "x25519",
}


def _empty_configuration() -> dict[str, Any]:
    return {
        "enc_alg": "unknown",
        "hash_alg": "unknown",
        "dh_group": "unknown",
        "pfs_enabled": None,
        "esp_enc": "unknown",
        "esp_integrity": "unknown",
    }


def _ethernet_payload(data: bytes) -> tuple[int, bytes] | None:
    if len(data) < 14:
        return None
    ether_type = struct.unpack("!H", data[12:14])[0]
    offset = 14
    while ether_type in {0x8100, 0x88A8, 0x9100}:
        if len(data) < offset + 4:
            return None
        ether_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        offset += 4
    return ether_type, data[offset:]


def _network_payload(link_type: int, data: bytes) -> tuple[int, bytes] | None:
    """Return an IP ethertype and its bytes for common capture link layers."""

    if link_type == 1:  # Ethernet
        return _ethernet_payload(data)
    if link_type in {101, 228}:  # raw IP / IPv4-without-link-header
        if not data:
            return None
        return (0x0800 if data[0] >> 4 == 4 else 0x86DD), data
    if link_type == 113:  # Linux cooked capture v1
        if len(data) < 16:
            return None
        return struct.unpack("!H", data[14:16])[0], data[16:]
    return None


def _parse_ip(ether_type: int, data: bytes) -> tuple[str, str, int, bytes] | None:
    if ether_type == 0x0800:
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        header_length = (data[0] & 0x0F) * 4
        total_length = struct.unpack("!H", data[2:4])[0]
        if header_length < 20 or len(data) < header_length or total_length < header_length:
            return None
        end = min(total_length, len(data))
        source = ".".join(str(value) for value in data[12:16])
        destination = ".".join(str(value) for value in data[16:20])
        return source, destination, data[9], data[header_length:end]
    if ether_type == 0x86DD:
        if len(data) < 40 or data[0] >> 4 != 6:
            return None
        payload_length = struct.unpack("!H", data[4:6])[0]
        source = ":".join(f"{value:02x}{next_value:02x}" for value, next_value in zip(data[8:24:2], data[9:24:2]))
        destination = ":".join(
            f"{value:02x}{next_value:02x}" for value, next_value in zip(data[24:40:2], data[25:40:2])
        )
        return source, destination, data[6], data[40 : min(40 + payload_length, len(data))]
    return None


def _parse_udp(data: bytes) -> tuple[int, int, bytes] | None:
    if len(data) < 8:
        return None
    source_port, destination_port, length = struct.unpack("!HHH", data[:6])
    if length < 8:
        return None
    return source_port, destination_port, data[8 : min(length, len(data))]


def _ike_header(data: bytes) -> dict[str, Any] | None:
    if len(data) < _IKE_HEADER_LENGTH:
        return None
    initiator_spi, responder_spi = data[:8], data[8:16]
    next_payload, version, exchange_type, flags = data[16:20]
    message_id, declared_length = struct.unpack("!II", data[20:28])
    if (
        initiator_spi == b"\0" * 8
        or version >> 4 != 2
        or exchange_type not in _IKE_EXCHANGES
        or declared_length < _IKE_HEADER_LENGTH
        or declared_length > len(data)
    ):
        return None
    return {
        "initiator_spi": initiator_spi.hex(),
        "responder_spi": responder_spi.hex(),
        "next_payload": next_payload,
        "exchange_type": _IKE_EXCHANGES[exchange_type],
        "is_response": bool(flags & 0x20),
        "message_id": message_id,
        "payload": data[_IKE_HEADER_LENGTH:declared_length],
    }


def _key_length(attributes: bytes) -> int | None:
    offset = 0
    while offset + 4 <= len(attributes):
        raw_type, value_or_length = struct.unpack("!HH", attributes[offset : offset + 4])
        offset += 4
        attribute_type = raw_type & 0x7FFF
        if raw_type & 0x8000:
            if attribute_type == 14:
                return value_or_length
            continue
        if offset + value_or_length > len(attributes):
            return None
        value = attributes[offset : offset + value_or_length]
        offset += value_or_length
        if attribute_type == 14 and len(value) == 2:
            return struct.unpack("!H", value)[0]
    return None


def _name_encryption(transform_id: int, attributes: bytes) -> str:
    name = _IKE_ENCRYPTION.get(transform_id, f"unknown-encr-{transform_id}")
    key_bits = _key_length(attributes)
    if name in {"aes-cbc", "aes-ctr"} and key_bits in {128, 192, 256}:
        return f"aes{key_bits}-{name.split('-', 1)[1]}"
    if name == "aes-gcm-16" and key_bits in {128, 192, 256}:
        return f"aes{key_bits}gcm16"
    return name


def _parse_sa_payload(payload: bytes) -> list[dict[str, str]]:
    """Parse IKEv2 SA payload proposals without claiming they were negotiated."""

    proposals: list[dict[str, str]] = []
    offset = 0
    while offset + 8 <= len(payload):
        _last, _reserved, proposal_length = struct.unpack("!BBH", payload[offset : offset + 4])
        if proposal_length < 8 or offset + proposal_length > len(payload):
            return proposals
        proposal = payload[offset : offset + proposal_length]
        _proposal_number, protocol_id, spi_size, transform_count = proposal[4:8]
        transform_offset = 8 + spi_size
        if transform_offset > len(proposal):
            return proposals
        transforms: dict[str, str] = {}
        parsed_count = 0
        while transform_offset + 8 <= len(proposal) and parsed_count < transform_count:
            _next, _reserved, transform_length, transform_type, _reserved2, transform_id = struct.unpack(
                "!BBHBBH", proposal[transform_offset : transform_offset + 8]
            )
            if transform_length < 8 or transform_offset + transform_length > len(proposal):
                break
            attributes = proposal[transform_offset + 8 : transform_offset + transform_length]
            if transform_type == 1:
                transforms["encryption"] = _name_encryption(transform_id, attributes)
            elif transform_type == 2:
                transforms["prf"] = _IKE_PRF.get(transform_id, f"unknown-prf-{transform_id}")
            elif transform_type == 3:
                transforms["integrity"] = _IKE_INTEGRITY.get(
                    transform_id, f"unknown-integrity-{transform_id}"
                )
            elif transform_type == 4:
                transforms["dh_group"] = _IKE_DH.get(transform_id, f"unknown-dh-{transform_id}")
            transform_offset += transform_length
            parsed_count += 1
        transforms["protocol"] = "ike" if protocol_id == 1 else "esp" if protocol_id == 3 else str(protocol_id)
        proposals.append(transforms)
        offset += proposal_length
    return proposals


def _ike_proposals(header: dict[str, Any]) -> list[dict[str, str]]:
    next_payload = header["next_payload"]
    payload = header["payload"]
    offset = 0
    while next_payload and offset + 4 <= len(payload):
        next_payload_after, _critical, payload_length = struct.unpack("!BBH", payload[offset : offset + 4])
        if payload_length < 4 or offset + payload_length > len(payload):
            return []
        if next_payload == 33:  # Security Association
            return _parse_sa_payload(payload[offset + 4 : offset + payload_length])
        next_payload = next_payload_after
        offset += payload_length
    return []


def _simulator_marker(udp_payload: bytes) -> bool:
    # ISIM is the repository's documented custom format, not an IKEv2 marker.
    return len(udp_payload) == 58 and udp_payload[:4] == b"ISIM" and udp_payload[4] in {2, 3}


def analyze_pcap(path: str | Path, settings: AnalysisSettings | None = None) -> dict[str, Any]:
    """Produce conservative protocol observations for one capture file."""

    active_settings = settings or AnalysisSettings.from_environment()
    reader = PcapReader(path, max_captured_packet_bytes=active_settings.max_captured_packet_bytes)
    counters: Counter[str] = Counter()
    ike_messages: list[dict[str, Any]] = []
    esp_flows: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    simulator_seen = False
    observed_configuration = _empty_configuration()

    for packet in reader:
        counters["frames_total"] += 1
        network = _network_payload(packet.link_type, packet.data)
        if network is None:
            counters["frames_unsupported_or_truncated"] += 1
            continue
        parsed_ip = _parse_ip(*network)
        if parsed_ip is None:
            counters["frames_malformed_network"] += 1
            continue
        source, destination, protocol, transport_payload = parsed_ip
        if protocol == 17:
            udp = _parse_udp(transport_payload)
            if udp is None:
                counters["udp_malformed"] += 1
                continue
            source_port, destination_port, udp_payload = udp
            if {source_port, destination_port} == {500} and _simulator_marker(udp_payload):
                simulator_seen = True
                counters["educational_simulator_key_exchange_packets"] += 1
                continue
            ike_payload: bytes | None = None
            if source_port == 500 or destination_port == 500:
                ike_payload = udp_payload
            elif source_port == 4500 or destination_port == 4500:
                if udp_payload[:4] == b"\0\0\0\0":
                    ike_payload = udp_payload[4:]
                elif len(udp_payload) >= 8:
                    counters["esp_udp_encapsulated_packets"] += 1
                    spi, sequence = struct.unpack("!II", udp_payload[:8])
                    key = (source, destination, spi, "udp-encapsulated")
                    flow = esp_flows.setdefault(
                        key,
                        {"src_ip": source, "dst_ip": destination, "spi": f"0x{spi:08x}", "encapsulation": "udp-encapsulated", "packet_count": 0, "first_sequence": sequence, "last_sequence": sequence},
                    )
                    flow["packet_count"] += 1
                    flow["last_sequence"] = sequence
            if ike_payload is not None:
                header = _ike_header(ike_payload)
                if header is None:
                    counters["udp_500_or_4500_non_ike"] += 1
                    continue
                counters["ikev2_packets"] += 1
                message = {
                    "src_ip": source,
                    "dst_ip": destination,
                    "exchange_type": header["exchange_type"],
                    "is_response": header["is_response"],
                    "initiator_spi": header["initiator_spi"],
                    "responder_spi": header["responder_spi"],
                    "message_id": header["message_id"],
                }
                proposals = _ike_proposals(header)
                if proposals:
                    message["proposals"] = proposals
                if len(ike_messages) < active_settings.max_packet_observations:
                    ike_messages.append(message)
                # IKE_SA_INIT response selects a proposal; an initiator message only offers one.
                if header["exchange_type"] == "IKE_SA_INIT" and header["is_response"] and proposals:
                    selected = proposals[0]
                    observed_configuration.update(
                        {
                            "enc_alg": selected.get("encryption", "unknown"),
                            "hash_alg": selected.get("prf", "unknown"),
                            "dh_group": selected.get("dh_group", "unknown"),
                        }
                    )
        elif protocol == 50:
            counters["esp_ip_protocol_packets"] += 1
            if len(transport_payload) < 8:
                counters["esp_truncated"] += 1
                continue
            spi, sequence = struct.unpack("!II", transport_payload[:8])
            key = (source, destination, spi, "native")
            flow = esp_flows.setdefault(
                key,
                {"src_ip": source, "dst_ip": destination, "spi": f"0x{spi:08x}", "encapsulation": "native", "packet_count": 0, "first_sequence": sequence, "last_sequence": sequence},
            )
            flow["packet_count"] += 1
            flow["last_sequence"] = sequence

    kind = "educational_custom_esp_style" if simulator_seen else "pcap"
    real_esp_flows = [] if simulator_seen else list(esp_flows.values())
    return {
        "capture_kind": kind,
        "disclaimer": (
            "Repository ISIM packets were detected. They are educational ESP-style simulation, not IKEv2 or ESP."
            if simulator_seen
            else "Observations are header-only; encrypted ESP does not reveal its algorithms, tunnel mode, or inner application."
        ),
        "capture": {
            "format": reader.info.capture_format if reader.info else "unknown",
            "link_types": list(reader.info.link_types) if reader.info else [],
            "timestamp_resolution": reader.info.timestamp_resolution if reader.info else "unknown",
        },
        "summary": {
            **dict(counters),
            "ikev2_messages_retained": len(ike_messages),
            "esp_security_associations": len(real_esp_flows),
            "educational_esp_style_flows": len(esp_flows) if simulator_seen else 0,
        },
        "ikev2_messages": ike_messages,
        "esp_security_associations": real_esp_flows,
        "observed_configuration": observed_configuration,
    }
