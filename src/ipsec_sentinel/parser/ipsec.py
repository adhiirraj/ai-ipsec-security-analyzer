"""Minimal, deterministic IP/IPsec header parsing for the first vertical slice.

This module intentionally stops at clear-text outer headers and the IKE common
header. It neither decrypts ESP nor infers IPsec configuration from packet
shape. Missing or truncated bytes produce absent observations, never guesses.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from ipsec_sentinel.capture.models import RawPacket
from ipsec_sentinel.parser.models import (
    AHHeaderObservation,
    ESPHeaderObservation,
    IKEHeaderObservation,
    PacketObservation,
)


_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LINUX_SLL = 113
_DLT_LINUX_SLL2 = 276
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
_IPPROTO_ESP = 50
_IPPROTO_AH = 51
_IPPROTO_UDP = 17


@dataclass(frozen=True, slots=True)
class _NetworkPacket:
    ip_version: int
    source: str
    destination: str
    next_protocol: int
    payload: bytes
    protocol_stack: tuple[str, ...]
    parse_note: str | None = None


def parse_packet(packet: RawPacket) -> PacketObservation:
    """Parse only observable outer headers from a raw capture record."""

    network_packet = _decode_link_layer(packet.data, packet.link_type)
    if network_packet is None:
        return PacketObservation(
            frame_number=packet.frame_number,
            timestamp=packet.timestamp,
            captured_length=packet.captured_length,
            original_length=packet.original_length,
            link_type=packet.link_type,
            protocol_stack=(),
            ip_version=None,
            source=None,
            destination=None,
            transport_protocol=None,
            parse_note="unsupported or truncated link-layer/network header",
        )

    return _parse_network_packet(packet, network_packet)


def _decode_link_layer(data: bytes, link_type: int) -> _NetworkPacket | None:
    if link_type == _DLT_EN10MB:
        if len(data) < 14:
            return None
        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ether_type in _VLAN_ETHERTYPES:
            if len(data) < offset + 4:
                return None
            ether_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
        if ether_type == _ETHERTYPE_IPV4:
            return _decode_ipv4(data[offset:], ("Ethernet", "IPv4"))
        if ether_type == _ETHERTYPE_IPV6:
            return _decode_ipv6(data[offset:], ("Ethernet", "IPv6"))
        return None

    if link_type == _DLT_RAW:
        if not data:
            return None
        version = data[0] >> 4
        if version == 4:
            return _decode_ipv4(data, ("Raw", "IPv4"))
        if version == 6:
            return _decode_ipv6(data, ("Raw", "IPv6"))
        return None

    if link_type == _DLT_LINUX_SLL:
        if len(data) < 16:
            return None
        protocol = struct.unpack("!H", data[14:16])[0]
        if protocol == _ETHERTYPE_IPV4:
            return _decode_ipv4(data[16:], ("Linux SLL", "IPv4"))
        if protocol == _ETHERTYPE_IPV6:
            return _decode_ipv6(data[16:], ("Linux SLL", "IPv6"))
        return None

    if link_type == _DLT_LINUX_SLL2:
        if len(data) < 20:
            return None
        protocol = struct.unpack("!H", data[:2])[0]
        if protocol == _ETHERTYPE_IPV4:
            return _decode_ipv4(data[20:], ("Linux SLL2", "IPv4"))
        if protocol == _ETHERTYPE_IPV6:
            return _decode_ipv6(data[20:], ("Linux SLL2", "IPv6"))
    return None


def _decode_ipv4(data: bytes, protocol_stack: tuple[str, ...]) -> _NetworkPacket | None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    header_length = (data[0] & 0x0F) * 4
    if header_length < 20 or header_length > len(data):
        return None
    total_length = struct.unpack("!H", data[2:4])[0]
    # A zero total length is malformed. If the capture was snaplen-truncated,
    # parsing the available outer header is still safe.
    if total_length == 0:
        return None
    payload_end = min(total_length, len(data))
    fragment_offset = struct.unpack("!H", data[6:8])[0] & 0x1FFF
    protocol = data[9]
    source = str(ipaddress.IPv4Address(data[12:16]))
    destination = str(ipaddress.IPv4Address(data[16:20]))
    if fragment_offset:
        return _NetworkPacket(
            ip_version=4,
            source=source,
            destination=destination,
            next_protocol=protocol,
            payload=b"",
            protocol_stack=protocol_stack,
            parse_note="non-initial IPv4 fragment; transport header is not observable",
        )
    return _NetworkPacket(
        ip_version=4,
        source=source,
        destination=destination,
        next_protocol=protocol,
        payload=data[header_length:payload_end],
        protocol_stack=protocol_stack,
    )


def _decode_ipv6(data: bytes, protocol_stack: tuple[str, ...]) -> _NetworkPacket | None:
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    payload_length = struct.unpack("!H", data[4:6])[0]
    next_protocol = data[6]
    source = str(ipaddress.IPv6Address(data[8:24]))
    destination = str(ipaddress.IPv6Address(data[24:40]))
    end = min(len(data), 40 + payload_length)
    offset = 40

    # Walk only clear IPv6 extension headers. ESP terminates the visible chain.
    for _ in range(16):
        if next_protocol in {_IPPROTO_ESP, _IPPROTO_AH, _IPPROTO_UDP, 59}:
            break
        if next_protocol in {0, 43, 60}:  # Hop-by-Hop, Routing, Destination
            if offset + 2 > end:
                return None
            following_header = data[offset]
            extension_length = (data[offset + 1] + 1) * 8
            if offset + extension_length > end:
                return None
            next_protocol = following_header
            offset += extension_length
            continue
        if next_protocol == 44:  # Fragment
            if offset + 8 > end:
                return None
            following_header = data[offset]
            fragment_field = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            if (fragment_field >> 3) != 0:
                return _NetworkPacket(
                    ip_version=6,
                    source=source,
                    destination=destination,
                    next_protocol=following_header,
                    payload=b"",
                    protocol_stack=protocol_stack,
                    parse_note="non-initial IPv6 fragment; transport header is not observable",
                )
            next_protocol = following_header
            offset += 8
            continue
        # An unknown extension/upper-layer protocol cannot be safely skipped.
        break

    return _NetworkPacket(
        ip_version=6,
        source=source,
        destination=destination,
        next_protocol=next_protocol,
        payload=data[offset:end],
        protocol_stack=protocol_stack,
    )


def _parse_network_packet(packet: RawPacket, network: _NetworkPacket) -> PacketObservation:
    stack = list(network.protocol_stack)
    source_port: int | None = None
    destination_port: int | None = None
    ike: IKEHeaderObservation | None = None
    esp: ESPHeaderObservation | None = None
    ah: AHHeaderObservation | None = None
    protocol = network.next_protocol

    if protocol == _IPPROTO_ESP:
        stack.append("ESP")
        esp = _parse_esp(network.payload, encapsulation="ip")
    elif protocol == _IPPROTO_AH:
        stack.append("AH")
        ah = _parse_ah(network.payload)
    elif protocol == _IPPROTO_UDP:
        stack.append("UDP")
        if len(network.payload) >= 8:
            source_port, destination_port, udp_length, _checksum = struct.unpack(
                "!HHHH", network.payload[:8]
            )
            udp_payload_end = min(len(network.payload), udp_length) if udp_length else len(network.payload)
            udp_payload = network.payload[8:udp_payload_end]
            ike, esp = _parse_udp_ipsec(source_port, destination_port, udp_payload)
            if ike is not None:
                stack.append(ike.version)
            elif esp is not None:
                stack.append("ESP")

    return PacketObservation(
        frame_number=packet.frame_number,
        timestamp=packet.timestamp,
        captured_length=packet.captured_length,
        original_length=packet.original_length,
        link_type=packet.link_type,
        protocol_stack=tuple(stack),
        ip_version=network.ip_version,
        source=network.source,
        destination=network.destination,
        transport_protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        ike=ike,
        esp=esp,
        ah=ah,
        parse_note=network.parse_note,
    )


def _parse_udp_ipsec(
    source_port: int, destination_port: int, udp_payload: bytes
) -> tuple[IKEHeaderObservation | None, ESPHeaderObservation | None]:
    if source_port not in {500, 4500} and destination_port not in {500, 4500}:
        return None, None
    if source_port == 500 or destination_port == 500:
        return _parse_ike(udp_payload), None

    # RFC NAT-T uses four zero bytes to distinguish IKE from ESP-in-UDP.
    if len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
        return _parse_ike(udp_payload[4:]), None
    return None, _parse_esp(udp_payload, encapsulation="udp-encapsulated")


def _parse_ike(data: bytes) -> IKEHeaderObservation | None:
    if len(data) < 28:
        return None
    version_byte = data[17]
    major_version = version_byte >> 4
    if major_version not in {1, 2}:
        return None
    # RFC 7296 requires the IKEv2 initiator SPI to be non-zero. Enforcing this
    # inexpensive structural invariant avoids labelling arbitrary UDP/500 data
    # as IKEv2 based on a coincidental version nibble.
    if major_version == 2 and data[:8] == b"\x00" * 8:
        return None
    declared_length = struct.unpack("!I", data[24:28])[0]
    if declared_length < 28:
        return None
    # A reported capture may be snaplen-truncated, so a larger declared length
    # is acceptable. A valid common header remains observable.
    return IKEHeaderObservation(
        version=f"IKEv{major_version}",
        initiator_spi=data[:8].hex(),
        responder_spi=data[8:16].hex(),
        exchange_type=data[18],
        flags=data[19],
        message_id=struct.unpack("!I", data[20:24])[0],
        declared_length=declared_length,
    )


def _parse_esp(data: bytes, *, encapsulation: str) -> ESPHeaderObservation | None:
    if len(data) < 8:
        return None
    spi, sequence_number = struct.unpack("!II", data[:8])
    # SPI zero is reserved. Do not call arbitrary UDP/4500 payload ESP if its
    # clear SPI cannot represent a valid Security Association.
    if spi == 0:
        return None
    return ESPHeaderObservation(spi=f"0x{spi:08x}", sequence_number=sequence_number,
                                encapsulation=encapsulation)


def _parse_ah(data: bytes) -> AHHeaderObservation | None:
    if len(data) < 12:
        return None
    next_header = data[0]
    spi, sequence_number = struct.unpack("!II", data[4:12])
    if spi == 0:
        return None
    return AHHeaderObservation(
        spi=f"0x{spi:08x}", sequence_number=sequence_number, next_header=next_header
    )
