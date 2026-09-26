"""Small deterministic PCAP fixtures without a capture-tool dependency."""

from __future__ import annotations

import struct


def ethernet_ipv4(protocol: int, payload: bytes, source: bytes = b"\x0a\x00\x00\x03", destination: bytes = b"\x0a\x00\x00\x02") -> bytes:
    total_length = 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 0, 0, 64, protocol, 0, source, destination
    )
    return b"\x02\0\0\0\0\x02\x02\0\0\0\0\x03\x08\0" + ipv4 + payload


def udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def pcap_bytes(frames: list[bytes]) -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
    for index, frame in enumerate(frames):
        output.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def _transform(next_value: int, transform_type: int, transform_id: int, key_length: int | None = None) -> bytes:
    attributes = b"" if key_length is None else struct.pack("!HH", 0x800E, key_length)
    return struct.pack("!BBHBBH", next_value, 0, 8 + len(attributes), transform_type, 0, transform_id) + attributes


def ike_sa_init_response() -> bytes:
    transforms = b"".join(
        [
            _transform(3, 1, 20, 256),  # AES-GCM-16 with a 256-bit key
            _transform(3, 2, 5),  # PRF HMAC-SHA2-256
            _transform(0, 4, 19),  # ECP-256
        ]
    )
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 3) + transforms
    sa = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    header = b"\x01" * 8 + b"\x02" * 8 + bytes([33, 0x20, 34, 0x20])
    return header + struct.pack("!II", 0, 28 + len(sa)) + sa


def native_esp(spi: int, sequence: int, payload: bytes = b"ciphertext") -> bytes:
    return struct.pack("!II", spi, sequence) + payload
