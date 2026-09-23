from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ipsec_sentinel.capture.reader import PcapError, PcapReader
from ipsec_sentinel.parser.ipsec import parse_packet


def _ipv4_packet(protocol: int, payload: bytes, source: bytes = b"\xc0\x00\x02\x01") -> bytes:
    destination = b"\xc6\x33\x64\x01"
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        source,
        destination,
    )
    return b"\x00" * 12 + b"\x08\x00" + header + payload


def _ikev2_payload() -> bytes:
    return struct.pack(
        "!8s8sBBBBII",
        b"\x01" * 8,
        b"\x02" * 8,
        0,
        0x20,
        34,
        0x08,
        7,
        28,
    )


def _udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def _write_classic_pcap(path: Path, frames: list[bytes]) -> None:
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    content = bytearray(global_header)
    for index, frame in enumerate(frames, start=1):
        content.extend(struct.pack("<IIII", 1_700_000_000 + index, 500_000, len(frame), len(frame)))
        content.extend(frame)
    path.write_bytes(content)


def _write_pcapng(path: Path, frame: bytes) -> None:
    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    padding = b"\x00" * ((-len(frame)) % 4)
    block_length = 8 + 20 + len(frame) + len(padding) + 4
    enhanced = (
        struct.pack("<II", 6, block_length)
        + struct.pack("<IIIII", 0, 0, 1_000_000, len(frame), len(frame))
        + frame
        + padding
        + struct.pack("<I", block_length)
    )
    path.write_bytes(section + interface + enhanced)


class CaptureAndParserTests(unittest.TestCase):
    def test_classic_pcap_streams_ike_and_esp_header_evidence(self) -> None:
        ike_frame = _ipv4_packet(17, _udp(500, 500, _ikev2_payload()))
        esp_frame = _ipv4_packet(50, struct.pack("!II", 0x01020304, 15) + b"encrypted")
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture_path = Path(temporary_directory) / "mixed.pcap"
            _write_classic_pcap(capture_path, [ike_frame, esp_frame])
            reader = PcapReader(capture_path)
            packets = list(reader)

        self.assertEqual(len(packets), 2)
        self.assertEqual(reader.info.capture_format, "pcap")
        self.assertEqual(reader.info.link_types, (1,))
        ike = parse_packet(packets[0])
        esp = parse_packet(packets[1])
        self.assertEqual(ike.ike.version, "IKEv2")
        self.assertEqual(ike.ike.initiator_spi, "0101010101010101")
        self.assertEqual(ike.source, "192.0.2.1")
        self.assertEqual(esp.esp.spi, "0x01020304")
        self.assertEqual(esp.esp.sequence_number, 15)
        self.assertEqual(esp.esp.encapsulation, "ip")

    def test_pcapng_enhanced_packet_is_read(self) -> None:
        frame = _ipv4_packet(17, _udp(500, 500, _ikev2_payload()))
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture_path = Path(temporary_directory) / "ike.pcapng"
            _write_pcapng(capture_path, frame)
            reader = PcapReader(capture_path)
            packets = list(reader)

        self.assertEqual(len(packets), 1)
        self.assertEqual(reader.info.capture_format, "pcapng")
        self.assertEqual(packets[0].timestamp, 1.0)
        self.assertEqual(parse_packet(packets[0]).ike.version, "IKEv2")

    def test_udp_4500_non_esp_marker_and_nat_t_esp_are_distinguished(self) -> None:
        ike_frame = _ipv4_packet(17, _udp(4500, 4500, b"\x00" * 4 + _ikev2_payload()))
        esp_frame = _ipv4_packet(17, _udp(4500, 4500, struct.pack("!II", 0x10203040, 99)))
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture_path = Path(temporary_directory) / "natt.pcap"
            _write_classic_pcap(capture_path, [ike_frame, esp_frame])
            packets = list(PcapReader(capture_path))

        self.assertEqual(parse_packet(packets[0]).ike.version, "IKEv2")
        natt_esp = parse_packet(packets[1]).esp
        self.assertEqual(natt_esp.spi, "0x10203040")
        self.assertEqual(natt_esp.encapsulation, "udp-encapsulated")

    def test_malformed_ikev2_zero_initiator_spi_is_not_classified_as_ike(self) -> None:
        malformed_header = struct.pack(
            "!8s8sBBBBII", b"\x00" * 8, b"\x00" * 8, 0, 0x20, 34, 0, 0, 28
        )
        frame = _ipv4_packet(17, _udp(500, 500, malformed_header))
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture_path = Path(temporary_directory) / "not-ike.pcap"
            _write_classic_pcap(capture_path, [frame])
            packet = next(iter(PcapReader(capture_path)))

        observation = parse_packet(packet)
        self.assertIsNone(observation.ike)
        self.assertNotIn("IKEv2", observation.protocol_stack)

    def test_truncated_capture_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture_path = Path(temporary_directory) / "broken.pcap"
            capture_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 3)
            with self.assertRaisesRegex(PcapError, "truncated"):
                list(PcapReader(capture_path))


if __name__ == "__main__":
    unittest.main()
