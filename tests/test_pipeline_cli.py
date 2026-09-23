from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from ipsec_sentinel.main import main


def _write_esp_capture(path: Path) -> None:
    payload = struct.pack("!II", 0xAABBCCDD, 1) + b"ciphertext"
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0,
        64,
        50,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    frame = b"\x00" * 12 + b"\x08\x00" + ipv4 + payload
    path.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(frame), len(frame))
        + frame
    )


class PipelineAndCliTests(unittest.TestCase):
    def test_pipeline_has_explicit_pending_analysis_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture_path = Path(temporary_directory) / "esp.pcap"
            _write_esp_capture(capture_path)
            report = analyze_pcap(capture_path).to_dict()

        self.assertEqual(report["schema_version"], "0.1.0")
        self.assertTrue(report["ipsec"]["detected"])
        self.assertEqual(report["ipsec"]["protocols"], ["ESP"])
        self.assertEqual(report["pcap"]["packet_count"], 1)
        self.assertEqual(report["security_associations"], [])
        self.assertEqual(report["esp_flows"], [])
        self.assertIsNone(report["security_assessment"]["score"])
        self.assertEqual(report["ml"]["predictions"], [])

    def test_cli_writes_versioned_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture_path = directory / "esp.pcap"
            output_path = directory / "result.json"
            _write_esp_capture(capture_path)
            status = main(["--pcap", str(capture_path), "--output", str(output_path)])
            document = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(document["pcap"]["filename"], "esp.pcap")
        self.assertEqual(document["packet_observations"][0]["esp"]["spi"], "0xaabbccdd")


if __name__ == "__main__":
    unittest.main()
