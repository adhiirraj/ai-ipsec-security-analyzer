#!/usr/bin/env python3
"""Extract reproducible, header-level features from real testbed ESP flows."""

from __future__ import annotations

import argparse
import csv
import logging
from pathlib import Path
import statistics

from scapy.all import ESP, IP, IPv6, PcapReader


LOGGER = logging.getLogger(__name__)
TESTBED_DIR = Path(__file__).resolve().parent
DEFAULT_PCAP_DIR = TESTBED_DIR / "runtime" / "pcaps"
FEATURE_COLUMNS = (
    "packet_count",
    "total_bytes",
    "mean_packet_size",
    "std_packet_size",
    "mean_iat",
    "std_iat",
)


def extract_features_from_pcap(pcap_path: str | Path, label: str, min_packets: int = 10) -> list[dict[str, object]]:
    """Return directional ESP-flow features without decrypting packet payloads."""

    if min_packets < 1:
        raise ValueError("min_packets must be positive")
    flows: dict[tuple[str, str, int], list[object]] = {}
    try:
        with PcapReader(str(pcap_path)) as packets:
            for packet in packets:
                if ESP not in packet:
                    continue
                if IP in packet:
                    source, destination = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    source, destination = packet[IPv6].src, packet[IPv6].dst
                else:
                    continue
                key = (source, destination, int(packet[ESP].spi))
                flows.setdefault(key, []).append(packet)
    except (OSError, EOFError, ValueError) as error:
        LOGGER.warning("Could not read PCAP %s: %s", pcap_path, error)
        return []

    features: list[dict[str, object]] = []
    for (source, destination, spi), packets in flows.items():
        if len(packets) < min_packets:
            continue
        packets.sort(key=lambda packet: float(packet.time))
        sizes = [len(packet) for packet in packets]
        inter_arrival_times = [
            float(packets[index].time) - float(packets[index - 1].time)
            for index in range(1, len(packets))
        ] or [0.0]
        features.append(
            {
                "spi": f"0x{spi:08x}",
                "src_ip": source,
                "dst_ip": destination,
                "packet_count": len(packets),
                "total_bytes": sum(sizes),
                "mean_packet_size": round(statistics.mean(sizes), 2),
                "std_packet_size": round(statistics.stdev(sizes), 2) if len(sizes) > 1 else 0.0,
                "mean_iat": round(statistics.mean(inter_arrival_times), 6),
                "std_iat": round(statistics.stdev(inter_arrival_times), 6)
                if len(inter_arrival_times) > 1
                else 0.0,
                "label": label,
            }
        )
    return features


def extract_directory(pcap_dir: Path, output_csv: Path, min_packets: int = 10) -> int:
    """Extract all PCAPs in one directory into a deterministic CSV file."""

    if not pcap_dir.is_dir():
        raise FileNotFoundError(f"PCAP directory does not exist: {pcap_dir}")
    rows: list[dict[str, object]] = []
    for pcap_path in sorted(pcap_dir.glob("*.pcap")):
        rows.extend(extract_features_from_pcap(pcap_path, pcap_path.stem.split("_")[-1], min_packets))
    if not rows:
        raise ValueError(f"No ESP flows with at least {min_packets} packets found in {pcap_dir}")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract ML features from real testbed ESP PCAPs")
    parser.add_argument("--pcap-dir", type=Path, default=DEFAULT_PCAP_DIR)
    parser.add_argument("--output", type=Path, default=TESTBED_DIR / "dataset.csv")
    parser.add_argument("--min-packets", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        count = extract_directory(args.pcap_dir, args.output, args.min_packets)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))
    print(f"Extracted {count} ESP flows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
