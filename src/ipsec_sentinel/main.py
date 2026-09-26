"""Command-line entry point for conservative PCAP analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from ipsec_sentinel.capture.reader import PcapError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze IKEv2/ESP headers in a PCAP without decryption.")
    parser.add_argument("pcap", type=Path, help="libpcap or PCAPNG capture to analyze")
    parser.add_argument("--output", type=Path, help="Write JSON report to this path instead of stdout")
    args = parser.parse_args(argv)
    try:
        report = analyze_pcap(args.pcap)
    except PcapError as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0
