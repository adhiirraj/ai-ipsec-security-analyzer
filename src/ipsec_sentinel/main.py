"""Command-line interface for local, read-only PCAP analysis."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from ipsec_sentinel.analysis.pipeline import analyze_pcap
from ipsec_sentinel.capture.reader import PcapError
from ipsec_sentinel.config.settings import AnalysisSettings


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipsec-sentinel",
        description="Stream a PCAP/PCAPNG and report observable IPsec header evidence.",
    )
    parser.add_argument("--pcap", help="Path to a classic PCAP or PCAPNG file")
    parser.add_argument("--output", "-o", help="Write JSON to this file; defaults to stdout")
    parser.add_argument(
        "--max-packet-observations",
        type=int,
        help="Maximum IPsec packet observations included in JSON (counts remain complete)",
    )
    subcommands = parser.add_subparsers(dest="command")
    analyze = subcommands.add_parser("analyze", help="Analyze a PCAP/PCAPNG file")
    analyze.add_argument("pcap_path", help="Path to a classic PCAP or PCAPNG file")
    analyze.add_argument("--output", "-o", help="Write JSON to this file; defaults to stdout")
    analyze.add_argument(
        "--max-packet-observations",
        type=int,
        help="Maximum IPsec packet observations included in JSON (counts remain complete)",
    )
    return parser


def _resolve_arguments(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[str, str | None, int | None]:
    if args.command == "analyze":
        return args.pcap_path, args.output, args.max_packet_observations
    if args.pcap:
        return args.pcap, args.output, args.max_packet_observations
    parser.error("provide --pcap PATH or use 'analyze PATH'")
    raise AssertionError("argparse.error always raises SystemExit")


def _write_json(output: str | None, report: dict[str, object]) -> None:
    document = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(document)
        return
    destination = Path(output)
    parent = destination.parent
    if not parent.is_dir():
        raise ValueError(f"output directory does not exist: {parent}")
    # A temporary file and replace avoid a partial report if serialization or a
    # write fails midway. No shell or user-provided command is executed.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=parent, prefix=f".{destination.name}.", delete=False
    ) as temporary:
        temporary.write(document)
        temporary_path = Path(temporary.name)
    temporary_path.replace(destination)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process-friendly status code."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    pcap, output, observation_limit = _resolve_arguments(args, parser)
    try:
        defaults = AnalysisSettings.from_environment()
        settings = (
            AnalysisSettings(
                max_packet_observations=observation_limit,
                max_captured_packet_bytes=defaults.max_captured_packet_bytes,
            )
            if observation_limit is not None
            else defaults
        )
        report = analyze_pcap(pcap, settings)
        _write_json(output, report.to_dict())
    except (OSError, PcapError, ValueError) as error:
        sys.stderr.write(f"ipsec-sentinel: {error}\n")
        return 2
    return 0
