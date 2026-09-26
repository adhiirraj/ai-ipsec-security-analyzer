#!/usr/bin/env python3
"""Generate controlled testbed workloads through a configured IPsec tunnel.

The UDP profiles are synthetic timing/size profiles. In particular, the
``whatsapp`` profile is not captured WhatsApp, WebRTC, VoIP, or video traffic.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import socket
import subprocess
import time


WORKLOADS = ("voip", "web", "bulk", "icmp", "video", "whatsapp", "email")


@dataclass(frozen=True)
class TrafficSettings:
    target_ip: str = "10.0.0.2"
    socket_family: int = socket.AF_INET


def settings_for_ip_version(ipv6: bool) -> TrafficSettings:
    return TrafficSettings("fd00::2", socket.AF_INET6) if ipv6 else TrafficSettings()


def _send_udp(
    settings: TrafficSettings,
    port: int,
    payload: bytes,
    duration: int,
    interval: float,
    burst: int = 1,
) -> int:
    deadline = time.monotonic() + duration
    sent = 0
    with socket.socket(settings.socket_family, socket.SOCK_DGRAM) as sock:
        while time.monotonic() < deadline:
            for _ in range(burst):
                sock.sendto(payload, (settings.target_ip, port))
                sent += 1
            time.sleep(interval)
    if sent == 0:
        raise RuntimeError("UDP workload sent no packets before its deadline.")
    return sent


def generate_voip(settings: TrafficSettings, duration: int) -> None:
    count = _send_udp(settings, 5060, b"A" * 160, duration, 0.02)
    print(f"Synthetic VoIP-like UDP profile: sent {count} packets to the test receiver.")


def generate_web(settings: TrafficSettings, duration: int) -> None:
    """Make real HTTP requests to the testbed's local HTTP server."""

    deadline = time.monotonic() + duration
    requests = 0
    url = f"http://[{settings.target_ip}]/" if settings.socket_family == socket.AF_INET6 else f"http://{settings.target_ip}/"
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["curl", "--fail", "--silent", "--show-error", "--max-time", "3", url],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"HTTP workload failed against {url}: {result.stderr.strip()}")
        requests += 1
        time.sleep(0.2)
    print(f"Web workload: completed {requests} HTTP requests to the test server.")


def generate_bulk(settings: TrafficSettings, duration: int) -> None:
    result = subprocess.run(
        ["iperf3", "-c", settings.target_ip, "-t", str(duration), "-b", "10M"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"iperf3 bulk workload failed: {result.stderr.strip() or result.stdout.strip()}")
    print("Bulk workload: iperf3 transfer completed against the test server.")


def generate_icmp(settings: TrafficSettings, duration: int) -> None:
    command = ["ping", "-c", str(duration), settings.target_ip]
    if settings.socket_family == socket.AF_INET6:
        command.insert(1, "-6")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"ICMP workload failed: {result.stderr.strip() or result.stdout.strip()}")
    print("ICMP workload: ping replies received from the test server.")


def generate_video(settings: TrafficSettings, duration: int) -> None:
    count = _send_udp(settings, 5004, b"V" * 1300, duration, 0.03, burst=30)
    print(f"Synthetic video-like UDP profile: sent {count} packets to the test receiver.")


def generate_whatsapp(settings: TrafficSettings, duration: int) -> None:
    count = _send_udp(settings, 3478, b"W" * 300, duration, 0.04)
    print(
        f"Synthetic chat-call-like UDP profile: sent {count} packets to the test receiver; "
        "this is not WhatsApp traffic."
    )


def generate_email(settings: TrafficSettings, duration: int) -> None:
    deadline = time.monotonic() + duration
    connections = 0
    while time.monotonic() < deadline:
        with socket.create_connection((settings.target_ip, 143), timeout=3) as sock:
            sock.sendall(b"A001 NOOP\r\n")
        connections += 1
        time.sleep(1)
    print(f"Synthetic email-like TCP profile: opened {connections} connections to the test receiver.")


GENERATORS = {
    "voip": generate_voip,
    "web": generate_web,
    "bulk": generate_bulk,
    "icmp": generate_icmp,
    "video": generate_video,
    "whatsapp": generate_whatsapp,
    "email": generate_email,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Controlled synthetic traffic generator for the IPsec testbed")
    parser.add_argument("--type", choices=WORKLOADS, required=True)
    parser.add_argument("--duration", type=int, default=2, help="Duration in seconds (1-300)")
    parser.add_argument("--ipv6", action="store_true", help="Send traffic to the IPv6 testbed endpoint")
    args = parser.parse_args(argv)
    if not 1 <= args.duration <= 300:
        parser.error("--duration must be between 1 and 300 seconds")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        GENERATORS[args.type](settings_for_ip_version(args.ipv6), args.duration)
    except (OSError, RuntimeError) as error:
        print(f"Workload failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
