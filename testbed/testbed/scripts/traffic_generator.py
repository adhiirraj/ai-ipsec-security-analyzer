#!/usr/bin/env python3
import argparse
import socket
import subprocess
import time

TARGET_IP = "10.0.0.2"

VOIP_PORT = 5060
WEB_PORT = 80
VIDEO_PORT = 5004

VOIP_PACKET_INTERVAL = 0.02
WEB_REQUEST_INTERVAL = 0.50
VIDEO_BURST_PACKETS = 30
VIDEO_FRAME_INTERVAL = 0.033


def generate_voip(duration: int) -> None:
    """G.711-like RTP traffic: 160 bytes every 20 ms."""
    print(f"Generating VoIP traffic for {duration} seconds...")

    payload = b"A" * 160
    deadline = time.perf_counter() + duration
    next_send = time.perf_counter()
    packets_sent = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while True:
            now = time.perf_counter()
            if now >= deadline:
                break

            if now < next_send:
                time.sleep(next_send - now)
                continue

            sock.sendto(payload, (TARGET_IP, VOIP_PORT))
            packets_sent += 1
            next_send += VOIP_PACKET_INTERVAL

    print(f"Sent {packets_sent} VoIP packets.")


def generate_web(duration: int) -> None:
    """
    Synthetic short TCP web flows.

    The current server container does not expose an HTTP server, so failed
    connections are intentionally tolerated. This still produces TCP traffic
    through the IPsec path.
    """
    print(f"Generating Web traffic for {duration} seconds...")

    deadline = time.perf_counter() + duration
    next_attempt = time.perf_counter()
    attempts = 0

    while True:
        now = time.perf_counter()
        if now >= deadline:
            break

        if now < next_attempt:
            time.sleep(next_attempt - now)
            continue

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                sock.connect((TARGET_IP, WEB_PORT))
                sock.sendall(
                    b"GET / HTTP/1.1\r\n"
                    b"Host: server\r\n"
                    b"Connection: close\r\n\r\n"
                )
                try:
                    sock.recv(1024)
                except (socket.timeout, ConnectionError):
                    pass
        except OSError:
            pass

        attempts += 1
        next_attempt += WEB_REQUEST_INTERVAL

    print(f"Web connection attempts: {attempts}")


def generate_bulk(duration: int) -> None:
    """High-volume TCP transfer through iperf3."""
    print(f"Generating Bulk traffic for {duration} seconds...")

    try:
        subprocess.run(
            [
                "iperf3",
                "-c",
                TARGET_IP,
                "-t",
                str(duration),
                "-b",
                "10M",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        print(f"iperf3 failed: {exc}")
        raise


def generate_icmp(duration: int) -> None:
    """ICMP traffic at approximately one packet per second."""
    print(f"Generating ICMP traffic for {duration} seconds...")

    try:
        subprocess.run(
            [
                "ping",
                "-c",
                str(duration),
                TARGET_IP,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        print(f"ping failed: {exc}")
        raise


def generate_video(duration: int) -> None:
    """Bursty RTP-like UDP video traffic."""
    print(f"Generating Video streaming traffic for {duration} seconds...")

    payload = b"V" * 1300
    deadline = time.perf_counter() + duration
    next_frame = time.perf_counter()
    packets_sent = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while True:
            now = time.perf_counter()
            if now >= deadline:
                break

            if now < next_frame:
                time.sleep(next_frame - now)
                continue

            for _ in range(VIDEO_BURST_PACKETS):
                sock.sendto(payload, (TARGET_IP, VIDEO_PORT))
                packets_sent += 1

            next_frame += VIDEO_FRAME_INTERVAL

    print(f"Video packets sent: {packets_sent}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synthetic Traffic Generator"
    )
    parser.add_argument(
        "--type",
        choices=["voip", "web", "bulk", "icmp", "video"],
        required=True,
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Duration in seconds",
    )

    args = parser.parse_args()

    generators = {
        "voip": generate_voip,
        "web": generate_web,
        "bulk": generate_bulk,
        "icmp": generate_icmp,
        "video": generate_video,
    }

    generators[args.type](args.duration)


if __name__ == "__main__":
    main()
