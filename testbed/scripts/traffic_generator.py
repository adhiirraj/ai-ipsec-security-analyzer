#!/usr/bin/env python3
import socket
import time
import argparse
import sys
import subprocess

TARGET_IP = "10.0.0.2"
VOIP_PORT = 5060
WEB_PORT = 80

def generate_voip(duration: int):
    """Simulates VoIP traffic (e.g., G.711 codec). 160 bytes of payload every 20ms."""
    print(f"Generating VoIP traffic for {duration} seconds...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'A' * 160
    end_time = time.time() + duration
    packets_sent = 0
    
    while time.time() < end_time:
        sock.sendto(payload, (TARGET_IP, VOIP_PORT))
        packets_sent += 1
        time.sleep(0.02) # 20ms
        
    print(f"Sent {packets_sent} VoIP packets.")

def generate_web(duration: int):
    """Simulates Web Browsing (HTTP GET and small response)."""
    # Since we don't have a real web server running on the server container right now,
    # we will just send TCP SYN packets or use UDP to simulate the asymmetric nature,
    # OR we can just use curl against a netcat on the server, but for simplicity, 
    # let's just send asymmetric UDP bursts to simulate web flow if we don't care about TCP state,
    # BUT IPsec ESP doesn't care about TCP/UDP, it just encrypts the IP payload.
    # To be realistic for ML, TCP is better because of handshakes and ACKs.
    # We can use iperf3 for web if we limit bandwidth and use small bursts, but custom socket is easier.
    print(f"Generating Web traffic for {duration} seconds... (Simulated via TCP connection attempts)")
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            # We just attempt a connection. It will send a SYN. Server replies RST-ACK.
            # This generates small packets.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((TARGET_IP, WEB_PORT))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: server\r\n\r\n")
            sock.recv(1024)
            sock.close()
        except Exception:
            pass # We expect connection refused since no server is listening, but packets are sent!
        time.sleep(0.2) # User reading time

def generate_bulk(duration: int):
    """Simulates Bulk transfer using iperf3."""
    print(f"Generating Bulk traffic for {duration} seconds...")
    try:
        subprocess.run(["iperf3", "-c", TARGET_IP, "-t", str(duration), "-b", "10M"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"iperf3 failed: {e}")

def generate_icmp(duration: int):
    """Simulates ICMP Ping traffic."""
    print(f"Generating ICMP traffic for {duration} seconds...")
    try:
        # Ping the target IP for the duration (1 ping per second)
        subprocess.run(["ping", "-c", str(duration), TARGET_IP], check=True)
    except subprocess.CalledProcessError as e:
        print(f"ping failed: {e}")

def generate_video(duration: int):
    """Simulates Video Streaming (Bursty UDP traffic with large MTU packets)."""
    print(f"Generating Video streaming traffic for {duration} seconds...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'V' * 1300 # Large packets typical for video
    end_time = time.time() + duration
    
    while time.time() < end_time:
        # Send a burst of 30 frames (packets)
        for _ in range(30):
            sock.sendto(payload, (TARGET_IP, 5004)) # Standard RTP port
        time.sleep(0.03) # ~30 FPS

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic Traffic Generator")
    parser.add_argument("--type", choices=["voip", "web", "bulk", "icmp", "video"], required=True)
    parser.add_argument("--duration", type=int, default=2, help="Duration in seconds")
    args = parser.parse_args()
    
    if args.type == "voip":
        generate_voip(args.duration)
    elif args.type == "web":
        generate_web(args.duration)
    elif args.type == "bulk":
        generate_bulk(args.duration)
    elif args.type == "icmp":
        generate_icmp(args.duration)
    elif args.type == "video":
        generate_video(args.duration)
