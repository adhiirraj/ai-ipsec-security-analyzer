#!/usr/bin/env python3
"""Explicit lifecycle control for the local strongSwan Docker testbed.

Importing this module performs no Docker calls.  Captures produced here are
intended to be real testbed traffic only after the command verifies a loaded
SA, successful workload, and a non-empty PCAP.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Iterable


TESTBED_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = Path(os.getenv("IPSEC_SENTINEL_TESTBED_RUNTIME_DIR", TESTBED_DIR / "runtime"))
PCAP_DIR = Path(os.getenv("IPSEC_SENTINEL_PCAP_DIR", RUNTIME_DIR / "pcaps"))
CONFIG_DIR = RUNTIME_DIR / "configs"
COMPOSE_FILE = TESTBED_DIR / "docker-compose.yml"
VALID_MODES = {"tunnel", "transport"}
VALID_TRAFFIC = {"voip", "web", "bulk", "icmp", "video", "whatsapp", "email"}
VALID_IP_VERSIONS = {"ipv4", "ipv6"}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,180}$")


class TestbedError(RuntimeError):
    """A prerequisite or live testbed operation failed."""


def _run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=TESTBED_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise TestbedError(f"Required executable is unavailable: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise TestbedError(f"Command timed out after {timeout}s: {' '.join(command)}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "no command output"
        raise TestbedError(f"Command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def get_docker_compose_command() -> list[str]:
    """Find Compose only when a caller asks to use the testbed."""

    if shutil.which("docker"):
        try:
            result = subprocess.run(
                ["docker", "compose", "version"], capture_output=True, text=True, timeout=10, check=False
            )
        except OSError:
            result = None
        if result is not None and result.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
        
    raise Exception("Neither 'docker compose' nor 'docker-compose' was found on this system.")

DOCKER_COMPOSE_CMD = get_docker_compose_cmd()

def setup_testbed():
    print(f"Starting Docker containers using {' '.join(DOCKER_COMPOSE_CMD)}...")
    os.makedirs(BASE_DIR / "pcaps", exist_ok=True)
    os.makedirs(BASE_DIR / "configs" / "server", exist_ok=True)
    os.makedirs(BASE_DIR / "configs" / "client", exist_ok=True)
    res = run_cmd(DOCKER_COMPOSE_CMD + ["up", "-d", "--build"], background=False)
    if res.returncode != 0:
        raise Exception("Docker compose failed")
    time.sleep(2) # Wait for charon to start

def run_experiment(label, ike_prop, esp_prop, mode, traffic, duration=15, ip_version="ipv4"):
    print(f"\n--- Running Experiment: {label} ---")
    
    # 1. Render configs
    context = {
        "ike_proposals": ike_prop,
        "esp_proposals": esp_prop,
        "mode": mode
    }
    outputs: list[Path] = []
    for template_name, role in (
        ("server_swanctl.conf.template", "server"),
        ("client_swanctl.conf.template", "client"),
    ):
        content = _read_template(template_name)
        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)
        if "{{" in content or "}}" in content:
            raise TestbedError(f"Unresolved template placeholder in {template_name}")
        output = CONFIG_DIR / role / "swanctl.conf"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        outputs.append(output)
    return outputs[0], outputs[1]


def build_label(ike: str, esp: str, mode: str, traffic: str, ip_version: str) -> str:
    pfs = "pfs" if esp.endswith(("-ecp256", "-modp2048", "-modp3072", "-modp4096")) else "nopfs"
    label = f"custom_{ike.replace('-', '')}_{esp.replace('-', '')}_{pfs}_{mode}_{ip_version}_{traffic}"
    if not _SAFE_LABEL.fullmatch(label):
        raise TestbedError("Generated capture label contains unsupported characters.")
    return label


def setup_testbed() -> list[str]:
    """Build and start containers after validating the Compose configuration."""

    compose = get_docker_compose_command()
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.joinpath("server").mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.joinpath("client").mkdir(parents=True, exist_ok=True)
    _run(compose + ["-f", str(COMPOSE_FILE), "config", "-q"])
    _run(compose + ["-f", str(COMPOSE_FILE), "up", "-d", "--build"], timeout=180)
    return compose


def _docker_exec(arguments: Iterable[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return _run(["docker", "exec", *arguments], timeout=timeout)


def _assert_security_association() -> None:
    result = _docker_exec(["vpn-client", "swanctl", "--list-sas"])
    if "ESTABLISHED" not in result.stdout.upper():
        raise TestbedError(f"IKE SA did not reach ESTABLISHED state.\n{result.stdout}\n{result.stderr}")
    state = _docker_exec(["vpn-client", "ip", "xfrm", "state"])
    if not state.stdout.strip():
        raise TestbedError("IKE SA was listed but no XFRM state was installed on vpn-client.")


def _capture_start(label: str) -> None:
    pcap_in_container = f"/pcaps/{label}.pcap"
    _docker_exec(
        [
            "-d",
            "vpn-sniffer",
            "sh",
            "-ec",
            f"rm -f {pcap_in_container}; exec tcpdump -i eth0 -nn -s 0 -U "
            f"'(udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50)' -w {pcap_in_container}",
        ]
    )
    time.sleep(1)
    
    # DIAGNOSTICS: Check if XFRM policies and states were actually installed
    print("\n--- XFRM STATE ---")
    print(run_cmd(["docker", "exec", "vpn-client", "ip", "xfrm", "state"]).stdout)
    print("--- XFRM POLICY ---")
    print(run_cmd(["docker", "exec", "vpn-client", "ip", "xfrm", "policy"]).stdout)
    
    # 5. Optional: Start iperf3 server if bulk
    iperf_proc = None
    if traffic == "bulk":
        iperf_proc = run_cmd(["docker", "exec", "vpn-server", "iperf3", "-s"], background=True)
        
    # 6. Run Traffic Generator
    print(f"Generating {traffic} traffic over {ip_version} for {duration}s...")
    gen_cmd = ["docker", "exec", "vpn-client", "python3", "/scripts/traffic_generator.py", "--type", traffic, "--duration", str(duration)]
    if ip_version == "ipv6":
        gen_cmd.append("--ipv6")
    gen_res = run_cmd(gen_cmd)
    print(gen_res.stdout)
    if gen_res.stderr:
        print(f"Gen Stderr: {gen_res.stderr}")
    
    # 7. Teardown
    print("Terminating IPsec tunnel...")
    run_cmd(["docker", "exec", "vpn-client", "swanctl", "--terminate", "--ike", "gw"])
    
    if iperf_proc:
        iperf_proc.terminate()
        
    print("Stopping packet capture...")
    # Killing tcpdump gracefully inside the container to flush PCAP
    run_cmd(["docker", "exec", "vpn-sniffer", "killall", "-2", "tcpdump"])
    time.sleep(0.5) # Give it time to flush to disk
    
    print(f"Experiment {label} complete.")

def main():
    setup_testbed()
    pcap_path = PCAP_DIR / f"{label}.pcap"
    capture_started = False
    initiated = False
    try:
        _docker_exec(["vpn-server", "swanctl", "--load-all"])
        _docker_exec(["vpn-client", "swanctl", "--load-all"])
        _capture_start(label)
        capture_started = True
        _docker_exec(["vpn-client", "swanctl", "--initiate", "--child", "net"], timeout=60)
        initiated = True
        _assert_security_association()
        command = [
            "vpn-client",
            "python3",
            "/scripts/traffic_generator.py",
            "--type",
            traffic,
            "--duration",
            str(duration),
        ]
        if ip_version == "ipv6":
            command.append("--ipv6")
        _docker_exec(command, timeout=duration + 30)
    finally:
        if initiated:
            try:
                _docker_exec(["vpn-client", "swanctl", "--terminate", "--ike", "gw"])
            except TestbedError:
                pass
        if capture_started:
            _capture_stop()
    if not pcap_path.is_file() or pcap_path.stat().st_size <= 24:
        raise TestbedError(f"Capture was not created or contains no packets: {pcap_path}")
    return pcap_path


def teardown_testbed() -> None:
    compose = get_docker_compose_command()
    _run(compose + ["-f", str(COMPOSE_FILE), "down"], timeout=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Control the local strongSwan testbed.")
    parser.add_argument("command", choices=["preflight", "up", "down"])
    args = parser.parse_args(argv)
    if args.command == "preflight":
        print(preflight())
    elif args.command == "up":
        setup_testbed()
    else:
        teardown_testbed()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
