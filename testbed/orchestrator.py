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
    raise TestbedError(
        "Docker Compose was not found. Install Docker Engine with the Compose plugin, then rerun from Ubuntu/WSL."
    )


def preflight() -> dict[str, object]:
    """Return non-mutating testbed readiness information for the API health route."""

    available = bool(shutil.which("docker") or shutil.which("docker-compose"))
    return {
        "docker_or_compose_on_path": available,
        "compose_file_exists": COMPOSE_FILE.is_file(),
        "runtime_directory": str(RUNTIME_DIR),
        "starts_on_health_check": False,
    }


def _read_template(name: str) -> str:
    path = TESTBED_DIR / "templates" / name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise TestbedError(f"Missing strongSwan template: {path}") from error


def _proposal_is_safe(proposal: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9-]+", proposal))


def render_swanctl_configs(ike_proposal: str, esp_proposal: str, mode: str) -> tuple[Path, Path]:
    """Render runtime-only configs; do not overwrite tracked baseline configs."""

    if mode not in VALID_MODES:
        raise TestbedError(f"Unsupported IPsec mode '{mode}'. Expected one of {sorted(VALID_MODES)}.")
    if not _proposal_is_safe(ike_proposal) or not _proposal_is_safe(esp_proposal):
        raise TestbedError("IKE and ESP proposals may contain only letters, digits, and hyphens.")
    replacements = {
        "{{ ike_proposals }}": ike_proposal,
        "{{ esp_proposals }}": esp_proposal,
        "{{ mode }}": mode,
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


def _capture_stop() -> None:
    try:
        _docker_exec(["vpn-sniffer", "sh", "-c", "pkill -INT tcpdump || true"])
        time.sleep(1)
    except TestbedError:
        # Preserve the root cause of an experiment; cleanup failure is logged by Docker on inspection.
        pass


def run_experiment(
    label: str,
    ike_prop: str,
    esp_prop: str,
    mode: str,
    traffic: str,
    duration: int = 15,
    ip_version: str = "ipv4",
) -> Path:
    """Create one real testbed capture and reject silent partial success."""

    if not _SAFE_LABEL.fullmatch(label):
        raise TestbedError("Capture label contains unsupported characters.")
    if traffic not in VALID_TRAFFIC:
        raise TestbedError(f"Unsupported workload '{traffic}'. Expected one of {sorted(VALID_TRAFFIC)}.")
    if ip_version not in VALID_IP_VERSIONS:
        raise TestbedError(f"Unsupported IP version '{ip_version}'.")
    if duration < 1 or duration > 300:
        raise TestbedError("Traffic duration must be between 1 and 300 seconds.")

    render_swanctl_configs(ike_prop, esp_prop, mode)
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
