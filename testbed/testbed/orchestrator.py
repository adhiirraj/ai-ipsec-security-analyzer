#!/usr/bin/env python3
import itertools
import os
import subprocess
import time
from pathlib import Path
from threading import Lock

# Hackathon / dataset configuration
MODES = ["tunnel", "transport"]

CRYPTO_SUITES = [
    ("aes128-sha256-modp2048", "aes128-sha256", "aes128_nopfs"),
    ("aes256-sha384-modp3072", "aes256-sha384-modp3072", "aes256_pfs"),
    ("aes256gcm16-prfsha256-ecp256", "aes256gcm16", "aes256gcm_nopfs"),
]

TRAFFIC_TYPES = ["voip", "web", "bulk", "icmp", "video"]

# Runtime tuning.
# 10 seconds is a reasonable compromise between dataset size and generation time.
DEFAULT_TRAFFIC_DURATION = int(os.getenv("TRAFFIC_DURATION", "15"))
CAPTURE_START_DELAY = float(os.getenv("CAPTURE_START_DELAY", "0.15"))
CAPTURE_STOP_TIMEOUT = float(os.getenv("CAPTURE_STOP_TIMEOUT", "5"))
COMMAND_TIMEOUT = int(os.getenv("TESTBED_COMMAND_TIMEOUT", "60"))

CONFIG_MATRIX = [
    (f"{crypto_lbl}_{mode}_{traffic}", ike, esp, mode, traffic)
    for mode, (ike, esp, crypto_lbl), traffic
    in itertools.product(MODES, CRYPTO_SUITES, TRAFFIC_TYPES)
]

BASE_DIR = Path(__file__).parent.resolve()
PCAP_DIR = BASE_DIR / "pcaps"
CONFIG_DIR = BASE_DIR / "configs"

_TESTBED_READY = False
_SETUP_LOCK = Lock()
_TEMPLATE_CACHE = {}


def render_template(template_name: str, output_name: str, context: dict) -> None:
    template_path = BASE_DIR / "templates" / template_name
    output_path = CONFIG_DIR / output_name

    if template_name not in _TEMPLATE_CACHE:
        _TEMPLATE_CACHE[template_name] = template_path.read_text()

    content = _TEMPLATE_CACHE[template_name]

    for key, value in context.items():
        content = content.replace(f"{{{{ {key} }}}}", value)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Keep the existing inode because docker-compose bind-mounts this file.
    output_path.write_text(content)


def run_cmd(
    cmd: list[str],
    *,
    background: bool = False,
    timeout: int = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess | subprocess.Popen:
    if background:
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=BASE_DIR,
        )

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=BASE_DIR,
        timeout=timeout,
    )


def get_docker_compose_cmd() -> list[str]:
    # Prefer Docker Compose v2.
    res = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        return ["docker", "compose"]

    # Fallback to legacy docker-compose.
    res = subprocess.run(
        ["docker-compose", "--version"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        return ["docker-compose"]

    raise RuntimeError(
        "Neither 'docker compose' nor 'docker-compose' "
        "was found on this system."
    )


DOCKER_COMPOSE_CMD = None


def compose_cmd() -> list[str]:
    global DOCKER_COMPOSE_CMD
    if DOCKER_COMPOSE_CMD is None:
        DOCKER_COMPOSE_CMD = get_docker_compose_cmd()
    return DOCKER_COMPOSE_CMD


def _container_running(name: str) -> bool:
    res = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
    )
    return res.returncode == 0 and res.stdout.strip() == "true"


def _charon_running(container: str) -> bool:
    res = subprocess.run(
        ["docker", "exec", container, "pidof", "charon"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return res.returncode == 0 and bool(res.stdout.strip())


def _wait_for_testbed(timeout: float = 15.0) -> None:
    deadline = time.perf_counter() + timeout

    while time.perf_counter() < deadline:
        containers_ready = all(
            _container_running(name)
            for name in ("vpn-server", "vpn-client", "vpn-sniffer")
        )

        charon_ready = (
            containers_ready
            and _charon_running("vpn-server")
            and _charon_running("vpn-client")
        )

        if charon_ready:
            return

        time.sleep(0.1)

    raise RuntimeError("Docker testbed did not become ready in time.")


def setup_testbed(force_rebuild: bool = False) -> None:
    """
    Start the testbed once and keep it alive across experiments.

    The old implementation ran `docker compose up -d --build` for every
    API request. This function makes startup idempotent and only touches
    Docker when the testbed is actually unavailable.
    """
    global _TESTBED_READY

    if _TESTBED_READY and not force_rebuild:
        return

    with _SETUP_LOCK:
        if _TESTBED_READY and not force_rebuild:
            return

        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        (CONFIG_DIR / "server").mkdir(parents=True, exist_ok=True)
        (CONFIG_DIR / "client").mkdir(parents=True, exist_ok=True)

        all_running = all(
            _container_running(name)
            for name in ("vpn-server", "vpn-client", "vpn-sniffer")
        )

        if not all_running or force_rebuild:
            cmd = compose_cmd() + ["up", "-d"]
            if force_rebuild:
                cmd.append("--build")

            res = run_cmd(cmd)
            if res.returncode != 0:
                raise RuntimeError(
                    "Docker compose failed:\n"
                    f"stdout: {res.stdout}\n"
                    f"stderr: {res.stderr}"
                )

        _wait_for_testbed()
        _TESTBED_READY = True


def mark_testbed_unhealthy() -> None:
    global _TESTBED_READY
    _TESTBED_READY = False


def esp_has_pfs(esp_prop: str) -> bool:
    """
    PFS is encoded as a final DH group on the ESP proposal.

    This deliberately does NOT use `"-" in esp_prop`, because proposals
    such as aes256-sha256 are non-PFS proposals that also contain '-'.
    """
    return esp_prop.endswith(("-ecp256", "-modp2048", "-modp3072"))


def _start_capture(label: str):
    pcap_host_path = PCAP_DIR / f"{label}.pcap"

    if pcap_host_path.exists():
        pcap_host_path.unlink()

    pcap_file = f"/pcaps/{label}.pcap"

    proc = run_cmd(
        [
            "docker",
            "exec",
            "vpn-sniffer",
            "tcpdump",
            "-i",
            "any",
            "-U",
            "-w",
            pcap_file,
            "udp port 500 or udp port 4500 or esp",
        ],
        background=True,
    )

    time.sleep(CAPTURE_START_DELAY)

    if not pcap_host_path.exists():
        # One short grace period. This is still far cheaper than a fixed 1s
        # sleep for every experiment.
        deadline = time.perf_counter() + 1.0
        while time.perf_counter() < deadline:
            if pcap_host_path.exists():
                break
            time.sleep(0.05)

    if not pcap_host_path.exists():
        proc.terminate()
        raise RuntimeError("tcpdump did not create the capture file.")

    return proc, pcap_host_path


def _stop_capture(sniffer_proc: subprocess.Popen | None) -> None:
    if sniffer_proc is None:
        return

    # Interrupt tcpdump inside the container so it flushes the pcap cleanly.
    stop_res = run_cmd(
        ["docker", "exec", "vpn-sniffer", "killall", "-2", "tcpdump"],
        timeout=10,
    )

    if stop_res.returncode != 0:
        # If killall failed, force-stop the host-side docker exec process.
        if sniffer_proc.poll() is None:
            sniffer_proc.terminate()

    try:
        sniffer_proc.wait(timeout=CAPTURE_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        sniffer_proc.kill()
        sniffer_proc.wait(timeout=2)


def _load_ipsec_config() -> None:
    # The secrets are static, so loading the full swanctl config is kept for
    # compatibility with the existing setup.
    for container in ("vpn-server", "vpn-client"):
        res = run_cmd(
            ["docker", "exec", container, "swanctl", "--load-all"],
            timeout=20,
        )
        if res.returncode != 0:
            raise RuntimeError(
                f"swanctl --load-all failed in {container}:\n"
                f"{res.stdout}\n{res.stderr}"
            )


def _terminate_tunnel() -> None:
    run_cmd(
        [
            "docker",
            "exec",
            "vpn-client",
            "swanctl",
            "--terminate",
            "--ike",
            "gw",
        ],
        timeout=15,
    )


def run_experiment(
    label: str,
    ike_prop: str,
    esp_prop: str,
    mode: str,
    traffic: str,
    duration: int | None = None,
) -> Path:
    """
    Run one complete experiment while reusing the already-running Docker
    testbed.
    """
    setup_testbed()

    duration = DEFAULT_TRAFFIC_DURATION if duration is None else int(duration)

    print(f"\n--- Running Experiment: {label} ---")

    context = {
        "ike_proposals": ike_prop,
        "esp_proposals": esp_prop,
        "mode": mode,
    }

    render_template(
        "server_swanctl.conf.template",
        "server/swanctl.conf",
        context,
    )
    render_template(
        "client_swanctl.conf.template",
        "client/swanctl.conf",
        context,
    )

    sniffer_proc = None
    iperf_proc = None

    try:
        print("Loading IPsec configurations...")
        _load_ipsec_config()

        print("Starting packet capture...")
        sniffer_proc, pcap_host_path = _start_capture(label)

        print("Initiating IPsec tunnel...")
        init_res = run_cmd(
            [
                "docker",
                "exec",
                "vpn-client",
                "swanctl",
                "--initiate",
                "--child",
                "net",
            ],
            timeout=30,
        )

        if init_res.returncode != 0:
            raise RuntimeError(
                "IPsec tunnel initiation failed:\n"
                f"{init_res.stdout}\n{init_res.stderr}"
            )

        # --initiate waits for the initiation job to complete, so the old
        # unconditional 2-second post-init sleep is unnecessary.
        print(f"Generating {traffic} traffic for {duration}s...")

        if traffic == "bulk":
            iperf_proc = run_cmd(
                [
                    "docker",
                    "exec",
                    "vpn-server",
                    "iperf3",
                    "-s",
                ],
                background=True,
            )
            # Give the server process a moment to bind its socket.
            time.sleep(0.1)

        gen_res = run_cmd(
            [
                "docker",
                "exec",
                "vpn-client",
                "python3",
                "/scripts/traffic_generator.py",
                "--type",
                traffic,
                "--duration",
                str(duration),
            ],
            timeout=max(COMMAND_TIMEOUT, duration + 30),
        )

        if gen_res.returncode != 0:
            raise RuntimeError(
                f"Traffic generator failed:\n"
                f"{gen_res.stdout}\n{gen_res.stderr}"
            )

        if gen_res.stdout:
            print(gen_res.stdout, end="")

        if gen_res.stderr:
            print(gen_res.stderr, end="")

        return pcap_host_path

    finally:
        if iperf_proc is not None:
            try:
                iperf_proc.terminate()
                iperf_proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    iperf_proc.kill()
                except ProcessLookupError:
                    pass

        _terminate_tunnel()
        _stop_capture(sniffer_proc)

        if "pcap_host_path" in locals() and not pcap_host_path.exists():
            raise RuntimeError(
                f"Expected pcap was not created: {pcap_host_path}"
            )

        print(f"Experiment {label} complete.")


def shutdown_testbed() -> None:
    global _TESTBED_READY

    if not _TESTBED_READY:
        return

    run_cmd(compose_cmd() + ["down"], timeout=60)
    _TESTBED_READY = False


def main():
    print(
        f"Generated a comprehensive matrix of "
        f"{len(CONFIG_MATRIX)} IPsec configurations!"
    )

    setup_testbed()

    try:
        for config in CONFIG_MATRIX:
            run_experiment(*config)
    finally:
        print("\nAll experiments finished. Shutting down containers...")
        shutdown_testbed()


if __name__ == "__main__":
    main()
