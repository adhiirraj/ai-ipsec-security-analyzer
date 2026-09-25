#!/usr/bin/env python3
import os
import time
import subprocess
from pathlib import Path

import itertools

# Hackathon Requirements:
# Modes: Tunnel, Transport
# Cryptography: AES-128, AES-256, AES-GCM, AES-CBC+HMAC
# PFS: Enabled/Disabled
# Traffic: VoIP, Web, Bulk, ICMP, Video

MODES = ["tunnel", "transport"]

# IKE and ESP combinations
# Tuple format: (ike_proposal, esp_proposal, label_prefix)
CRYPTO_SUITES = [
    # AES-128-CBC + HMAC-SHA256 (No PFS)
    ("aes128-sha256-modp2048", "aes128-sha256", "aes128_nopfs"),
    # AES-256-CBC + HMAC-SHA384 (PFS enabled with DH 15 / modp3072)
    ("aes256-sha384-modp3072", "aes256-sha384-modp3072", "aes256_pfs"),
    # AES-256-GCM (No PFS)
    ("aes256gcm16-prfsha256-ecp256", "aes256gcm16", "aes256gcm_nopfs"),
]

TRAFFIC_TYPES = ["voip", "web", "bulk", "icmp", "video"]

CONFIG_MATRIX = []
for mode, (ike, esp, crypto_lbl), traffic in itertools.product(MODES, CRYPTO_SUITES, TRAFFIC_TYPES):
    label = f"{crypto_lbl}_{mode}_{traffic}"
    CONFIG_MATRIX.append((label, ike, esp, mode, traffic))

print(f"Generated a comprehensive matrix of {len(CONFIG_MATRIX)} IPsec configurations!")

BASE_DIR = Path(__file__).parent.resolve()

def render_template(template_name: str, output_name: str, context: dict):
    template_path = BASE_DIR / "templates" / template_name
    output_path = BASE_DIR / "configs" / output_name
    
    with open(template_path, 'r') as f:
        content = f.read()
        
    for key, value in context.items():
        content = content.replace(f"{{{{ {key} }}}}", value)
        
    os.makedirs(output_path.parent, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(content)

def run_cmd(cmd: list[str], background=False):
    if background:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=BASE_DIR)
    else:
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR)
        if res.returncode != 0:
            print(f"Command failed: {' '.join(cmd)}\nStdout: {res.stdout}\nStderr: {res.stderr}")
        return res

def get_docker_compose_cmd():
    # Check if 'docker compose' (v2) works
    res = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if res.returncode == 0 and "version" in res.stdout.lower():
        return ["docker", "compose"]
    
    # Fallback to 'docker-compose' (v1)
    res = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
    if res.returncode == 0:
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
    render_template("server_swanctl.conf.template", "server/swanctl.conf", context)
    render_template("client_swanctl.conf.template", "client/swanctl.conf", context)
    
    # 2. Load configs into running containers
    print("Loading IPsec configurations...")
    run_cmd(["docker", "exec", "vpn-server", "swanctl", "--load-all"])
    run_cmd(["docker", "exec", "vpn-client", "swanctl", "--load-all"])
    
    # 3. Start PCAP capture in sniffer
    pcap_file = f"/pcaps/{label}.pcap"
    print(f"Starting packet capture to {pcap_file}...")
    # BPF: capture IKE (500,4500) and ESP (50)
    sniffer_proc = run_cmd([
        "docker", "exec", "vpn-sniffer", 
        "tcpdump", "-i", "any", "-U", "udp port 500 or udp port 4500 or esp", "-w", pcap_file
    ], background=True)
    
    time.sleep(0.5)
    
    # 4. Initiate VPN
    print("Initiating IPsec tunnel...")
    init_res = run_cmd(["docker", "exec", "vpn-client", "swanctl", "--initiate", "--child", "net"])
    if "established successfully" not in init_res.stdout:
        print(f"Warning: Tunnel might not have established. Output: {init_res.stdout}\nStderr: {init_res.stderr}")
    
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
    
    for config in CONFIG_MATRIX:
        run_experiment(*config)
        
    print("\nAll experiments finished. Shutting down containers...")
    run_cmd(DOCKER_COMPOSE_CMD + ["down"])

if __name__ == "__main__":
    main()
