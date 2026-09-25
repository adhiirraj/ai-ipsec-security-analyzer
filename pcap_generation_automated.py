import argparse
import itertools
import json
import os
import shutil
import time
from pathlib import Path
import requests

# API Configuration
API_URL = "http://127.0.0.1:8000/api/run_testbed"

# Directories
PROJECT_ROOT = Path(__file__).parent.resolve()
DEST_PCAP_DIR = PROJECT_ROOT / "data" / "raw_pcaps"
TESTBED_PCAP_DIR = PROJECT_ROOT / "testbed" / "pcaps"
PROGRESS_FILE = PROJECT_ROOT / "data" / "pcap_generation_progress.json"

# --- Parameter Combinations (15,360 Total) ---
MODES = ["tunnel", "transport"]                                          # 2
TRAFFIC_TYPES = ["voip", "web", "bulk", "video", "icmp"]                  # 5

# IKE Phase 1
IKE_ENCS = ["aes256gcm16", "aes256", "aes128ctr", "3des"]               # 4
IKE_HASHES = ["sha256", "sha384", "sha1"]                               # 3
IKE_DHS = ["ecp256", "modp2048", "modp3072", "modp1024"]                  # 4 -> Total IKE = 48

# ESP Phase 2 & PFS
ESP_AEAD = ["aes256gcm16", "aes128gcm16"]                              # 2
ESP_NON_AEAD = ["aes256", "aes128", "aes128ctr"]                        # 3
ESP_AUTHS = ["sha256", "sha384"]                                        # 2 -> 6 non-AEAD
PFS_GROUPS = ["", "-ecp256", "-modp2048", "-modp3072"]                  # 4 -> Total ESP = 32


def generate_ike_proposals():
    """Generates all 48 IKE proposal combinations."""
    return [f"{enc}-{h}-{dh}" for enc, h, dh in itertools.product(IKE_ENCS, IKE_HASHES, IKE_DHS)]


def generate_esp_proposals():
    """Generates all 32 ESP proposal combinations."""
    base_proposals = list(ESP_AEAD)
    for enc, auth in itertools.product(ESP_NON_AEAD, ESP_AUTHS):
        base_proposals.append(f"{enc}-{auth}")
    
    all_esp = []
    for base in base_proposals:
        for pfs in PFS_GROUPS:
            all_esp.append(f"{base}{pfs}")
    return all_esp


def load_progress():
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, "r") as f:
            return set(json.load(f))
    return set()


def save_progress(completed_labels):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(list(completed_labels), f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Automated IPsec PCAP Variation Generator")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay (seconds) between runs to allow container reset")
    parser.add_argument("--limit", type=int, default=None, help="Limit total runs (useful for dry runs)")
    args = parser.parse_args()

    # Ensure output directories exist
    DEST_PCAP_DIR.mkdir(parents=True, exist_ok=True)
    
    ike_proposals = generate_ike_proposals()
    esp_proposals = generate_esp_proposals()
    
    all_combinations = list(itertools.product(MODES, TRAFFIC_TYPES, ike_proposals, esp_proposals))
    total_count = len(all_combinations)
    
    print(f"==================================================")
    print(f"🚀 Starting PCAP Dataset Generator")
    print(f"📊 Total Variations Target: {total_count:,}")
    print(f"📁 Saving to: {DEST_PCAP_DIR}")
    print(f"==================================================\n")

    completed = load_progress()
    skipped_count = 0
    success_count = 0
    failed_count = 0

    start_time = time.time()

    for idx, (mode, traffic, ike, esp) in enumerate(all_combinations, 1):
        if args.limit and (success_count + failed_count) >= args.limit:
            print(f"\n[!] Reached run limit of {args.limit}. Stopping.")
            break

        # Compute unique label string (matching backend label generation logic)
        has_pfs = "-" in esp
        pfs_str = "pfs" if has_pfs else "nopfs"
        label = f"custom_{ike.replace('-','')}_{esp.replace('-','')}_{pfs_str}_{mode}_{traffic}"
        pcap_filename = f"{label}.pcap"
        dest_file_path = DEST_PCAP_DIR / pcap_filename

        # Skip if already executed or file exists
        if label in completed or dest_file_path.exists():
            skipped_count += 1
            continue

        payload = {
            "mode": mode,
            "traffic": traffic,
            "ike": ike,
            "esp": esp
        }

        print(f"[{idx:,}/{total_count:,}] Running: IKE={ike} | ESP={esp} | Mode={mode} | Traffic={traffic}")

        try:
            # 1. Post request to FastAPI endpoint
            res = requests.post(API_URL, json=payload, timeout=90)
            
            if res.status_code == 200:
                success_count += 1
                completed.add(label)
                save_progress(completed)

                # 2. Move generated PCAP from testbed output to data/raw_pcaps/
                src_file_path = TESTBED_PCAP_DIR / pcap_filename
                if not src_file_path.exists():
                    # Fallback check in project root
                    src_file_path = PROJECT_ROOT / pcap_filename

                if src_file_path.exists():
                    shutil.move(str(src_file_path), str(dest_file_path))
                    print(f"   └── [✓] Saved: {dest_file_path.name}")
                else:
                    print(f"   └── [!] PCAP generated but source file not found at {src_file_path}")
            else:
                failed_count += 1
                print(f"   └── [X] Server error ({res.status_code}): {res.text}")

        except Exception as e:
            failed_count += 1
            print(f"   └── [X] Request failed: {e}")

        # Rate limiting / container stabilization pause
        time.sleep(args.delay)

    elapsed_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - start_time))
    print(f"\n==================================================")
    print(f"🎉 Execution Finished!")
    print(f"⏱️ Total Duration: {elapsed_time}")
    print(f"✅ Successfully Created: {success_count:,}")
    print(f"⏭️ Previously Skipped: {skipped_count:,}")
    print(f"❌ Failures: {failed_count:,}")
    print(f"==================================================")


if __name__ == "__main__":
    main()
