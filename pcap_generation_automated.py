#!/usr/bin/env python3
import argparse
import itertools
import json
import shutil
import time
from pathlib import Path

import requests

API_URL = "http://127.0.0.1:8000/api/run_testbed"

PROJECT_ROOT = Path(__file__).parent.resolve()
DEST_PCAP_DIR = PROJECT_ROOT / "data" / "raw_pcaps"
TESTBED_PCAP_DIR = PROJECT_ROOT / "testbed" / "pcaps"
PROGRESS_FILE = PROJECT_ROOT / "data" / "pcap_generation_progress.json"

MODES = ["tunnel", "transport"]
TRAFFIC_TYPES = ["voip", "web", "bulk", "video", "icmp"]

IKE_ENCS = ["aes256gcm16", "aes256", "aes128ctr", "3des"]
IKE_HASHES = ["sha256", "sha384", "sha1"]
IKE_DHS = ["ecp256", "modp2048", "modp3072", "modp1024"]

ESP_AEAD = ["aes256gcm16", "aes128gcm16"]
ESP_NON_AEAD = ["aes256", "aes128", "aes128ctr"]
ESP_AUTHS = ["sha256", "sha384"]
PFS_GROUPS = ["", "-ecp256", "-modp2048", "-modp3072"]

SAVE_PROGRESS_EVERY = 100
DEFAULT_DELAY = 0.0
DEFAULT_DURATION = 15


def generate_ike_proposals():
    return [
        f"{enc}-{h}-{dh}"
        for enc, h, dh in itertools.product(
            IKE_ENCS,
            IKE_HASHES,
            IKE_DHS,
        )
    ]


def generate_esp_proposals():
    base_proposals = list(ESP_AEAD)

    base_proposals.extend(
        f"{enc}-{auth}"
        for enc, auth in itertools.product(
            ESP_NON_AEAD,
            ESP_AUTHS,
        )
    )

    yield from (
        f"{base}{pfs}"
        for base, pfs in itertools.product(
            base_proposals,
            PFS_GROUPS,
        )
    )


def generate_combinations():
    ike_list = generate_ike_proposals()
    esp_list = list(generate_esp_proposals())

    yield from (
        (mode, traffic, ike, esp)
        for ike, esp, mode, traffic in itertools.product(
            ike_list,
            esp_list,
            MODES,
            TRAFFIC_TYPES,
        )
    )


def load_progress():
    if not PROGRESS_FILE.exists():
        return set()

    with PROGRESS_FILE.open("r") as f:
        return set(json.load(f))


def save_progress(completed_labels):
    with PROGRESS_FILE.open("w") as f:
        json.dump(sorted(completed_labels), f)


def esp_has_pfs(esp: str) -> bool:
    return esp.endswith(("-ecp256", "-modp2048", "-modp3072"))


def move_file(src: Path, dst: Path):
    try:
        src.replace(dst)
    except OSError:
        shutil.move(str(src), str(dst))


def main():
    parser = argparse.ArgumentParser(
        description="Automated IPsec PCAP Variation Generator"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Extra delay between API runs (default: 0)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of attempted runs",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        help="Traffic duration per sample in seconds",
    )
    args = parser.parse_args()

    DEST_PCAP_DIR.mkdir(parents=True, exist_ok=True)

    total_count = (
        len(IKE_ENCS)
        * len(IKE_HASHES)
        * len(IKE_DHS)
        * (
            len(ESP_AEAD)
            + len(ESP_NON_AEAD) * len(ESP_AUTHS)
        )
        * len(PFS_GROUPS)
        * len(MODES)
        * len(TRAFFIC_TYPES)
    )

    print("=" * 50)
    print("Starting optimized interleaved PCAP dataset generator")
    print(f"Total target: {total_count:,}")
    print(f"Traffic duration: {args.duration}s")
    print(f"Extra delay: {args.delay}s")
    print("=" * 50)

    completed = load_progress()

    skipped_count = 0
    success_count = 0
    failed_count = 0

    start_time = time.perf_counter()

    session = requests.Session()

    try:
        for idx, (mode, traffic, ike, esp) in enumerate(
            generate_combinations(),
            1,
        ):
            attempts = success_count + failed_count
            if args.limit is not None and attempts >= args.limit:
                print(f"\nReached run limit of {args.limit}.")
                break

            pfs_str = "pfs" if esp_has_pfs(esp) else "nopfs"

            label = (
                f"custom_"
                f"{ike.replace('-', '')}_"
                f"{esp.replace('-', '')}_"
                f"{pfs_str}_"
                f"{mode}_"
                f"{traffic}"
            )

            pcap_filename = f"{label}.pcap"
            dest_file_path = DEST_PCAP_DIR / pcap_filename

            if label in completed or dest_file_path.exists():
                skipped_count += 1
                continue

            payload = {
                "mode": mode,
                "traffic": traffic,
                "ike": ike,
                "esp": esp,
                "duration": args.duration,
            }

            print(
                f"[{idx:,}/{total_count:,}] "
                f"{traffic:<5} | {mode:<9} | "
                f"IKE={ike} | ESP={esp}"
            )

            try:
                res = session.post(
                    API_URL,
                    json=payload,
                    timeout=(5, max(90, args.duration + 60)),
                )

                if res.status_code == 200:
                    success_count += 1
                    completed.add(label)

                    src_file_path = TESTBED_PCAP_DIR / pcap_filename

                    if not src_file_path.exists():
                        src_file_path = PROJECT_ROOT / pcap_filename

                    if src_file_path.exists():
                        move_file(src_file_path, dest_file_path)
                        print(f"   [OK] {dest_file_path.name}")
                    else:
                        failed_count += 1
                        success_count -= 1
                        print(
                            f"   [FAIL] API succeeded but pcap was missing: "
                            f"{src_file_path}"
                        )

                    if success_count % SAVE_PROGRESS_EVERY == 0:
                        save_progress(completed)

                else:
                    failed_count += 1
                    print(
                        f"   [FAIL] Server error "
                        f"{res.status_code}: {res.text}"
                    )

            except Exception as exc:
                failed_count += 1
                print(f"   [FAIL] Request failed: {exc}")

            if args.delay > 0:
                time.sleep(args.delay)

    finally:
        save_progress(completed)
        session.close()

    elapsed = time.perf_counter() - start_time

    print("\n" + "=" * 50)
    print("Execution finished")
    print(f"Duration: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")
    print(f"Successful: {success_count:,}")
    print(f"Skipped: {skipped_count:,}")
    print(f"Failed: {failed_count:,}")
    print("=" * 50)


if __name__ == "__main__":
    main()
