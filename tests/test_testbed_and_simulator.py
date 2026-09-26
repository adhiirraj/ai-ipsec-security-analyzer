from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from testbed import orchestrator
from testbed.scripts import traffic_generator


def test_testbed_import_and_preflight_are_side_effect_free() -> None:
    readiness = orchestrator.preflight()

    assert readiness["compose_file_exists"] is True
    assert readiness["starts_on_health_check"] is False


def test_runtime_config_rendering_does_not_change_tracked_configs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(orchestrator, "RUNTIME_DIR", tmp_path / "runtime")
    monkeypatch.setattr(orchestrator, "CONFIG_DIR", tmp_path / "runtime" / "configs")

    server, client = orchestrator.render_swanctl_configs("aes256gcm16-prfsha256-ecp256", "aes256gcm16", "tunnel")

    assert "aes256gcm16" in server.read_text(encoding="utf-8")
    assert "{{" not in client.read_text(encoding="utf-8")
    with pytest.raises(orchestrator.TestbedError, match="letters, digits, and hyphens"):
        orchestrator.render_swanctl_configs("bad;proposal", "aes256gcm16", "tunnel")


def test_traffic_generator_configuration_is_bounded_and_labels_synthetic() -> None:
    arguments = traffic_generator.parse_args(["--type", "whatsapp", "--duration", "2", "--ipv6"])

    assert arguments.type == "whatsapp"
    assert traffic_generator.settings_for_ip_version(True).target_ip == "fd00::2"
    # Verify the function source explicitly labels this as NOT real WhatsApp traffic.
    import inspect
    src = inspect.getsource(traffic_generator.generate_whatsapp)
    assert "not WhatsApp" in src, "generate_whatsapp must label its output as non-WhatsApp"


def test_educational_simulator_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"priority-zero simulator round trip" * 100)
    generated = tmp_path / "generated"
    recovered = tmp_path / "recovered"
    project_root = Path(__file__).resolve().parents[1]
    script = project_root / "aes_ctr" / "ipsec_multi.py"

    subprocess.run(
        [sys.executable, str(script), "encrypt", str(source), "--out", str(generated)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(script),
            "recover",
            str(generated / "traffic.pcap"),
            "--receiver-key",
            str(generated / "receiver_private.pem"),
            "--out",
            str(recovered),
            "--mode",
            "decrypt",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    # With --mode decrypt the simulator writes to out/decrypted/<name>.
    assert (recovered / "decrypted" / source.name).read_bytes() == source.read_bytes()
