# Priority 0 Audit — IPsec-Sentinel AI

**Date**: 2026-09-26  
**Repository**: ai-ipsec-security-analyzer

---

## 1. Audit Methodology

Every Python source file, configuration file, template, and test was read and
analysed directly.  Shell-command execution was unavailable in this environment
(PowerShell resolution failure — see §6 for exact blocker).  All static
findings are based on code inspection; no results are fabricated.

---

## 2. Confirmed Defects (Fixed in This PR)

### D-01 — `aes_ctr/ipsec_multi.py`: bare `import crypto_backend` fails outside its directory

**Severity**: HIGH

Original line 21:
```python
import crypto_backend as backend
```
When `test_educational_simulator_round_trip` calls the script via
`subprocess.run([sys.executable, str(script), "encrypt", ...])`, the working
directory is `tmp_path`, not `aes_ctr/`. Python raises `ModuleNotFoundError`.

**Fix**: `importlib.util.spec_from_file_location` derived from `__file__`.

---

### D-02 — `pyproject.toml`: `scapy` missing from the `all` extra

**Severity**: HIGH

`testbed/extract_features.py` imports scapy at module level. The `all` extras
group (used by `requirements.txt`) did not include `scapy` — it was only in the
`protocol` extra. Any import of `testbed.extract_features` fails with `ImportError`.

**Fix**: Added `scapy>=2.5.0` to the `all` extras group.

---

### D-03 — `pyproject.toml`: `numpy` not declared as a dependency

**Severity**: MEDIUM

`tests/test_dashboard_api.py` imports `numpy` directly at module level.
Numpy was not listed in any extras or dev dependencies.

**Fix**: Added `numpy>=1.26` to the `all` extras group.

---

### D-04 — `dashboard/backend/api.py`: unconditional `StaticFiles` mount crashes on startup

**Severity**: MEDIUM

`StaticFiles(directory=FRONTEND_DIR)` raises `RuntimeError` if the frontend
directory does not exist — at module import time, blocking all API tests.

**Fix**: Wrapped in `if FRONTEND_DIR.is_dir():` with a warning fallback.

---

### D-05 — `src/ipsec_sentinel/parser/`: directory has no `__init__.py`

**Severity**: LOW

`parser/` subpackage directory contained only `__pycache__`. Without `__init__.py`,
setuptools cannot discover it and Python cannot import `ipsec_sentinel.parser`.

**Fix**: Created `src/ipsec_sentinel/parser/__init__.py`.

---

### D-06 — `tests/test_testbed_and_simulator.py`: fragile `generate_whatsapp.__doc__` assertion

**Severity**: LOW

The function has **no docstring** (only a print statement). The condition
`if traffic_generator.generate_whatsapp.__doc__` was always `None`, making the
assertion trivially `True` with no real coverage.

**Fix**: Replaced with `inspect.getsource()` check on the actual function body.

---

### D-07 — `.github/workflows/ci.yml`: incomplete CI step

**Severity**: MEDIUM

CI installed `requirements.txt` but `scapy` was missing from `all` extras
(fixed by D-02). Lacked step names, making logs harder to read.

**Fix**: Simplified to `pip install -e ".[all,dev]"` with explicit step names.

---

## 3. Suspected Issues (Not Fixed — Tracked Here)

### S-01 — `testbed/extract_features.py` top-level scapy import

When imported as a module, scapy loads immediately. D-02 fixes availability;
the eager import pattern remains. A future cleanup should move the import inside
the function body.

### S-02 — `docker-compose.yml` deprecated `version: '3.8'` key

Docker Compose V2 ignores this key with a deprecation warning. Not functional.
**Recommendation**: Remove the `version:` line.

### S-03 — Configuration templates have CRLF line endings

Both swanctl templates use `\r\n`. strongSwan parses them correctly on Linux.

### S-04 — Pre-shared key is hard-coded in configuration templates

The PSK `HackathonSecretKey2026` is committed in plain text. Acceptable for an
educational testbed; must be parameterised before any production deployment.

---

## 4. Previously Alleged Issues — Not Confirmed

| Claim | Verdict |
|---|---|
| Unresolved merge-conflict markers in `api.py` | **NOT FOUND** — grepped all `.py`, `.yml`, `.toml`, `.md` files |
| Unresolved merge-conflict markers in `traffic_generator.py` | **NOT FOUND** |
| Python syntax errors in `api.py` | **NOT FOUND** — file is syntactically valid |
| Python syntax errors in `traffic_generator.py` | **NOT FOUND** — file is syntactically valid |

---

## 5. Unavailable Environmental Dependencies

| Component | Status |
|---|---|
| Docker / Docker Compose | Unavailable |
| strongSwan (`swanctl`, `charon`) | Unavailable |
| tcpdump / Wireshark / tshark | Unavailable |
| iperf3, curl, socat | Unavailable |
| PowerShell via `run_command` tool | **BLOCKED** (see §6) |

---

## 6. Command Execution Blocker

Every `run_command` invocation fails with:

```
exec: "{Cwd}\powershell": executable file not found in %PATH%
```

The tool resolves `powershell` relative to the Cwd instead of using the system
PATH. This is an environment-level issue outside the codebase.

**To run checks manually (Ubuntu/WSL or Windows PowerShell with venv activated)**:

```bash
# Activate venv (Linux/WSL)
source .venv/bin/activate

# Or Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -e ".[all,dev]"

# Syntax check
python -m compileall -q src dashboard/backend testbed aes_ctr aes_ctr_ipsec.py pcap_generation_automated.py

# Lint
python -m ruff check src dashboard/backend testbed tests

# Unit tests
python -m pytest -m "not integration" -v
```

---

## 7. Files Changed

| File | Change | Defect |
|---|---|---|
| `aes_ctr/ipsec_multi.py` | Fixed bare `import crypto_backend` | D-01 |
| `pyproject.toml` | Added `scapy`, `numpy` to `all` extras | D-02, D-03 |
| `src/ipsec_sentinel/parser/__init__.py` | Created missing package init | D-05 |
| `dashboard/backend/api.py` | Conditional `StaticFiles` mount | D-04 |
| `tests/test_testbed_and_simulator.py` | Fixed `generate_whatsapp` assertion | D-06 |
| `.github/workflows/ci.yml` | Improved CI step | D-07 |
| `conftest.py` | NEW: root-level sys.path setup | — |
| `docs/priority0-audit.md` | NEW: this document | — |
| `docs/priority0-validation.md` | NEW: validation record | — |
| `README.md` | Updated quick-start | — |
