"""Shared pytest configuration and path helpers.

This conftest provides belt-and-suspenders sys.path setup to ensure that both
``src/`` (for ``ipsec_sentinel``) and the project root (for ``testbed`` and
``dashboard``) are importable.  The primary path injection is handled by
``[tool.pytest.ini_options].pythonpath`` in ``pyproject.toml``; this conftest
provides a redundant fallback for environments that use pytest < 7.0 which does
not support the ``pythonpath`` option.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
_SRC_DIR = _PROJECT_ROOT / "src"

for _directory in (_SRC_DIR, _PROJECT_ROOT):
    _dir_str = str(_directory)
    if _dir_str not in sys.path:
        sys.path.insert(0, _dir_str)
