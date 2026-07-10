"""Warnings-as-errors policy guard.

Pins the FutureWarning/DeprecationWarning-as-errors policy in pyproject.toml so it
cannot be silently deleted later while the suite happens to be warning-clean.
"""

import tomllib
from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_pytest_filterwarnings_policy():
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    filterwarnings = data["tool"]["pytest"]["ini_options"]["filterwarnings"]
    assert set(filterwarnings) == {"error::FutureWarning", "error::DeprecationWarning"}
    assert len(filterwarnings) == 2
