"""Package module execution support."""

from __future__ import annotations

import subprocess
import sys


def test_python_m_sigwood_runs_cli_help() -> None:
    """``python -m sigwood`` delegates to the normal CLI entry point."""
    result = subprocess.run(
        [sys.executable, "-m", "sigwood", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "sigwood - network threat hunting" in result.stdout
    assert "Usage:" in result.stdout
    assert "sigwood hunt [options] [PATH ...]" in result.stdout
    assert result.stderr == ""
