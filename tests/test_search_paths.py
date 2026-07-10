"""Config search path - ``./sigwood.conf`` is not searched.

Clean-break: no project-local config; user must use --config or one of the
two remaining tiers (~/.sigwood/config.toml, /etc/sigwood/config.toml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood.common import config as cfg


def test_search_paths_does_not_include_project_local_sigwood_conf() -> None:
    """SEARCH_PATHS must not carry ./sigwood.conf - the clean-break drop."""
    paths_str = [str(p) for p in cfg.SEARCH_PATHS]
    for p in paths_str:
        assert not p.endswith("sigwood.conf"), (
            f"./sigwood.conf is back in SEARCH_PATHS: {paths_str}"
        )


def test_search_paths_carries_user_and_system_only() -> None:
    paths_str = [str(p) for p in cfg.SEARCH_PATHS]
    # User dir (expanded) and /etc both present.
    assert any(p.endswith(".sigwood/config.toml") for p in paths_str)
    assert "/etc/sigwood/config.toml" in paths_str
    # Exactly two tiers - keep the precedence list tight.
    assert len(paths_str) == 2


def test_stray_sigwood_conf_in_cwd_is_not_picked_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Create a ./sigwood.conf in CWD with a sentinel value. cfg.load() must
    NOT pick it up - only --config explicit + the two remaining tiers."""
    monkeypatch.chdir(tmp_path)
    stray = tmp_path / "sigwood.conf"
    stray.write_text('[sigwood]\nzeek_dir = "/should-never-load"\n', encoding="utf-8")
    # Point the two remaining search paths at nonexistent locations so cfg.load
    # falls back to _DEFAULTS rather than picking up the stray.
    monkeypatch.setattr(
        cfg, "SEARCH_PATHS",
        [tmp_path / "no-user-config", tmp_path / "no-etc-config"],
    )
    config = cfg.load(config_file=None)
    # Defaults shipped, not the sentinel.
    assert config["sigwood"].get("zeek_dir") != "/should-never-load"
