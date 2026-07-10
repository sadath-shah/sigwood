"""Unit coverage for ``common.paths.resolve_path`` and ``effective_root``.

The SIGWOOD_ROOT rail collapses scattered ``os.path.expanduser`` calls at the
CLI/config seam. ``resolve_path`` is pure: no validation, no URL handling,
no suffix sniffing - string in, string-or-None out, trailing slash preserved.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sigwood.common.paths import effective_root, resolve_path


# ── resolve_path: four-branch coverage ────────────────────────────────────────


def test_resolve_path_none_returns_none() -> None:
    assert resolve_path(None, "/some/root") is None


def test_resolve_path_empty_string_returns_none() -> None:
    """Empty config value → None. Exporter cascade still floors
    to '.' afterward, but this helper does not."""
    assert resolve_path("", "/some/root") is None


def test_resolve_path_absolute_value_returned_as_is_root_ignored() -> None:
    assert resolve_path("/var/log/zeek", "/elsewhere") == "/var/log/zeek"


def test_resolve_path_tilde_anchored_expands_user_root_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(fake_home))
    assert resolve_path("~/x/exports", "/elsewhere") == str(fake_home / "x/exports")


def test_resolve_path_relative_with_root_joins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # Absolute root: literal join.
    assert resolve_path("exports", "/sigwood-root") == os.path.join("/sigwood-root", "exports")


def test_resolve_path_relative_with_tilde_root_expanduser_then_join(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(fake_home))
    assert resolve_path("exports", "~/sigwood-root") == os.path.join(str(fake_home / "sigwood-root"), "exports")


def test_resolve_path_relative_with_empty_root_returns_as_is() -> None:
    """root="" is the CLI provenance - no root prepended. Shell semantics."""
    assert resolve_path("exports", "") == "exports"


# ── trailing-slash preservation across branches ───────────────────────────────


def test_resolve_path_preserves_trailing_slash_absolute() -> None:
    assert resolve_path("/var/log/zeek/", "") == "/var/log/zeek/"


def test_resolve_path_preserves_trailing_slash_tilde(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    # Must end in a "/" so be_like_water downstream sees directory intent.
    result = resolve_path("~/exports/", "")
    assert result.endswith("/")


def test_resolve_path_preserves_trailing_slash_relative_root_join() -> None:
    result = resolve_path("exports/", "/sigwood-root")
    assert result == os.path.join("/sigwood-root", "exports/")
    assert result.endswith("/")


# ── effective_root precedence: env > config > "" ──────────────────────────────


def test_effective_root_env_wins_over_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGWOOD_ROOT", "/from-env")
    config = {"sigwood": {"root": "/from-config"}}
    assert effective_root(config) == "/from-env"


def test_effective_root_falls_back_to_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    config = {"sigwood": {"root": "/from-config"}}
    assert effective_root(config) == "/from-config"


def test_effective_root_empty_when_neither_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    config = {"sigwood": {}}
    assert effective_root(config) == ""


def test_effective_root_empty_when_config_root_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty config root reads as 'no root' - env fallback applies."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    config = {"sigwood": {"root": ""}}
    assert effective_root(config) == ""
