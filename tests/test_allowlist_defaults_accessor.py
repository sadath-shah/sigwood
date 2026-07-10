"""Allowlist fallback paths read from the single config defaults accessor.

``common/allowlist.py`` carries no copy of default paths. When config keys are
absent (raw / notebook config), the fallback comes from
``cfg.default_allowlist_paths()`` - a deep copy of ``_DEFAULTS["allowlist"]``.
All three keys are covered: ``domain_patterns``, ``connection_rules``, and
``allowlist_dir``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood.common import allowlist, config as cfg


def test_default_allowlist_paths_returns_deep_copy_of_defaults() -> None:
    paths = cfg.default_allowlist_paths()
    assert paths == cfg._DEFAULTS["allowlist"]
    paths["domain_patterns"] = ["mutated"]
    assert cfg._DEFAULTS["allowlist"]["domain_patterns"] != ["mutated"], (
        "default_allowlist_paths must return a deep copy"
    )


def test_build_matcher_domain_patterns_fallback_uses_accessor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """When config has no domain_patterns, accessor supplies the path. Patch
    the accessor and observe the result."""
    fake = tmp_path / "fake_domains.txt"
    fake.write_text("example.com\n", encoding="utf-8")
    monkeypatch.setattr(
        cfg, "default_allowlist_paths",
        lambda: {"domain_patterns": [str(fake)], "connection_rules": [], "allowlist_dir": ""},
    )
    # Config with NO allowlist subkeys - forces the fallback.
    matcher = allowlist.build_matcher({"allowlist": {}})
    assert "example.com" in matcher._domain_patterns


def test_build_matcher_connection_rules_fallback_uses_accessor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = tmp_path / "fake_conn.txt"
    fake.write_text("192.0.2.1\n", encoding="utf-8")
    monkeypatch.setattr(
        cfg, "default_allowlist_paths",
        lambda: {"domain_patterns": [], "connection_rules": [str(fake)], "allowlist_dir": ""},
    )
    matcher = allowlist.build_matcher({"allowlist": {}})
    assert len(matcher._numeric_rules) == 1


def test_build_matcher_allowlist_dir_fallback_uses_accessor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """allowlist_dir gets the same single-source treatment."""
    fake_dir = tmp_path / "fake_allowlist.d"
    fake_dir.mkdir()
    (fake_dir / "users.toml").write_text(
        '[[allowlist.entry]]\nmatch = "example.com"\ncomment = "x"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cfg, "default_allowlist_paths",
        lambda: {
            "domain_patterns": [],
            "connection_rules": [],
            "allowlist_dir": str(fake_dir),
        },
    )
    matcher = allowlist.build_matcher({"allowlist": {}})
    assert len(matcher._entries) == 1
    assert matcher._entries[0].match == "example.com"


def test_shipped_domain_files_stay_package_local_not_routed_through_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Shipped lists (_SHIPPED_LISTS) are package data, NOT routed through
    SIGWOOD_ROOT. Setting a bogus root must not displace them."""
    monkeypatch.setenv("SIGWOOD_ROOT", str(tmp_path / "nonexistent"))
    # Build with no allowlist config - only shipped patterns load.
    matcher = allowlist.build_matcher({"allowlist": {}})
    # Shipped files include the large common list; at least one entry must load.
    # If the shipped path were routed through bogus root, they'd be absent.
    assert len(matcher._domain_patterns) > 0
