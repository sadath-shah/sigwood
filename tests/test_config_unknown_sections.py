"""Unknown top-level config sections are disclosed, never swallowed.

A section no reader looks up voids every setting under it: each reader fetches its
section by name, misses, and falls back to a default. Without a diagnostic the run
looks normal while reading none of the operator's configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood import cli
from sigwood.common import config as cfg

EXAMPLE_PATH = Path("sigwood/data/config_example.toml")


def _dry_run(conf: Path) -> None:
    cli.main(["hunt", f"--config={conf}", "--dry-run"])


def test_known_sections_and_provenance_sidecar_are_not_unknown() -> None:
    """A merged config carries every known section plus the ``__user_set__``
    sidecar the loader attaches; neither is a user-facing section."""
    assert cfg.unknown_sections(cfg.load(None)) == []
    assert cfg.unknown_sections({"sigwood": {}, "__user_set__": {}}) == []


def test_unknown_sections_preserve_first_seen_order() -> None:
    assert cfg.unknown_sections({"zzz": 1, "sigwood": {}, "aaa": 2}) == ["zzz", "aaa"]


def test_known_sections_derive_from_defaults() -> None:
    """Sourcing the set from ``_DEFAULTS`` is what keeps a new section from
    drifting into the unknown set."""
    assert cfg.KNOWN_SECTIONS == frozenset(cfg._DEFAULTS)


def test_shipped_example_declares_no_unknown_section() -> None:
    """The shipped template must not trip the tool's own disclosure after init."""
    assert cfg.unknown_sections(cfg.load(EXAMPLE_PATH)) == []


def test_stale_section_name_is_disclosed_not_silently_ignored(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mistyped or stale section reads as absent; the run says so on stderr."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text('[sigwod]\nzeek_dir = "/nonexistent"\n', encoding="utf-8")

    _dry_run(conf)

    assert "config: ignoring unknown section [sigwod]" in capsys.readouterr().err


def test_known_sections_emit_no_disclosure(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text(
        '[sigwood]\nzeek_dir = "/nonexistent"\n\n[allowlist]\nenabled = false\n',
        encoding="utf-8",
    )

    _dry_run(conf)

    assert "config:" not in capsys.readouterr().err


def test_two_unknown_sections_pluralize_and_keep_order(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text("[foo]\nx = 1\n\n[bar]\ny = 2\n", encoding="utf-8")

    _dry_run(conf)

    err = capsys.readouterr().err
    assert "config: ignoring unknown sections [foo], [bar]" in err


def test_disclosure_does_not_stop_the_run(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unrecognized section is an advisory, not an error: the run proceeds on
    defaults and the banner still renders to stdout."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text("[foo]\nx = 1\n", encoding="utf-8")

    _dry_run(conf)

    captured = capsys.readouterr()
    assert "config: ignoring unknown section [foo]" in captured.err
    assert "dry run" in captured.out


def test_control_bytes_in_a_quoted_section_name_are_stripped(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TOML quoted key carries arbitrary code points into a terminal sink.

    The probe token reassembles - proving the value reaches the sink - and no
    C0 / DEL / C1 code point survives, proving it is neutralized there.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    # TOML basic strings forbid raw control characters, so the file carries the
    # escapes and tomllib decodes them into real code points.
    conf.write_text(
        '["PROBE\\u001BTOKEN\\u0007SEEN\\u009B\\u007F\\u0001"]\nx = 1\n',
        encoding="utf-8",
    )

    _dry_run(conf)

    err = capsys.readouterr().err
    assert "config: ignoring unknown section [PROBETOKENSEEN]" in err
    assert not [
        ch
        for ch in err
        if (ord(ch) < 0x20 and ch != "\n") or ord(ch) == 0x7F or 0x80 <= ord(ch) <= 0x9F
    ]
