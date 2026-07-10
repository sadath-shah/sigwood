"""Unit tests for the be_like_water target resolver.

Gated ladder, evaluated in order - a winning gate decides without falling
through:

  Step 0 (gate): trailing slash -> DIRECTORY. No disk consult.
  Step 1: exists and is_file()  -> FILE.
  Step 2: exists and is_dir()   -> DIRECTORY.
  Step 3: does not exist        -> FILE (basename is the filename; parent
                                  will be mkdir-p'd at write).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood.common.paths import ResolvedTarget, be_like_water


def test_trailing_slash_gate_wins_over_existing_file(tmp_path: Path) -> None:
    """Step 0: a target with a trailing slash is DIRECTORY even when a file
    by that exact name exists on disk. The gate runs before disk reads."""
    f = tmp_path / "X"
    f.write_text("preexisting file content", encoding="utf-8")
    assert f.is_file()  # confirm the file exists

    result = be_like_water(f"{f}/")   # trailing slash forces directory verdict
    assert result == ResolvedTarget(Path(f"{f}/").expanduser(), is_file=False)
    # User intent (trailing slash) wins over disk state.


def test_existing_file_resolves_to_file(tmp_path: Path) -> None:
    """Step 1: an existing file with no trailing slash -> FILE at that path."""
    f = tmp_path / "events.log"
    f.write_text("data", encoding="utf-8")
    result = be_like_water(str(f))
    assert result.is_file is True
    assert result.path == f


def test_existing_directory_resolves_to_directory(tmp_path: Path) -> None:
    """Step 2: an existing directory with no trailing slash -> DIRECTORY."""
    d = tmp_path / "reports"
    d.mkdir()
    result = be_like_water(str(d))
    assert result.is_file is False
    assert result.path == d


def test_not_exists_resolves_to_file(tmp_path: Path) -> None:
    """Step 3: a path that does not exist -> FILE named by the last segment."""
    target = tmp_path / "missing" / "leaf"
    assert not target.exists()
    result = be_like_water(str(target))
    assert result.is_file is True
    assert result.path == target
    # Verify NO directory was created during resolution - that's a write-time concern.
    assert not target.parent.exists()


def test_trailing_slash_on_nonexistent_resolves_to_directory(tmp_path: Path) -> None:
    """Step 0 (gate): trailing slash on a non-existent path -> DIRECTORY."""
    target = tmp_path / "a" / "b" / "c"
    assert not target.exists()
    result = be_like_water(f"{target}/")
    assert result.is_file is False
    # Note: Path() normalizes trailing slashes, so result.path equals the
    # unsuffixed equivalent - but the verdict is still DIRECTORY.
    assert result.path == target
    # Resolver did not create anything.
    assert not target.exists()


def test_tilde_reports_consequence(monkeypatch, tmp_path: Path) -> None:
    """Explicit consequence: only trailing slash, or an already-existing directory,
    yields directory behavior. `--out=~/reports` (no trailing slash, not exists)
    creates a FILE named "reports" (after mkdir -p of the parent at write time).
    This is the surprising-but-consistent behavior we lock down.
    """
    # Force ~ to expand to a tmp location so the test does not touch the real HOME.
    monkeypatch.setenv("HOME", str(tmp_path))
    result = be_like_water("~/reports")
    assert result.is_file is True   # NOT a directory verdict
    assert result.path == tmp_path / "reports"


def test_expanduser_applied_to_both_branches(monkeypatch, tmp_path: Path) -> None:
    """expanduser is applied for both the trailing-slash gate and the disk-conform paths."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Trailing slash:
    dir_result = be_like_water("~/foo/")
    assert dir_result.path == tmp_path / "foo"
    assert dir_result.is_file is False
    # No trailing slash, not exists:
    file_result = be_like_water("~/foo")
    assert file_result.path == tmp_path / "foo"
    assert file_result.is_file is True


def test_resolved_target_path_is_pathlib_path(tmp_path: Path) -> None:
    """ResolvedTarget.path is a Path object, not a str - callers depend on it."""
    result = be_like_water(str(tmp_path))   # tmp_path exists, is dir
    assert isinstance(result.path, Path)
    assert isinstance(result.is_file, bool)
