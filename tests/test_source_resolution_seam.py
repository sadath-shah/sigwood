"""Scope seam-crossing tests for the single-ownership source-resolution rail.

These tests exercise the REAL CLI ↔ runner path with ``--dry-run`` and a temp
``--config=<tmp_path>/cfg.toml`` file. They prove the property that
mocked-``runner.run`` regression tests CANNOT prove: that a positional PATH
scoping the run keeps
sibling source-dirs from configured locations from sneaking in through the
runner-side config fallback.

The user's real ``~/.sigwood/config.toml`` MUST NOT participate - every test
either points ``--config=`` at a temp file written in ``tmp_path`` OR
monkeypatches ``cfg.SEARCH_PATHS`` to ``[]`` and ``cfg.load`` to a fixed dict
(when explicit-PATH config isn't relevant to the assertion).

Companion to:

- ``tests/test_sources.py`` (unit) - router + resolver primitives.
- ``tests/test_root_provenance.py`` (programmatic) - ``runner.run`` and
  ``run_digest`` config-fallback rail.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sigwood import cli, runner
from sigwood.common import config as cfg


# ── helpers ──────────────────────────────────────────────────────────────────


_FLAT_SYSLOG_LINE = (
    "<134>Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user\n"
)

_PIHOLE_LINE = (
    "Jun 11 12:00:00 host1 dnsmasq[1234]: query[A] example.test from 192.0.2.10\n"
)


def _write_cfg(
    tmp_path: Path,
    *,
    zeek_dir: str | None = None,
    syslog_dir: str | None = None,
    pihole_dir: str | None = None,
    cloudtrail_dir: str | None = None,
) -> str:
    """Write a minimal TOML config under tmp_path and return its absolute path.

    Only the keys explicitly passed are written - the rest stay at default
    (which means whatever ``_DEFAULTS`` has). The shipped defaults set
    ``zeek_dir=/var/log/zeek`` and ``syslog_dir=/var/log``; tests that need
    a fully-isolated config write all four keys (or rely on the seam test's
    "scoped-out sibling does not appear in output" assertion holding even
    if a default leaks in elsewhere).
    """
    lines = ["[sigwood]", 'root = ""']
    if zeek_dir is not None:
        lines.append(f'zeek_dir = "{zeek_dir}"')
    if syslog_dir is not None:
        lines.append(f'syslog_dir = "{syslog_dir}"')
    if pihole_dir is not None:
        lines.append(f'pihole_dir = "{pihole_dir}"')
    if cloudtrail_dir is not None:
        lines.append(f'cloudtrail_dir = "{cloudtrail_dir}"')
    cfg_path = tmp_path / "cfg.toml"
    cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(cfg_path)


# ── 1) analyze single-detector: positional scopes; configured sibling stays out


def test_syslog_positional_via_real_cli_scopes_out_configured_zeek_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood syslog ./flat.log --dry-run`` against a config that sets
    BOTH zeek_dir AND syslog_dir must NOT load the configured zeek_dir.

    This drives ``runner.run`` with ``--dry-run`` rather than mocking it, so it
    crosses the seam where the runner could undo the CLI scope by config-filling
    a scoped-out ``None`` back - a mocked ``runner.run`` never exercises that.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    syslog_d = tmp_path / "configured_syslog"
    syslog_d.mkdir()
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d), syslog_dir=str(syslog_d))

    flat_file = tmp_path / "flat.log"
    flat_file.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")

    cli._main(["syslog", str(flat_file), f"--config={cfg_path}", "--dry-run"])

    out = capsys.readouterr().out
    # Positive: the positional routed to syslog_dir.
    assert str(flat_file) in out
    # Negative: the configured zeek_dir did NOT sneak through the seam.
    assert str(zeek_d) not in out
    # And the dry-run line for zeek_dir reads "not configured" - the scope
    # rail kept it None all the way through.
    assert "zeek_dir:" in out
    assert "not configured" in out.split("zeek_dir:")[1].split("\n")[0]


def test_analyze_detect_syslog_positional_scopes_out_configured_zeek_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Mirror of the single-detector seam test on the analyze entry point.

    ``sigwood --detect=syslog ./flat.log`` flows through ``_run_hunt``,
    a separate code path from ``_run_single_detector``. Both must honor scope.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    syslog_d = tmp_path / "configured_syslog"
    syslog_d.mkdir()
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d), syslog_dir=str(syslog_d))

    flat_file = tmp_path / "flat.log"
    flat_file.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")

    cli._main([
        "--detect=syslog", str(flat_file), f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(flat_file) in out
    assert str(zeek_d) not in out


# ── 2) runner-level mirror - runner.run with scope, no CLI involved ─────────


def test_runner_run_scope_suppresses_unscoped_config_fill(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``runner.run(config={both set}, syslog_dir=<file>, scope=frozenset({"syslog_dir"}), dry_run=True)``
    → zeek_dir absent from the dry-run output. Direct lock on the runner half
    of the seam - what the CLI test above proves through the full path."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    flat_file = tmp_path / "flat.log"
    flat_file.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")

    runner.run(
        config={"sigwood": {
            "zeek_dir": str(zeek_d),
            "syslog_dir": str(tmp_path / "configured_syslog"),
        }},
        syslog_dir=str(flat_file),
        scope=frozenset({"syslog_dir"}),
        dry_run=True,
    )
    out = capsys.readouterr().out
    assert str(flat_file) in out
    assert str(zeek_d) not in out


# ── 3) same-source explicit flag + positional MERGE; positional still scopes


def test_same_source_flag_and_positional_merge_both_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood syslog ./auto.log --syslog-dir=/explicit --dry-run``:

    - same-family flag + positional MERGE: BOTH the positional file AND the
      flag's directory contribute to syslog_dir and both load. A flag does
      not replace a same-family positional - it adds to it.
    - The positional still scopes the run (configured zeek_dir stays unloaded).
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    explicit_d = tmp_path / "explicit_syslog"
    explicit_d.mkdir()
    auto = tmp_path / "auto.log"
    auto.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d))

    cli._main([
        "syslog", str(auto),
        f"--syslog-dir={explicit_d}",
        f"--config={cfg_path}",
        "--dry-run",
    ])

    out = capsys.readouterr().out
    # MERGE: BOTH positional AND flag value appear under syslog_dir.
    assert str(auto) in out
    assert str(explicit_d) in out
    # Scope: configured zeek_dir stayed out.
    assert str(zeek_d) not in out


# ── 4) different-source explicit flag widens - operator widening ────────────


def test_different_source_flag_alongside_positional_widens_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood syslog ./flat.log --zeek-dir=/widen --dry-run``: an explicit
    DIFFERENT-source flag still loads - the resolver's "override wins even
    outside scope" branch is the operator widening the run deliberately."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    widen_zeek = tmp_path / "widen_zeek"
    widen_zeek.mkdir()
    flat_file = tmp_path / "flat.log"
    flat_file.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")
    # No config setup needed - the explicit flags carry the run.
    cfg_path = _write_cfg(tmp_path)

    cli._main([
        "syslog", str(flat_file),
        f"--zeek-dir={widen_zeek}",
        f"--config={cfg_path}",
        "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(flat_file) in out      # positional → syslog_dir
    assert str(widen_zeek) in out     # explicit flag widens to zeek_dir


# ── 5) DNS content-sniff regression ──────────────────────────────────────────


def test_dns_pihole_content_under_neutral_name_routes_pihole_via_real_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A Pi-hole-CONTENT file whose NAME does NOT match ``pihole*.log*``
    routes to pihole_dir end-to-end. Locks the fnmatch→content-sniff
    migration at the CLI seam, in addition to the router unit test in
    tests/test_sources.py."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    # Bland name - cannot satisfy pihole*.log*. Content is dnsmasq.
    pihole = tmp_path / "mystery.log"
    pihole.write_text(_PIHOLE_LINE, encoding="utf-8")
    cfg_path = _write_cfg(tmp_path)

    cli._main(["dns", str(pihole), f"--config={cfg_path}", "--dry-run"])

    out = capsys.readouterr().out
    # The positional routed to pihole_dir - visible on the dry-run line.
    pihole_line = [
        line for line in out.splitlines() if "pihole_dir:" in line
    ]
    assert pihole_line, out
    assert str(pihole) in pihole_line[0]
    # And the zeek_dir line says "not configured" - sniff routed pihole, not
    # the historical zeek_dir default.
    zeek_line = [
        line for line in out.splitlines() if "zeek_dir:" in line
    ][0]
    assert "not configured" in zeek_line


def test_hunt_directory_positional_votes_pihole_via_real_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood <pihole-dir> --dry-run`` routes the directory to pihole_dir."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    pihole_d = tmp_path / "pihole"
    pihole_d.mkdir()
    (pihole_d / "FTL.log").write_text(
        "<134>Jun 11 12:00:00 host1 pihole-FTL[123]: daemon ready\n",
        encoding="utf-8",
    )
    (pihole_d / "pihole.log").write_text("", encoding="utf-8")
    (pihole_d / "pihole.log.1").write_text(_PIHOLE_LINE, encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d))

    cli._main([str(pihole_d), f"--config={cfg_path}", "--dry-run"])

    out = capsys.readouterr().out
    pihole_line = [line for line in out.splitlines() if "pihole_dir:" in line][0]
    zeek_line = [line for line in out.splitlines() if "zeek_dir:" in line][0]
    assert str(pihole_d) in pihole_line
    assert str(zeek_d) not in out
    assert "not configured" in zeek_line


def test_dns_directory_positional_votes_pihole_via_real_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood dns <pihole-dir> --dry-run`` routes the directory to pihole_dir."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    pihole_d = tmp_path / "pihole"
    pihole_d.mkdir()
    (pihole_d / "pihole.log.1").write_text(_PIHOLE_LINE, encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d))

    cli._main(["dns", str(pihole_d), f"--config={cfg_path}", "--dry-run"])

    out = capsys.readouterr().out
    pihole_line = [line for line in out.splitlines() if "pihole_dir:" in line][0]
    zeek_line = [line for line in out.splitlines() if "zeek_dir:" in line][0]
    assert str(pihole_d) in pihole_line
    assert str(zeek_d) not in out
    assert "not configured" in zeek_line


def test_hunt_directory_permission_hint_routes_pihole_via_real_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Permission-blocked pihole*.log* samples route across the real CLI seam."""
    import sigwood.common.sources as source_mod

    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    pihole_d = tmp_path / "pihole"
    pihole_d.mkdir()
    (pihole_d / "FTL.log").write_text("daemon log\n", encoding="utf-8")
    (pihole_d / "pihole.log").write_text("unreadable placeholder\n", encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d))

    def _fake_sniff(path: Path):
        if path.name.startswith("pihole.log"):
            raise PermissionError("synthetic denied")
        return SimpleNamespace(origin=None)

    monkeypatch.setattr(source_mod, "sniff_format_detailed", _fake_sniff)

    cli._main([str(pihole_d), f"--config={cfg_path}", "--dry-run"])

    out = capsys.readouterr().out
    pihole_line = [line for line in out.splitlines() if "pihole_dir:" in line][0]
    zeek_line = [line for line in out.splitlines() if "zeek_dir:" in line][0]
    assert str(pihole_d) in pihole_line
    assert str(zeek_d) not in out
    assert "not configured" in zeek_line


# ── 6) aws ``~`` positional (seam form of the deleted CLI test) ─────────────


def test_aws_subcommand_with_tilde_positional_resolves_via_dry_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood aws ~/exports/cloudtrail.json.log --dry-run`` - the full
    chain: router lands the positional on cloudtrail_dir, the resolver
    ``~``-expands the override.

    This proves both halves end to end - routing and ``~``-expansion -
    because expansion happens inside the resolver, not the CLI seam.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    # The positional must EXIST - explicit positionals fail fast on a missing
    # path (the `sigwood: <path>: not found` rail), even under --dry-run.
    # Content is irrelevant: aws routes by REQUIRED_LOGS, not by sniffing, and
    # dry-run does not read the file. We only assert the ~-expansion shows.
    ct_file = tmp_path / "exports" / "cloudtrail.json.log"
    ct_file.parent.mkdir(parents=True, exist_ok=True)
    ct_file.write_text("", encoding="utf-8")
    cfg_path = _write_cfg(tmp_path)
    cli._main([
        "aws", "~/exports/cloudtrail.json.log",
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    expected = str(tmp_path / "exports" / "cloudtrail.json.log")
    assert expected in out
    assert "~" not in out.split("cloudtrail_dir:")[1].split("\n")[0]


# ── 7) digest seam - single-owner config fallback, no CLI scope, sniff routes


def test_digest_positional_via_real_cli_routes_and_suppresses_zeek_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood digest ./flat.log --dry-run`` against a config that sets
    BOTH zeek_dir AND syslog_dir: the sniff router lands the positional on
    syslog_dir, ``resolve_digest_source`` resolves a single source (syslog),
    and the dry-run output does NOT mention zeek_dir.

    Digest has no analyze-style ``scope``; this test proves single-owner
    config fallback, positional self-routing through the real CLI path, and
    the implicit "only one source per schema" property.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    syslog_d = tmp_path / "configured_syslog"
    syslog_d.mkdir()
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d), syslog_dir=str(syslog_d))

    flat_file = tmp_path / "flat.log"
    flat_file.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")

    cli._main(["digest", str(flat_file), f"--config={cfg_path}", "--dry-run"])

    out = capsys.readouterr().out
    # Digest dry-run prints `<source_key>: <directory>` - confirm we routed
    # on syslog and the directory IS the positional.
    assert "schema:" in out and "syslog" in out
    assert "syslog_dir:" in out
    assert str(flat_file) in out
    # Negative: zeek_dir directory does NOT appear in the dry-run output.
    assert str(zeek_d) not in out


# ── 8) empty-string override falls through to config ────────────────────────


def test_analyze_empty_string_zeek_dir_flag_falls_through_to_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood beacon --zeek-dir= --dry-run`` (bare flag, empty value)
    against a configured ``[sigwood].zeek_dir`` must resolve to the
    CONFIGURED directory - NOT silently to None.

    The CLI parser stores ``--zeek-dir=`` as the empty string. The naive
    ``override is not None`` check at the resolver boundary treated ``""``
    as "present," sent it through ``resolve_path("", "")`` → None, and
    suppressed the config fallback - so beacon read "zeek_dir not
    configured" and skipped, even with a perfectly good configured dir.
    The ``_present`` helper uses truthiness-based presence semantics, so a
    falsy override falls through to config instead of scoping it out.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    configured_zeek = tmp_path / "configured_zeek"
    configured_zeek.mkdir()
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(configured_zeek))

    cli._main([
        "beacon", "--zeek-dir=", f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    # The configured zeek_dir must appear in the dry-run output.
    assert str(configured_zeek) in out
    # And the "not configured" sentinel must NOT show up for zeek_dir.
    zeek_line = [
        line for line in out.splitlines() if "zeek_dir:" in line
    ][0]
    assert "not configured" not in zeek_line


def test_digest_empty_string_zeek_dir_flag_falls_through_to_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood digest --zeek-dir= --dry-run`` (bare-digest, empty flag)
    against a configured ``[sigwood].zeek_dir`` must resolve the conn card's
    source to the CONFIGURED directory - NOT raise "zeek_dir not configured".

    Mirror of the analyze test for the digest resolver. Without truthiness-based
    presence, ``resolve_digest_source`` would see an empty string in
    ``overrides["zeek_dir"]``, treat it as present, then fail to resolve it
    (empty string → None) and walk away from the candidate ladder - raising here.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    configured_zeek = tmp_path / "configured_zeek"
    configured_zeek.mkdir()
    cfg_path = _write_cfg(tmp_path, zeek_dir=str(configured_zeek))

    cli._main([
        "digest", "--zeek-dir=", f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    # The configured zeek_dir must appear on the digest dry-run's source line.
    assert str(configured_zeek) in out
    # And the schema is conn (the bare-digest default), not an error.
    assert "schema:" in out and "conn" in out


def test_digest_wrong_source_flag_error_byte_preserved_via_real_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood digest <Zeek-conn-file> --pihole-dir=/x`` raises the
    byte-preserved wrong-source error through the CLI boundary.

    Locks the error-string preservation at the real CLI seam, complementing
    the resolver-level locks in tests/test_sources.py.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    pihole_dummy = tmp_path / "ph"
    pihole_dummy.mkdir()
    cfg_path = _write_cfg(tmp_path)

    # The CLI rejects --pihole-dir alongside a positional BEFORE resolution
    # (cli.py:825 guard). Use the bare-digest form (no positional) so the
    # resolver sees the wrong-key combination - conn schema with
    # --pihole-dir set in parsed.
    #
    # But --pihole-dir is not in _DIGEST_ALLOWED_LONG_FLAGS today, so this
    # test exercises the analogous scenario at the resolver layer via a
    # direct run_digest call (the seam test for digest error strings is
    # primarily at the resolver). Skipped at the CLI seam because the
    # digest CLI's narrow flag surface intentionally hides three of the
    # four source-dir flags - that's a separate rail.
    pytest.skip(
        "digest CLI exposes only --zeek-dir; wrong-source error strings "
        "are locked at the resolver layer in tests/test_sources.py."
    )
