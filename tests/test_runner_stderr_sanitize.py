"""Runner stderr diagnostics neutralize terminal control bytes.

Untrusted filenames / directory names from a scanned tree reach the runner's stderr
diagnostic seams; a name embedding ESC / OSC / BEL would forge or hide terminal output.
Every runner-owned ``print(..., file=sys.stderr)`` routes through the ``_estderr`` choke
point, which strips the C0 / DEL / C1 control class while leaving printable text intact.

These probes drive the REAL cli.main / run_digest path with fixtures whose NAMES carry
control bytes, and assert that the captured stderr carries no terminal control bytes other
than newline line-terminators (``strip_control_keep_newlines(err) == err``) AND that a harmless
marker substring survives - proving the bytes are stripped, not that the line vanished.
All log content is RFC 5737 documentation space.
"""

from __future__ import annotations

import io

import pytest

from sigwood import cli, runner
from sigwood.common import config as cfg
from sigwood.outputs._sanitize import strip_control_keep_newlines

ESC = "\x1b"
BEL = "\x07"
CLEAR = f"{ESC}[2J"        # ANSI clear-screen
OSC = f"{ESC}]0;PWN{BEL}"  # OSC terminal-retitle

# A clean single-row Zeek conn.log TSV (loads without warnings).
_CONN_TSV_CLEAN = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
    "1779750000.000000\tCXX\t192.0.2.10\t1000\t192.0.2.20\t53\tudp\n"
)
# Same header + one ragged data line (too few fields) -> a bad-lines warning.
_CONN_TSV_RAGGED = _CONN_TSV_CLEAN + "1779750001.000000\tCYY\tRAGGED\n"


def _run_cli(argv: list[str]) -> None:
    """Drive the real CLI, swallowing the exit code (clean runs return, errors sys.exit).

    The probes assert on captured stderr content, not the exit status.
    """
    try:
        cli.main(argv)
    except SystemExit:
        pass


def _assert_neutralized_and_survives(err: str, marker: str) -> None:
    """No terminal control bytes present (newline line-terminators excepted); marker kept.

    ``print`` appends a legitimate ``\\n`` after the line is stripped, so the honest
    invariant is "the only control characters on stderr are newlines"
    (``strip_control_keep_newlines``), not the newline-forbidding ``strip_control``.
    """
    assert strip_control_keep_newlines(err) == err, (
        f"raw control bytes survived on stderr: {err!r}"
    )
    assert ESC not in err and BEL not in err
    assert marker in err, f"marker {marker!r} did not survive in: {err!r}"


# ── the choke point ─────────────────────────────────────────────────────────

def test_estderr_strips_control_keeps_text(capsys: pytest.CaptureFixture[str]) -> None:
    runner._estderr(f"{CLEAR}mark{BEL}")
    err = capsys.readouterr().err
    assert err == "[2Jmark\n"  # ESC + BEL gone; printable text + newline kept
    assert strip_control_keep_newlines(err) == err


# ── three end-to-end probes through the real CLI / runner ───────────────────

def test_stderr_skip_reason_hostile_dir_neutralized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A hostile zeek_dir NAME reaching the :1039 skip reason is neutralized."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    hostile = tmp_path / f"zeekdir{CLEAR}MARKER_A{BEL}"
    hostile.mkdir()  # exists, holds no conn*.log* -> beacon skips
    _run_cli(["beacon", f"--zeek-dir={hostile}"])
    _assert_neutralized_and_survives(capsys.readouterr().err, "MARKER_A")


def test_stderr_looks_binary_hostile_file_neutralized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A hostile pihole FILE name reaching the :287 looks-binary warning is neutralized.

    zeek_dir is overridden to an empty directory so the test loads no ambient logs and the
    dns clustering child never spawns.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    empty_zeek = tmp_path / "zeek_empty"
    empty_zeek.mkdir()
    pihole = tmp_path / "pihole"
    pihole.mkdir()
    evil = pihole / f"pihole{OSC}MARKER_B.log"  # pihole*.log* glob selects it
    evil.write_bytes(b"\x00\x01\x02\xff\xfe binary garbage \x00")
    _run_cli(["dns", f"--zeek-dir={empty_zeek}", f"--pihole-dir={pihole}"])
    _assert_neutralized_and_survives(capsys.readouterr().err, "MARKER_B")


def test_stderr_digest_warnings_loop_hostile_file_neutralized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A hostile conn FILE name reaching the digest :2114 warnings loop is neutralized."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conn = tmp_path / f"conn{CLEAR}MARKER_C{BEL}.log"
    conn.write_text(_CONN_TSV_RAGGED, encoding="utf-8")  # one ragged line -> warning
    _run_cli(["digest", str(conn)])
    _assert_neutralized_and_survives(capsys.readouterr().err, "MARKER_C")


# ── focused per-site pin: the digest fallback breadcrumb (:2239) ────────────

def test_digest_fallback_breadcrumb_neutralized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The richest site: the breadcrumb carries BOTH a hostile fallback filename AND {exc}.

    A clean conn.log loads a frame; a monkeypatched summariser raises with control bytes in
    its message; the fallback_blob_path name carries control bytes too. Both are neutralized.
    """
    data = tmp_path / "data"
    data.mkdir()
    (data / "conn.log").write_text(_CONN_TSV_CLEAN, encoding="utf-8")
    hostile = tmp_path / f"conn{CLEAR}MARKER_D{BEL}.log"
    hostile.write_text("orientation sample\n", encoding="utf-8")

    def _boom(frame, *args, **kwargs):
        raise ValueError(f"boom{OSC}payload")

    monkeypatch.setattr("sigwood.digest.get_summarizer", lambda schema: _boom)
    runner.run_digest(
        config={"sigwood": {"root": str(tmp_path)}},
        zeek_dir=str(data),
        schema="conn",
        fallback_blob_path=hostile,
        verbose_level=1,
        quiet=True,
        stream=io.StringIO(),  # blob card goes here, not stdout
    )
    err = capsys.readouterr().err
    assert strip_control_keep_newlines(err) == err
    assert ESC not in err and BEL not in err
    assert "MARKER_D" in err  # hostile filename survives (stripped, not vanished)
    assert "payload" in err   # hostile exception text survives
