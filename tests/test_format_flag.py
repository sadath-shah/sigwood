"""CLI ``--format`` / ``-f`` format-selection flag."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import sigwood.cli as cli
import sigwood.common.config as cfg

_CONN = """\
#separator \\x09
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount
1717243200.0\tC1\t192.0.2.10\t1234\t192.0.2.20\t443\ttcp\t0.5\t100
"""


@pytest.fixture
def zeek_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    d = tmp_path / "zeek"
    d.mkdir()
    (d / "conn.log").write_text(_CONN, encoding="utf-8")
    return d


def _run(args: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = cli._main(args)
    except SystemExit as exc:  # operational errors exit via SystemExit
        rc = exc.code
    return rc, buf.getvalue()


def test_format_json_runs_end_to_end(zeek_dir: Path) -> None:
    rc, out = _run(["beacon", f"--zeek-dir={zeek_dir}", "--format=json", "--all"])
    assert rc == 0
    payload = json.loads(out)
    assert set(payload) >= {"sigwood_version", "schema_version", "run_summary", "findings"}


def test_short_f_flag_runs_end_to_end(zeek_dir: Path) -> None:
    rc, out = _run(["beacon", f"--zeek-dir={zeek_dir}", "-f=json", "--all"])
    assert rc == 0
    json.loads(out)  # valid JSON - the short form routes identically


def test_old_output_flag_is_now_rejected(
    zeek_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["beacon", f"--zeek-dir={zeek_dir}", "--output=json", "--all"])
    assert exc.value.code == 1
    assert "unknown flag --output" in capsys.readouterr().err


def test_format_appears_in_verb_help(capsys: pytest.CaptureFixture[str]) -> None:
    cli._main(["beacon", "--help"])
    out = capsys.readouterr().out
    assert "--format" in out
    assert "-f" in out
    assert "FORMAT" in out


def test_config_output_format_drives_default(
    zeek_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No --format on the CLI → the config's output_format wins.
    monkeypatch.setattr(cli.cfg, "load", lambda _=None: {"sigwood": {"output_format": "json"}})
    rc, out = _run(["beacon", f"--zeek-dir={zeek_dir}", "--all"])
    assert rc == 0
    json.loads(out)  # default came from config output_format=json
