"""Integration tests for sniff_format - the loader-layer orchestrator.

Verifies file I/O integration (`_open_log`, gzip transparency), precedence,
the blob floor, and the bounded-read perf guarantee. All sample data is
synthetic per the privacy rail - RFC 5737 IPs and placeholder hostnames.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from sigwood.common import loader
from sigwood.common.loader import _SNIFF_MAX_PEEK, sniff_format, sniff_format_detailed


# ── File fixture helpers ──────────────────────────────────────────────────────

def _write(path: Path, lines: list[str]) -> None:
    path.write_text("".join(lines), encoding="utf-8")


def _write_gz(path: Path, lines: list[str]) -> None:
    path.write_bytes(gzip.compress("".join(lines).encode("utf-8")))


ZEEK_TSV_CONN_LINES = [
    "#separator \\x09\n",
    "#set_separator\t,\n",
    "#empty_field\t(empty)\n",
    "#unset_field\t-\n",
    "#path\tconn\n",
    "#open\t2026-06-01-12-00-00\n",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\n",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\n",
]

ZEEK_TSV_DNS_LINES = [
    "#separator \\x09\n",
    "#path\tdns\n",
    "#fields\tts\tuid\tid.orig_h\tquery\n",
    "#types\ttime\tstring\taddr\tstring\n",
]

ZEEK_NDJSON_CONN_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",'
    ' "id.resp_p": 443, "proto": "tcp", "duration": 1.23}\n'
)

ZEEK_NDJSON_DNS_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "query": "example.test"}\n'
)

CLOUDTRAIL_NDJSON_LINE = json.dumps({
    "eventVersion":    "1.08",
    "eventTime":       "2026-06-01T12:00:00Z",
    "userIdentity":    {"type": "IAMUser"},
    "eventName":       "GetObject",
    "eventSource":     "s3.amazonaws.com",
    "sourceIPAddress": "192.0.2.10",
}) + "\n"

CLOUDTRAIL_ENVELOPE_PAYLOAD = json.dumps({
    "Records": [
        {
            "eventVersion":    "1.08",
            "eventTime":       "2026-06-01T12:00:00Z",
            "userIdentity":    {"type": "IAMUser"},
            "eventName":       "GetObject",
            "eventSource":     "s3.amazonaws.com",
            "sourceIPAddress": "192.0.2.10",
        }
    ]
}, indent=2) + "\n"

DNSMASQ_LINES = [
    "Jun  1 12:00:00 piholehost dnsmasq[123]: query[A] example.test from 192.0.2.10\n",
    "Jun  1 12:00:01 piholehost dnsmasq[123]: forwarded example.test to 198.51.100.53\n",
]

SYSLOG_LINES = [
    "<13>Jun  1 12:00:00 examplehost sshd[1234]: Accepted publickey for placeholder\n",
    "Jun  1 12:00:01 examplehost cron[5678]: (root) CMD (placeholder)\n",
]


# ── Per-format classification ─────────────────────────────────────────────────

def test_sniff_format_zeek_tsv_conn(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    _write(path, ZEEK_TSV_CONN_LINES)
    assert sniff_format(path) == "conn"


def test_sniff_format_zeek_tsv_dns(tmp_path: Path) -> None:
    path = tmp_path / "dns.log"
    _write(path, ZEEK_TSV_DNS_LINES)
    assert sniff_format(path) == "dns"


def test_sniff_format_zeek_ndjson_conn(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    _write(path, [ZEEK_NDJSON_CONN_LINE])
    assert sniff_format(path) == "conn"


def test_sniff_format_zeek_ndjson_dns(tmp_path: Path) -> None:
    path = tmp_path / "dns.log"
    _write(path, [ZEEK_NDJSON_DNS_LINE])
    assert sniff_format(path) == "dns"


def test_sniff_format_cloudtrail_ndjson(tmp_path: Path) -> None:
    path = tmp_path / "cloudtrail.json.log"
    _write(path, [CLOUDTRAIL_NDJSON_LINE])
    assert sniff_format(path) == "cloudtrail"


def test_sniff_format_cloudtrail_envelope(tmp_path: Path) -> None:
    path = tmp_path / "cloudtrail.json"
    path.write_text(CLOUDTRAIL_ENVELOPE_PAYLOAD, encoding="utf-8")
    assert sniff_format(path) == "cloudtrail"


def test_sniff_format_cloudtrail_envelope_gz(tmp_path: Path) -> None:
    # Exercises the _open_log gzip path in the orchestrator end-to-end.
    path = tmp_path / "cloudtrail.json.gz"
    path.write_bytes(gzip.compress(CLOUDTRAIL_ENVELOPE_PAYLOAD.encode("utf-8")))
    assert sniff_format(path) == "cloudtrail"


def test_sniff_format_dnsmasq(tmp_path: Path) -> None:
    path = tmp_path / "pihole.log"
    _write(path, DNSMASQ_LINES)
    assert sniff_format(path) == "dns"


def test_sniff_format_syslog(tmp_path: Path) -> None:
    path = tmp_path / "syslog"
    _write(path, SYSLOG_LINES)
    assert sniff_format(path) == "syslog"


def test_sniff_format_zeek_tsv_gz(tmp_path: Path) -> None:
    path = tmp_path / "conn.log.gz"
    _write_gz(path, ZEEK_TSV_CONN_LINES)
    assert sniff_format(path) == "conn"


# ── Ambiguity / precedence ────────────────────────────────────────────────────

def test_zeek_ndjson_not_claimed_as_cloudtrail(tmp_path: Path) -> None:
    # A Zeek NDJSON conn line is JSON but lacks CT event keys - cloudtrail
    # must not claim it; the zeek recognizer downstream wins.
    path = tmp_path / "conn.log"
    _write(path, [ZEEK_NDJSON_CONN_LINE])
    assert sniff_format(path) == "conn"


def test_cloudtrail_event_not_claimed_as_zeek(tmp_path: Path) -> None:
    # A CloudTrail per-event NDJSON line is JSON but lacks Zeek's key sets
    # - the cloudtrail recognizer wins (precedence: cloudtrail before zeek).
    path = tmp_path / "events.json.log"
    _write(path, [CLOUDTRAIL_NDJSON_LINE])
    assert sniff_format(path) == "cloudtrail"


def test_zeek_ndjson_notice_no_path_routes_to_blob(tmp_path: Path) -> None:
    # notice.log-shaped pathless NDJSON: carries the conn 5-tuple via
    # id.* AND its own native src/dst (the original incident shape).
    # The Layer-2 conn fallback rejects the rename-collision; sniff
    # returns None and the orchestrator drops to the blob floor.
    line = (
        '{"ts": 1779750000.0, "uid": "Cxxxxxx",'
        ' "id.orig_h": "192.0.2.10", "id.orig_p": 41514,'
        ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
        ' "src": "192.0.2.10", "dst": "198.51.100.20",'
        ' "note": "Placeholder::Note", "msg": "placeholder message"}\n'
    )
    path = tmp_path / "notice.log"
    _write(path, [line])
    assert sniff_format(path) == "blob"


def test_dnsmasq_wins_over_syslog(tmp_path: Path) -> None:
    # Dnsmasq IS RFC 3164 - both recognizers would match at the
    # recognizer level. The orchestrator runs dnsmasq first.
    path = tmp_path / "pihole.log"
    _write(path, DNSMASQ_LINES)
    assert sniff_format(path) == "dns"


# ── Blob floor ────────────────────────────────────────────────────────────────

def test_sniff_format_unrecognized_text_returns_blob(tmp_path: Path) -> None:
    path = tmp_path / "mystery.txt"
    _write(path, ["hello world\n", "this is not a log\n", "lorem ipsum\n"])
    assert sniff_format(path) == "blob"


def test_sniff_format_empty_file_returns_blob(tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")
    assert sniff_format(path) == "blob"


def test_sniff_format_blanks_only_returns_blob(tmp_path: Path) -> None:
    path = tmp_path / "blanks.log"
    _write(path, ["\n", "\n", "  \n"])
    assert sniff_format(path) == "blob"


# ── Bounded-read perf guarantee ───────────────────────────────────────────────

class _CountingHandle:
    """Context-manager iterator that counts how many lines were pulled."""

    def __init__(self, lines):
        self._iter = iter(lines)
        self.read_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __iter__(self):
        return self

    def __next__(self):
        line = next(self._iter)
        self.read_count += 1
        return line


def test_sniff_format_caps_reads_at_max_peek(monkeypatch, tmp_path: Path) -> None:
    """Orchestrator pulls at most _SNIFF_MAX_PEEK lines, even for huge inputs."""
    over_budget_count = _SNIFF_MAX_PEEK + 100_000
    lines = (f"random text line {i}\n" for i in range(over_budget_count))
    handle = _CountingHandle(lines)

    def fake_open_log(path):
        return handle

    monkeypatch.setattr(loader, "_open_log", fake_open_log)
    result = sniff_format(tmp_path / "fake")

    assert result == "blob"
    assert handle.read_count == _SNIFF_MAX_PEEK


def test_sniff_format_pulls_only_as_many_lines_as_file_has(
    monkeypatch, tmp_path: Path
) -> None:
    """When the file is smaller than the budget, only the file's lines are pulled."""
    short_lines = ["hello\n", "world\n", "shorter than budget\n"]
    assert len(short_lines) < _SNIFF_MAX_PEEK
    handle = _CountingHandle(short_lines)

    def fake_open_log(path):
        return handle

    monkeypatch.setattr(loader, "_open_log", fake_open_log)
    result = sniff_format(tmp_path / "fake")

    assert result == "blob"
    assert handle.read_count == len(short_lines)


# ── sniff_format_detailed: schema + origin + empty-state ─────────────────────

def test_detailed_zeek_ndjson_conn_origin_zeek(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    _write(path, [ZEEK_NDJSON_CONN_LINE])
    result = sniff_format_detailed(path)
    assert result.state == "classified"
    assert result.schema == "conn"
    assert result.origin == "zeek"


def test_detailed_zeek_ndjson_dns_origin_zeek(tmp_path: Path) -> None:
    path = tmp_path / "dns.log"
    _write(path, [ZEEK_NDJSON_DNS_LINE])
    result = sniff_format_detailed(path)
    assert result.state == "classified"
    assert result.schema == "dns"
    assert result.origin == "zeek"


def test_detailed_dnsmasq_origin_pihole(tmp_path: Path) -> None:
    path = tmp_path / "pihole.log"
    _write(path, DNSMASQ_LINES)
    result = sniff_format_detailed(path)
    assert result.state == "classified"
    assert result.schema == "dns"
    assert result.origin == "pihole"


def test_detailed_cloudtrail_origin_cloudtrail(tmp_path: Path) -> None:
    path = tmp_path / "cloudtrail.json.log"
    _write(path, [CLOUDTRAIL_NDJSON_LINE])
    result = sniff_format_detailed(path)
    assert result.state == "classified"
    assert result.schema == "cloudtrail"
    assert result.origin == "cloudtrail"


def test_detailed_syslog_origin_syslog(tmp_path: Path) -> None:
    path = tmp_path / "syslog"
    _write(path, SYSLOG_LINES)
    result = sniff_format_detailed(path)
    assert result.state == "classified"
    assert result.schema == "syslog"
    assert result.origin == "syslog"


def test_detailed_zero_byte_file_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")
    result = sniff_format_detailed(path)
    assert result.state == "empty"
    assert result.schema is None
    assert result.origin is None


def test_detailed_short_whitespace_only_file_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "blanks.log"
    _write(path, ["\n", "  \n", "\t\n"])
    result = sniff_format_detailed(path)
    assert result.state == "empty"
    assert result.schema is None


def test_detailed_long_whitespace_falls_to_blob_not_empty(
    monkeypatch, tmp_path: Path
) -> None:
    """More leading-whitespace lines than the bounded peek can prove → blob, not empty.

    The EOF probe cannot confirm the file is truly empty when it has more
    content past the peek. Whitespace beyond what we read must NOT short-
    circuit to the empty path. Locks the EOF-sensitive contract.
    """
    # Yield _SNIFF_MAX_PEEK whitespace lines followed by more whitespace -
    # the EOF probe will pull one extra line, so EOF is not reached and
    # the result must NOT be "empty".
    extra_whitespace = (f"   \n" for _ in range(_SNIFF_MAX_PEEK + 5))
    handle = _CountingHandle(extra_whitespace)

    def fake_open_log(path):
        return handle

    fake_path = tmp_path / "fake"
    fake_path.write_text("placeholder", encoding="utf-8")  # nonzero size to pass stat()
    monkeypatch.setattr(loader, "_open_log", fake_open_log)
    result = sniff_format_detailed(fake_path)
    assert result.state == "classified"
    assert result.schema == "blob"
    assert result.origin is None
    # Peek + 1 EOF probe; never more.
    assert handle.read_count == _SNIFF_MAX_PEEK + 1


def test_detailed_unrecognized_text_is_blob(tmp_path: Path) -> None:
    path = tmp_path / "mystery.txt"
    _write(path, ["hello world\n", "this is not a log\n"])
    result = sniff_format_detailed(path)
    assert result.state == "classified"
    assert result.schema == "blob"
    assert result.origin is None
