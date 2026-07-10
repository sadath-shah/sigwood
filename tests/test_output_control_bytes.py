"""Shared output control-code stripping contract."""

from __future__ import annotations

from sigwood.outputs._sanitize import strip_control, strip_control_keep_newlines

_CONTROL_CODEPOINTS = (
    tuple(range(0x00, 0x20))
    + (0x7F,)
    + tuple(range(0x80, 0xA0))
)


def test_strip_control_drops_full_control_class() -> None:
    for codepoint in _CONTROL_CODEPOINTS:
        assert strip_control(chr(codepoint)) == ""


def test_strip_control_keep_newlines_preserves_only_newline() -> None:
    for codepoint in _CONTROL_CODEPOINTS:
        expected = "\n" if codepoint == ord("\n") else ""
        assert strip_control_keep_newlines(chr(codepoint)) == expected


def test_control_helpers_drift_only_on_newline() -> None:
    for codepoint in range(0x120):
        value = chr(codepoint)
        if codepoint == ord("\n"):
            assert strip_control(value) == ""
            assert strip_control_keep_newlines(value) == "\n"
        else:
            assert strip_control(value) == strip_control_keep_newlines(value)


def test_non_control_report_glyphs_survive() -> None:
    value = "flow 192.0.2.1 -> 198.51.100.2 -> ▇"
    assert strip_control(value) == value
    assert strip_control_keep_newlines(value) == value


# os.fsdecode maps a non-UTF-8 filename byte (0x80-0xFF) to a lone surrogate in
# U+DC80-U+DCFF; both strip helpers drop the whole range so it cannot re-encode to
# a raw control byte on a surrogateescape output stream.
_SURROGATE_ESCAPE_CODEPOINTS = tuple(range(0xDC80, 0xDD00))


def test_strip_control_drops_surrogate_escape_range() -> None:
    for codepoint in _SURROGATE_ESCAPE_CODEPOINTS:
        char = chr(codepoint)
        assert strip_control(char) == ""
        # No surrogate-escaped byte is a newline, so keep_newlines drops it too.
        assert strip_control_keep_newlines(char) == ""


def test_surrogate_scope_boundaries() -> None:
    # Stripped: the surrogateescape byte range only. U+DCA0 (byte 0xA0) proves the
    # range is not narrowed to the C1 subset U+DC80-U+DC9F.
    for codepoint in (0xDC80, 0xDC9B, 0xDCA0, 0xDCFF):
        assert strip_control(chr(codepoint)) == ""
        assert strip_control_keep_newlines(chr(codepoint)) == ""
    # Survive: outside the surrogateescape byte range. U+DC7F / U+DD00 bracket the
    # range; U+D800 is a high surrogate. Guards against broad surrogate erasure.
    for codepoint in (0xDC7F, 0xDD00, 0xD800):
        assert strip_control(chr(codepoint)) == chr(codepoint)
        assert strip_control_keep_newlines(chr(codepoint)) == chr(codepoint)
