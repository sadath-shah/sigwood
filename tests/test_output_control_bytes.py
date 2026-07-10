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
