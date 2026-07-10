"""Output-surface control-code neutralization helpers."""

from __future__ import annotations

_CONTROL_CODEPOINTS = (
    tuple(range(0x00, 0x20))
    + (0x7F,)
    + tuple(range(0x80, 0xA0))
    # os.fsdecode maps a non-UTF-8 filename byte (0x80-0xFF) to a lone surrogate
    # U+DC80-U+DCFF; deleting the range stops it re-encoding to a raw control byte
    # on a surrogateescape output stream.
    + tuple(range(0xDC80, 0xDD00))
)

_CONTROL_DELETE = {codepoint: None for codepoint in _CONTROL_CODEPOINTS}
_CONTROL_DELETE_KEEP_NEWLINES = {
    codepoint: None
    for codepoint in _CONTROL_CODEPOINTS
    if codepoint != ord("\n")
}


def strip_control(value: object) -> str:
    """Strip C0, DEL, C1, and surrogate-escaped filesystem bytes (U+DC80-U+DCFF)
    from an output value."""
    return str(value).translate(_CONTROL_DELETE)


def strip_control_keep_newlines(value: object) -> str:
    """Strip control code points and surrogate-escaped filesystem bytes from an
    output value while preserving newlines."""
    return str(value).translate(_CONTROL_DELETE_KEEP_NEWLINES)
