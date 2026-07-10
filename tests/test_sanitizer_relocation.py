"""Single-owner + layering guards for the control-code sanitizer.

The delete maps live only in ``sigwood.common.sanitize`` so that non-output
sinks (``common/loader``, ``exporters``) can neutralize their own output without
importing ``sigwood.outputs`` (the one-way-dependency rail). ``outputs/_sanitize``
is a re-export shim. These tests fail if the owner is duplicated (two drifting
maps) or if a ``common``/``exporters`` module imports the sanitizer through the
output shim (a layering violation).
"""

from __future__ import annotations

import ast
from pathlib import Path

import sigwood.common.sanitize as common_sanitize
import sigwood.outputs._sanitize as shim

_PKG_ROOT = Path(__file__).resolve().parent.parent / "sigwood"


def test_shim_reexports_the_common_owner_same_object() -> None:
    # A re-export, not a copy: identical objects mean one delete map, so a future
    # edit to the owner cannot leave a stale second copy behind the output shim.
    assert shim.strip_control is common_sanitize.strip_control
    assert shim.strip_control_keep_newlines is common_sanitize.strip_control_keep_newlines


def test_shim_defines_no_control_maps() -> None:
    # Zero ``_CONTROL_*`` in the shim: the maps have exactly one home.
    leaked = [name for name in vars(shim) if name.startswith("_CONTROL_")]
    assert leaked == []


def test_common_owner_holds_the_control_maps() -> None:
    for name in ("_CONTROL_CODEPOINTS", "_CONTROL_DELETE", "_CONTROL_DELETE_KEEP_NEWLINES"):
        assert hasattr(common_sanitize, name)


def _imports_output_shim(py_file: Path) -> bool:
    """True if ``py_file`` imports the sanitizer through ``outputs._sanitize``.

    AST-based so a docstring or comment that merely names the shim is not a hit -
    only an actual import statement counts.
    """
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and "outputs._sanitize" in node.module:
                return True
        elif isinstance(node, ast.Import):
            if any("outputs._sanitize" in alias.name for alias in node.names):
                return True
    return False


def test_common_and_exporters_never_import_the_output_shim() -> None:
    # The central layering guard: a ``common``/``exporters`` module reaching
    # the sanitizer through ``outputs`` would invert the one-way dependency.
    offenders = []
    for subtree in ("common", "exporters"):
        for py_file in (_PKG_ROOT / subtree).rglob("*.py"):
            if _imports_output_shim(py_file):
                offenders.append(str(py_file.relative_to(_PKG_ROOT)))
    assert offenders == []


def test_strip_control_drops_surrogate_embedded_in_a_string() -> None:
    # The delete translation removes every occurrence, not just a lone char.
    assert common_sanitize.strip_control("a\udc9bb") == "ab"


def test_multibyte_text_survives_stripping() -> None:
    # Non-control code points above U+009F (CJK, box glyphs) are never stripped.
    value = "日本語 report ▇"
    assert common_sanitize.strip_control(value) == value
    assert common_sanitize.strip_control_keep_newlines(value) == value
