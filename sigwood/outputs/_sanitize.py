"""Re-export of the control-code sanitizer for output-surface callers.

The delete maps and both functions are owned by ``sigwood.common.sanitize`` (a
leaf every layer can import). Output-local modules keep importing from here.
"""

from __future__ import annotations

from sigwood.common.sanitize import strip_control, strip_control_keep_newlines

__all__ = ["strip_control", "strip_control_keep_newlines"]
