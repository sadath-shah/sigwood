"""Low-level filesystem primitives for the loader package (leaf module).

Decompression-transparent file opening plus the path-normalization helpers
(``_safe_resolve`` / ``_union_dedupe``). These are the lowest leaf: every other
loader submodule may import from here, and this module imports nothing from the
package. ``_open_log`` is the SINGLE chokepoint every source flows through.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
from pathlib import Path


def _open_log(path: Path):
    """Open a plain, gzip-, bzip2-, or xz-compressed log file for reading.

    Suffix-gated (NOT magic-authoritative - the blob profiler is the magic-sniff
    context; the loader routes by suffix, keeping the two contexts distinct).
    `_open_log` is the SINGLE chokepoint every source flows through, so adding a
    new format here closes the gap across conn/dns/syslog/pihole/cloudtrail/sniff
    in one place.
    """
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".xz":
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _safe_resolve(p: Path) -> Path:
    """``p.resolve()``, falling back to ``p`` on ``OSError``.

    The single realpath-normalization primitive the loader uses for dedupe,
    the rotation-windowing explicit-file partition, and rotation grouping -
    one consistent notion of "same path" across all three.
    """
    try:
        return p.resolve()
    except OSError:
        return p


def _union_dedupe(per_input_files: list[list[Path]]) -> list[Path]:
    """Concat per-input discovery results; dedupe by ``.resolve()`` preserving
    first-seen order.

    Single-ownership union point - the loader is the only place file lists
    from multiple source-dir inputs are concatenated under one family. Dedup
    by realpath catches:

    - the same file appearing in two inputs (positional pointing at a file
      that's ALSO inside a positional directory);
    - symlink farms (a non-date child of a Zeek dated dir that resolves to a
      date dir already in the list).

    First-seen order preservation keeps user-visible file ordering predictable
    (positionals before flag-supplied dirs, mirrors CLI bucket order).
    Returns the deduped list; downstream accounting (``data_size_bytes`` sums,
    warnings, ``load_*`` iteration) runs over this list so duplicates never
    double-count.
    """
    seen: set[Path] = set()
    out: list[Path] = []
    for files in per_input_files:
        for p in files:
            key = _safe_resolve(p)
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
    return out
