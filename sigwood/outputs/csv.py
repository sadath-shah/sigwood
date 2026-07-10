"""CSV output handler - a remediation WORKLIST for triage.

Not the lossless surface (json owns lossless). One row per finding, a fixed
worklist column set, human-readable cells (no JSON brackets), seeded-empty
``status`` / ``notes`` columns for the analyst to fill. Verbosity-INVARIANT
(a checklist's columns don't move with ``-v``) and NEVER capped - a worklist
that silently drops rows is dangerous.
"""

from __future__ import annotations

import csv
import sys
from typing import Any, TextIO

from sigwood.common.display import to_display_timezone
from sigwood.common.finding import Finding, RunSummary
from sigwood.common.output import OutputHandler, register_handler
from sigwood.outputs._evidence import curated_evidence
from sigwood.outputs._sanitize import strip_control_keep_newlines
from sigwood.outputs._serialize import jsonable_to_human, to_jsonable

_FIELDNAMES = [
    "severity",
    "detector",
    "finding",
    "next_steps",
    "description",
    "signals",
    "data_window_start",
    "data_window_end",
    "status",
    "notes",
]
_CSV_FORMULA_PREFIXES = "=+-@\t\r"


def _csv_safe(value: str) -> str:
    """Prefix spreadsheet-formula-looking cells with an apostrophe."""
    if value and value[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


class CsvHandler(OutputHandler):
    """Write findings as a fixed-column CSV worklist to stdout or a file."""

    def __init__(self, stream: TextIO = sys.stdout, verbose_level: int = 0) -> None:
        # verbose_level is accepted for registry uniformity but UNUSED - the csv
        # worklist is verbosity-invariant (fixed column set at every level).
        self._stream = stream
        self._verbose_level = verbose_level
        self._rows: list[dict[str, Any]] = []
        self._run_summary: RunSummary | None = None

    def begin(self, run_summary: RunSummary) -> None:
        """Store run metadata (unused in rows today; kept for symmetry)."""
        self._run_summary = run_summary

    def write(self, findings: list[Finding]) -> None:
        """Build one worklist row per finding."""
        self._rows.extend(self._row(f) for f in findings)

    def end(self) -> None:
        """Write the header and all rows. Never capped."""
        # csv requires the underlying stream be opened newline="" or embedded
        # newlines in quoted cells (multi-step next_steps) get mangled on
        # newline-translating platforms (Windows text-mode stdout). The runner's
        # FILE path already opens newline=""; reconfigure a reconfigurable stream
        # (e.g. sys.stdout) so the piped path is safe too. StringIO (tests) has no
        # reconfigure and needs none.
        reconfigure = getattr(self._stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(newline="")
            except (ValueError, OSError):
                pass
        writer = csv.DictWriter(self._stream, fieldnames=_FIELDNAMES)
        writer.writeheader()
        for row in self._rows:
            writer.writerow(row)

    def _row(self, finding: Finding) -> dict[str, Any]:
        """One worklist row. ``status`` / ``notes`` seeded EMPTY (analyst-filled)."""
        row = {
            "severity": finding.severity.name.lower(),
            "detector": finding.detector,
            "finding": finding.title,
            "next_steps": "\n".join(finding.next_steps),
            "description": finding.description,
            "signals": self._signals(finding),
            # ISO-8601 with the display-timezone offset (the single tz
            # conversion point; local by default, +00:00 under --utc/use_utc).
            "data_window_start": to_display_timezone(finding.data_window[0]).isoformat(),
            "data_window_end": to_display_timezone(finding.data_window[1]).isoformat(),
            "status": "",
            "notes": "",
        }
        return {
            key: _csv_safe(strip_control_keep_newlines(value))
            if isinstance(value, str) else value
            for key, value in row.items()
        }

    @staticmethod
    def _signals(finding: Finding) -> str:
        """Curated evidence as ``k=v; k=v`` human cells (no JSON brackets).

        Each value is normalised by ``to_jsonable`` then rendered by the shared
        ``jsonable_to_human``; an empty curated set yields an empty cell.
        """
        cells = [
            f"{key}={jsonable_to_human(to_jsonable(value), item_sep=',', kv_sep=':')}"
            for key, value in curated_evidence(finding).items()
        ]
        return "; ".join(cells)


register_handler("csv", CsvHandler)
