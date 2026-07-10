"""Weird detector - signals from Zeek weird.log and notice.log. (planned)

Surfaces Zeek's own anomaly signals: protocol violations, connection state issues,
and notice events that indicate suspicious or malformed network behavior.
"""

from __future__ import annotations

from sigwood.common.finding import DetectorContext, Finding

DETECTOR_NAME = "weird"
STATUS = "planned"

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "weird*.log*"},
]

OPTIONAL_LOGS = [
    {"source": "zeek_dir", "pattern": "notice*.log*"},
]

DEFAULT_CONFIG: dict = {}


def run(context: DetectorContext) -> list[Finding]:
    """Aggregate and score Zeek weird and notice events."""
    raise NotImplementedError("weird detector is planned - not yet implemented")
