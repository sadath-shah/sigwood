"""Protocol detector - per-protocol autoencoder on connection metadata. (planned)

Trains a per-protocol autoencoder on connection feature vectors derived from
Zeek conn.log. High reconstruction error indicates anomalous session behavior
for that protocol. Requires session-level feature data.
"""

from __future__ import annotations

from sigwood.common.finding import DetectorContext, Finding

DETECTOR_NAME = "protocol"
STATUS = "planned"

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "conn*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG: dict = {}


def run(context: DetectorContext) -> list[Finding]:
    """Detect anomalous sessions using per-protocol autoencoder reconstruction error."""
    raise NotImplementedError("protocol detector is planned - not yet implemented")
