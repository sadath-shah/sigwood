"""Dnsblock detector - behavioral anomalies in blocked DNS query patterns. (planned)

Surfaces who is querying known-bad domains, how often, with what
persistence, and across what spread of clients. Complements the dns
detector: DNS clustering finds *unknown-bad* domains by behavioral
fingerprint; dnsblock finds *known-bad-domain access patterns* by client
behavior. Pi-hole/dnsmasq only - needs the `was_blocked` column that
Zeek does not carry.
"""

from __future__ import annotations

from sigwood.common.finding import DetectorContext, Finding

DETECTOR_NAME = "dnsblock"
STATUS = "planned"

REQUIRED_LOGS = [
    {"source": "pihole_dir", "pattern": "pihole*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG: dict = {}


def run(context: DetectorContext) -> list[Finding]:
    """Detect behavioral anomalies in blocked DNS query patterns."""
    raise NotImplementedError("dnsblock detector is planned - not yet implemented")
