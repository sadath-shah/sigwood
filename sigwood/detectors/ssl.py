"""SSL detector - TLS anomaly detection from Zeek ssl.log. (planned)

Flags self-signed certificates, weak cipher suites, unusual SNI patterns,
and certificate validity anomalies that may indicate malicious infrastructure.
"""

from __future__ import annotations

from sigwood.common.finding import DetectorContext, Finding

DETECTOR_NAME = "ssl"
STATUS = "planned"

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "ssl*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG: dict = {}


def run(context: DetectorContext) -> list[Finding]:
    """Detect TLS anomalies including self-signed certs and cipher outliers."""
    raise NotImplementedError("ssl detector is planned - not yet implemented")
