"""Auth detector - authentication pattern analysis from syslog. (planned)

Analyzes auth.log and secure log files for brute-force attempts, unusual
authentication patterns, privilege escalation, and new account activity.
"""

from __future__ import annotations

from sigwood.common.finding import DetectorContext, Finding

DETECTOR_NAME = "auth"
STATUS = "planned"

REQUIRED_LOGS = [
    {"source": "syslog_dir", "pattern": "auth.log*"},
]

OPTIONAL_LOGS = [
    {"source": "syslog_dir", "pattern": "secure*"},
]

DEFAULT_CONFIG: dict = {}


def run(context: DetectorContext) -> list[Finding]:
    """Detect anomalous authentication patterns in syslog auth files."""
    raise NotImplementedError("auth detector is planned - not yet implemented")
