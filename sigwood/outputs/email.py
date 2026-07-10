"""Email output handler - plain text suitable for piping to sendmail. (planned)

Formats findings as a plain-text email body. Handler is dormant - not registered
in the output registry and has no shipped config section. Wiring up will add a
new config surface and handler registration.
"""

from __future__ import annotations

from sigwood.common.finding import Finding, RunSummary
from sigwood.common.output import OutputHandler


class EmailHandler(OutputHandler):
    """Format findings as a plain-text email and send via SMTP."""

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        to: str = "",
        from_addr: str = "",
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._to = to
        self._from = from_addr
        self._findings: list[Finding] = []
        self._run_summary: RunSummary | None = None

    def begin(self, run_summary: RunSummary) -> None:
        """Store run summary for the email subject line."""
        ...

    def write(self, findings: list[Finding]) -> None:
        """Accumulate findings for transmission at end()."""
        ...

    def end(self) -> None:
        """Compose and send the email via SMTP."""
        ...
