"""Shared exception types used across runner, exporters, and CLI.

ExportAborted lives here (not under exporters/) so that runner.py can raise it
without creating a runner → exporter dependency. The CLI catches it once and
translates to a clean exit 0.
"""

from __future__ import annotations


class ExportAborted(Exception):
    """Raised when the operator declines an advisory confirmation prompt.

    Used by the runner's large-dataset prompt and by exporter backends'
    cost-prompts (e.g. CloudTrail's S3 egress guard). Caught by cli.main()
    and translated to a clean exit 0 with the message. Not a ValueError -
    distinct from the user-facing error path.
    """


class UsageError(ValueError):
    """Raised for an argument / flag / form error the operator can fix by
    re-reading the usage.

    A ValueError subclass so programmatic callers that catch ValueError are
    unaffected. The CLI boundary (``cli.main``) catches it BEFORE plain
    ValueError and appends the ``run 'sigwood --help' for usage`` pointer -
    that pointer belongs to argument errors only, never to config / path /
    backend / runtime ValueErrors.
    """


class DigestEmpty(Exception):
    """Raised by run_digest when a RECOGNIZED schema loads to an empty frame.

    Not an error - the file was understood, it simply had no parseable
    records (e.g. a Zeek conn.log with header rows but zero data rows).
    Callers catch this and narrate it without rendering a card.

    Explicitly NOT a subclass of ValueError: catch-arms in cli.py that
    handle real per-path failures (corrupt gzip, parser errors) MUST NOT
    consume DigestEmpty, which is a control signal carrying a successful
    "the file was understood and contained nothing to render" outcome.

    basename: filename when the digest source was a file (sniff-driven
    fan-out, single-file source_dir); directory name when the source was
    a configured directory (bare-config branch). The stderr narration
    "recognized as <schema> but no parseable records" reads correctly
    in both cases.
    """

    def __init__(self, basename: str, schema: str) -> None:
        super().__init__(
            f"recognized {basename} as {schema} but no parseable records"
        )
        self.basename = basename
        self.schema = schema
