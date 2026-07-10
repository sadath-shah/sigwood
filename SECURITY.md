# Security Policy

## Reporting a vulnerability

If you believe you have found a security issue in sigwood, please report it
privately. **Do not open a public issue for security problems.**

- Email: **security@augros.org**
- Please include a description, reproduction steps, and the version or commit.

We aim to acknowledge a report within a few business days and to keep you updated
as we investigate. We will credit reporters who wish to be credited.

## Supported versions

sigwood is pre-1.0. Security fixes land on the latest release and `main`.

## Threat model - what sigwood does and does not trust

sigwood is a **local, offline, batch** analysis tool. It runs on your machine,
reads log files from disk, and writes reports and exports to directories you
choose.

**It trusts:**

- The machine and account it runs as.
- The configuration file and allowlist files you point it at. Allowlist `re:`
  patterns are compiled and executed, so review any allowlist you did not write
  yourself.

**It treats log *content* as untrusted data.** Log files may originate from
compromised hosts. sigwood is built so that hostile log content cannot execute
code or escape the tool:

- Every human-facing report surface - text, CSV, and HTML/PDF - strips terminal
  control bytes from log-derived values, so hostile log content cannot emit
  terminal control sequences when a report or worklist is printed or opened in a
  terminal.
- CSV worklist cells additionally carry a spreadsheet formula-injection guard
  (CWE-1236): a cell that would start with `=`, `+`, `-`, or `@` is quote-prefixed,
  so opening the file in Excel or LibreOffice cannot execute a formula planted in
  log content.
- HTML and PDF report output additionally escapes markup at a single enforced
  choke point, so a log line cannot inject markup or script into a report.
- No log field is ever passed to a shell, to `eval`, or to a code-executing
  deserializer - log content is parsed with `json.loads` and plain text parsers;
  there is no pickle, marshal, or YAML load anywhere on the data path.

**Two things to keep in mind when handling untrusted logs:**

- **Suggested commands contain values from your logs.** Findings include
  copy-pasteable triage commands (`whois …`, `grep …`) built from fields such as
  domains and IP addresses. Review a suggested command before you run it.
- **sigwood loads recognized log formats into memory and does not sandbox or
  hard-limit analysis input.** Analyzing an extremely large or maliciously
  crafted archive - for example, a decompression bomb - can exhaust memory.
  When you are scoping out logs of unknown origin, format, or size, start with
  `sigwood digest <file>`: unrecognized input is profiled from a bounded
  sample before you commit to a full analysis run. Recognized formats may still
  be loaded fully, so keep first-pass inputs narrow when you do not yet trust
  the archive.

## Design guarantees

- **No phone-home, no telemetry, no account, no cloud.** sigwood does not send
  your data anywhere. The only network activity is the optional exporters, which
  pull logs *toward* you - from Splunk or an S3 CloudTrail bucket into local
  files - and never push your data out.
- **No credential handling for AWS.** sigwood uses your ambient boto3
  credential chain and never reads, stores, or prompts for AWS credentials.
- **Splunk credentials** are read from environment variables
  (`SIGWOOD_SPLUNK_USER` / `SIGWOOD_SPLUNK_PASS`) - the recommended path - or
  from your config file. They are sent only to the Splunk host you configure.
  TLS certificate verification is on by default (`verify_tls = true`). Prefer
  the environment variables over storing a password in the config file.
- **No background process, no database, no daemon, no listening socket.**
- **No dynamic code execution.** sigwood uses no `eval`, `exec`, or shell
  invocation, and performs no code-executing deserialization of untrusted input.

## Dependencies

sigwood depends on widely-used scientific Python libraries (pandas, numpy,
scikit-learn) and log-analysis utilities (drain3, tldextract), plus an
arch-selected clustering backend: fast-hdbscan, which pulls numba and llvmlite, on
common 64-bit platforms (x86-64, aarch64/arm64); stock hdbscan elsewhere,
including 32-bit ARM. Optional features pull additional stacks (`[splunk]`,
`[cloudtrail]`, `[pdf]`). Keep your dependencies updated; we track advisories
against them as part of release hygiene.
