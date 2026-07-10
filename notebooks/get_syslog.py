#!/usr/bin/env python3
"""
get_syslog.py - Pull raw syslog from Splunk and write to a flat text file.

This is a data acquisition utility, not part of the analysis pipeline.
Its output is a plain syslog text file that the analysis tools consume
directly - no Splunk dependency required downstream.

Usage:
    python get_syslog.py                      # pulls last 1 full day (yesterday)
    python get_syslog.py --days 3
    python get_syslog.py --days 3 --out /tmp/syslog.log
    python get_syslog.py --days 7 --max 200000

    --days N covers the N most recent complete calendar days in local time.
    --days 1   = yesterday 00:00:00 → 23:59:59 local
    --days 3   = three days ago 00:00:00 → yesterday 23:59:59 local

    --days M-N (or N-M) covers the inclusive range of complete days between
    M and N days ago. The larger offset is the earlier bound.
    --days 3-5 = five days ago 00:00:00 → three days ago 23:59:59 local (3 days)
    --days 5-3 = same as above (order doesn't matter)
    --days 3-3 = same as --days 3 (single day, three days ago)

Environment variables (override defaults):
    SPLUNK_HOST   Splunk host IP or hostname  (default: 192.0.2.20)
    SPLUNK_PORT   Splunk management port      (default: 8089)
    SPLUNK_USER   Splunk username             (default: prompt)
    SPLUNK_PASS   Splunk password             (default: prompt)

Output format:
    One raw syslog line per line, exactly as received from Splunk _raw field.
    RFC 3164 PRI prefix (<N>) is stripped if present.
    Lines are sorted by timestamp ascending.

Notes:
    Data is pulled in hourly chunks to stay under Splunk's per-query result
    cap (enforced at the binary level on developer/free licenses). For a 7-day
    pull this means 168 queries; expect 10-15 minutes total runtime.
"""

import argparse
import getpass
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
except ImportError:
    print("ERROR: splunk-sdk not installed. Run: pip install splunk-sdk")
    sys.exit(1)

# ── Compiled patterns ─────────────────────────────────────────────────────────
# RFC 3164 PRI field: <N> or <NN> or <NNN> at start of line
PRI_RE = re.compile(r'^<\d+>')

# ── Fleet configuration ───────────────────────────────────────────────────────
# Hosts to include in the pull. Edit this list to match your fleet.
# Workstations and high-noise hosts should be excluded here so the
# analysis pipeline operates on a clean server-only baseline.

INCLUDE_HOSTS = [
    "server1.example.com",
    "server2.example.com",
    "server3.example.com",
    "server4.example.com",
    "server5.example.com",
    # "server6.example.com",
    # "server7.example.com",
    # "server8.example.com",
    "router.example.com",
]

# ── Splunk connection defaults ────────────────────────────────────────────────

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "192.0.2.20")
SPLUNK_PORT = int(os.environ.get("SPLUNK_PORT", 8089))
SPLUNK_USER = os.environ.get("SPLUNK_USER", "")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "")

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_credentials() -> tuple[str, str]:
    """Resolve credentials from env vars or interactive prompt."""
    user = SPLUNK_USER or input("Splunk username: ").strip()
    passwd = SPLUNK_PASS or getpass.getpass("Splunk password: ")
    return user, passwd


def connect(user: str, passwd: str):
    """Connect to Splunk and return a service handle."""
    print(f"Connecting to {SPLUNK_HOST}:{SPLUNK_PORT} as {user}...")
    service = splunk_client.connect(
        host=SPLUNK_HOST,
        port=SPLUNK_PORT,
        username=user,
        password=passwd,
    )
    print(f"Connected. Splunk version: {service.info['version']}")
    return service


def build_hour_windows(far: int, near: int) -> list[tuple[datetime, datetime]]:
    """Return a list of (chunk_start, chunk_end) pairs in local time.

    far  -- the larger day offset (earlier boundary), e.g. 5 for "5 days ago"
    near -- the smaller day offset (later boundary),  e.g. 3 for "3 days ago"
             near=0 is special: upper bound is the top of the last completed hour.

    Normal upper bound (near >= 1):
        today_midnight - near_days + 1 day  (i.e. end of that calendar day)

    Partial-day upper bound (near == 0):
        now truncated to the hour  (never a partial hour chunk)

    Examples (today = 2026-05-16 14:37 local):
        far=1, near=1 -> 2026-05-15 00:00 -> 2026-05-16 00:00  (yesterday, 24h)
        far=3, near=1 -> 2026-05-13 00:00 -> 2026-05-16 00:00  (3 days, 72h)
        far=5, near=3 -> 2026-05-11 00:00 -> 2026-05-13 00:00  (48h)
        far=0, near=0 -> 2026-05-16 00:00 -> 2026-05-16 14:00  (today so far, 14h)
        far=3, near=0 -> 2026-05-13 00:00 -> 2026-05-16 14:00  (3 days + partial, 86h)

    Each pair spans exactly one hour. The list is ordered chronologically
    (oldest first) so progress output reads naturally.
    """
    local_now = datetime.now().astimezone()
    today_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)

    window_start = today_midnight - timedelta(days=far)

    if near == 0:
        # Truncate to the top of the last completed hour.
        window_end = local_now.replace(minute=0, second=0, microsecond=0)
    else:
        window_end = today_midnight - timedelta(days=near) + timedelta(days=1)

    total_hours = int((window_end - window_start).total_seconds() // 3600)
    windows = []
    for i in range(total_hours):
        h_start = window_start + timedelta(hours=i)
        h_end   = window_start + timedelta(hours=i + 1)
        windows.append((h_start, h_end))

    return windows


def fetch_chunked(service, far: int, near: int, hosts: list[str], max_results: int) -> list[dict]:
    """Pull data in hourly chunks to stay under Splunk per-query row limits.

    Splunk developer/free licenses enforce a hard per-query result cap at the
    binary level (~50k rows) that limits.conf cannot override. Hourly chunking
    keeps each query well under this ceiling even on high-volume hosts.

    Time bounds are passed as Unix timestamps so Splunk interprets them
    unambiguously regardless of the server's own timezone setting.
    """
    all_rows = []
    host_filter = " OR ".join(f'host="{h}"' for h in hosts)

    spl = f"""
search index=main sourcetype=syslog
  NOT sourcetype="zeek:json"
  NOT (process=dnsmasq)
  NOT (process=unbound)
  ({host_filter})
| table _time, host, _raw
""".strip()

    windows = build_hour_windows(far, near)
    total_hours = len(windows)

    for i, (chunk_start, chunk_end) in enumerate(windows):
        earliest = str(int(chunk_start.timestamp()))
        latest   = str(int(chunk_end.timestamp()))

        label = chunk_start.strftime("%Y-%m-%d %H:%M %Z")
        print(f"  [{i+1:>4}/{total_hours}] {label}", end=" ... ", flush=True)

        job = service.jobs.oneshot(
            spl,
            count=0,
            output_mode="json",
            earliest_time=earliest,
            latest_time=latest,
        )
        chunk = [r for r in splunk_results.JSONResultsReader(job)
                 if isinstance(r, dict)]
        print(f"{len(chunk):,} rows")
        all_rows.extend(chunk)

        if max_results and len(all_rows) >= max_results:
            print(f"  Reached max_results cap ({max_results:,}), stopping.")
            break

    return all_rows


def make_auto_name(window_start: datetime, window_end: datetime,
                   far: int, near: int, partial: bool, total_days: int) -> str:
    """Return the default output filename derived from the time window."""
    start_str = window_start.strftime("%Y%m%d")
    if partial:
        end_str = window_end.strftime("%Y%m%d_%Hh")
        return f"syslog_{start_str}_to_{end_str}.log"
    elif far == near:
        return f"syslog_{start_str}_1d.log"
    elif near == 1:
        return f"syslog_{start_str}_{total_days}d.log"
    else:
        end_str = (window_end - timedelta(days=1)).strftime("%Y%m%d")
        return f"syslog_{start_str}_to_{end_str}.log"


def resolve_outpath(arg_out: Path | None, auto_name: str) -> Path:
    """Resolve the final output path from the --out argument.

    Rules:
      no --out          -> auto_name in CWD
      --out <dir>       -> auto_name inside that directory
      --out <new path>  -> use as-is (parent dir must exist)
      --out <file>      -> prompt to overwrite; exit if declined
    """
    if arg_out is None:
        return Path(auto_name)

    if arg_out.is_dir():
        return arg_out / auto_name

    if arg_out.exists():
        answer = input(f"{arg_out} already exists. Overwrite? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            sys.exit(0)
        return arg_out

    # Path doesn't exist - treat as an explicit file path.
    if not arg_out.parent.exists():
        print(f"ERROR: Parent directory does not exist: {arg_out.parent}")
        sys.exit(1)
    return arg_out


def write_output(rows: list[dict], outpath: Path) -> None:
    """Write raw syslog lines to a flat text file, one line per event."""
    rows_sorted = sorted(rows, key=lambda r: r.get("_time", ""))

    with open(outpath, "w", encoding="utf-8") as f:
        for row in rows_sorted:
            raw = PRI_RE.sub("", row.get("_raw", "").strip())
            if raw:
                f.write(raw + "\n")

    size_kb = outpath.stat().st_size / 1024
    print(f"\nWritten: {outpath}  ({len(rows_sorted):,} lines, {size_kb:.1f} KB)")


def parse_days_arg(value: str) -> tuple[int, int]:
    """Parse the --days argument into a (far, near) pair of day offsets.

    Accepted forms:
        "N"    -> (N, 1)    -- N complete days ending at last midnight
        "M-N"  -> (max, min) where max/min are the two values; order is ignored
        "N-N"  -> (N, N)    -- single day N days ago
        "0"    -> (0, 0)    -- today so far, up to the last completed hour
        "N-0"  -> (N, 0)    -- N days ago midnight through last completed hour

    near=0 means the upper bound is the top of the most recently completed
    hour (now truncated to the hour), not a calendar-day boundary.
    far must be >= near; both must be >= 0.
    """
    value = value.strip()
    if "-" in value:
        parts = value.split("-", 1)
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid range '{value}': both values must be integers (e.g. '3-5')"
            )
        far, near = max(a, b), min(a, b)
    else:
        try:
            n = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid value '{value}': must be an integer or a range like '3-5'"
            )
        # Single "0" = today so far; single "N" = N trailing complete days.
        far, near = n, (0 if n == 0 else 1)

    if far < 0 or near < 0:
        raise argparse.ArgumentTypeError(
            "Day offsets must be >= 0 (0 = today so far, up to last completed hour)"
        )
    return far, near


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Pull syslog from Splunk and write to a flat text file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--days", "-d",
        type=parse_days_arg,
        default="1",
        metavar="N or M-N",
        help=(
            "Days to pull. Single number N: the N most recent complete days "
            "(e.g. --days 3 = three days ago through yesterday). "
            "Range M-N: the inclusive span of days M through N days ago "
            "(e.g. --days 3-5 = five days ago through three days ago). "
            "Order doesn't matter; M-M is the single day M days ago. "
            "Default: 1 (yesterday)."
        ),
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help=(
            "Output destination. "
            "If omitted: auto-named file in CWD. "
            "If a directory: auto-named file placed inside it. "
            "If a new path: used as the file path (parent dir must exist). "
            "If an existing file: prompts before overwriting."
        ),
    )
    parser.add_argument(
        "--max",
        type=int,
        default=0,
        help="Maximum number of events to pull (default: 0 = unlimited)",
    )
    parser.add_argument(
        "--hosts",
        nargs="+",
        default=INCLUDE_HOSTS,
        metavar="HOST",
        help="Override the default host list",
    )
    args = parser.parse_args()

    far, near = args.days  # unpacked from parse_days_arg

    # Compute the actual window boundaries for display and default filename.
    # Mirror the logic in build_hour_windows so the summary is always accurate.
    local_now = datetime.now().astimezone()
    today_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    window_start = today_midnight - timedelta(days=far)
    if near == 0:
        window_end = local_now.replace(minute=0, second=0, microsecond=0)
    else:
        window_end = today_midnight - timedelta(days=near) + timedelta(days=1)
    total_hours = int((window_end - window_start).total_seconds() // 3600)
    # For display: partial-day windows show hours, whole-day windows show days.
    partial = (near == 0)
    total_days = total_hours // 24

    auto_name = make_auto_name(window_start, window_end, far, near, partial, total_days)
    outpath = resolve_outpath(args.out, auto_name)

    span_str = f"{total_hours}h partial" if partial else f"{total_days} day(s)"
    print(f"\nget_syslog.py")
    print(f"  Window  : {window_start.strftime('%Y-%m-%d %H:%M %Z')} -> {window_end.strftime('%Y-%m-%d %H:%M %Z')}  ({span_str})")
    print(f"  Chunks  : {total_hours} hourly")
    print(f"  Hosts   : {', '.join(args.hosts)}")
    print(f"  Max rows: {'unlimited' if not args.max else f'{args.max:,}'}")
    print(f"  Output  : {outpath}\n")

    user, passwd = get_credentials()
    service = connect(user, passwd)

    print(f"\nFetching {total_hours} hourly chunk(s)...")
    rows = fetch_chunked(service, far, near, args.hosts, args.max)

    if not rows:
        print("No results returned. Check your Splunk connection and index.")
        sys.exit(1)

    # Report host breakdown before writing
    host_counts = Counter(r.get("host", "unknown") for r in rows)
    print(f"\nTotal rows: {len(rows):,}")
    print("Host breakdown:")
    for host, count in sorted(host_counts.items(), key=lambda x: -x[1]):
        print(f"  {host:<35} {count:>8,}")

    write_output(rows, outpath)
    print("Done.")


if __name__ == "__main__":
    main()