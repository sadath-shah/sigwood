#!/usr/bin/env python3
"""
syslog_hunt.py - Syslog structural anomaly detection.

Reads a flat syslog file (one RFC 3164 line per line, as produced by
get_syslog.py), runs drain3 log templating followed by rarity-based
anomaly scoring, and writes a plain-text report to ./hunt_output/.

Pipeline:
    1. Load & parse  - strip RFC 3164 PRI prefix and syslog header
    2. Normalize     - collapse PID variants (sshd[1234] → sshd[*])
    3. Template      - drain3 structural clustering
    4. Score         - rarity ranking (bottom N percentile = anomalous)
    5. Reboot detect - suppress per-host kernel boot bursts, emit single line
    6. Report        - flat list of anomalous raw syslog lines

Usage:
    python syslog_hunt.py syslog_20260515_1d.log
    python syslog_hunt.py --rarity 5 --max-count 2 syslog.log
    python syslog_hunt.py --exclude host1.example.com host2.example.com syslog.log

Cron example (daily, 06:00):
    0 6 * * * cd /opt/hunt && python syslog_hunt.py syslog_$(date +%%Y%%m%%d)_1d.log

Dependencies:
    pip install drain3
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
except ImportError:
    print("ERROR: drain3 not installed. Run: pip install drain3")
    sys.exit(1)

# ── Compiled patterns ─────────────────────────────────────────────────────────
PRI_RE        = re.compile(r'^<\d+>')
SYSLOG_HDR_RE = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+')
PROC_PID_RE   = re.compile(r'\[\d+\]')

# Syslog timestamp for approximate event time parsing (no year - use current year)
SYSLOG_TS_RE  = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})')

# Reboot signal patterns - any of these in a message body triggers reboot detection
REBOOT_SIGNALS_RE = re.compile(
    r'(systemd-logind.*[Ss]ystem is rebooting|'
    r'rsyslogd.*exiting on signal 15|'
    r'systemd-shutdown.*Sending SIGTERM to remaining|'
    r'kernel: Linux version\s)',
    re.IGNORECASE
)

# ── Pipeline defaults ─────────────────────────────────────────────────────────
DRAIN_SIM_THRESH          = 0.5
DRAIN_DEPTH               = 4
DRAIN_PARAMETRIZE_NUMERIC = True
DEFAULT_RARITY_PCT        = 10
DEFAULT_MAX_COUNT         = 1   # hard ceiling on template count regardless of percentile
REBOOT_SUPPRESS_WINDOW    = 300  # seconds: suppress anomalies within this window of reboot

# ── Text formatting ───────────────────────────────────────────────────────────
WIDTH = 72

def banner(text):
    return "\n" + "═" * WIDTH + f"\n  {text}\n" + "═" * WIDTH

def section(text):
    return f"\n── {text} " + "─" * max(0, WIDTH - len(text) - 4)

# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_host(raw):
    """Extract hostname from RFC 3164 syslog line."""
    stripped = PRI_RE.sub("", raw).strip()
    parts = stripped.split()
    return parts[3] if len(parts) >= 4 else "unknown"


def strip_header(raw):
    """Remove RFC 3164 PRI prefix and timestamp+hostname."""
    raw = PRI_RE.sub("", raw)
    return SYSLOG_HDR_RE.sub("", raw).strip()


def normalize(msg):
    """Collapse PID brackets so sshd[1234] and sshd[5678] share a template."""
    return PROC_PID_RE.sub("[*]", msg)


def parse_syslog_ts(raw):
    """
    Parse the syslog timestamp from a raw line. Returns a datetime in local
    time (naive, current year assumed) or None if unparseable.
    """
    stripped = PRI_RE.sub("", raw).strip()
    m = SYSLOG_TS_RE.match(stripped)
    if not m:
        return None
    month_str, day_str, time_str = m.group(1), m.group(2), m.group(3)
    year = datetime.now().year
    try:
        return datetime.strptime(
            f"{year} {month_str} {day_str.zfill(2)} {time_str}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

# ── Load ──────────────────────────────────────────────────────────────────────

def load_syslog(path, exclude_hosts):
    """
    Read flat syslog file. Returns list of dicts:
        raw      - original line
        host     - parsed hostname
        message  - stripped + normalized message body
        ts       - datetime (local, naive) or None
    """
    events        = []
    skipped_empty = 0
    skipped_host  = 0

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw or raw.startswith("#"):
                continue

            host = parse_host(raw)

            if exclude_hosts and host in exclude_hosts:
                skipped_host += 1
                continue

            msg = normalize(strip_header(raw))
            if not msg:
                skipped_empty += 1
                continue

            events.append({
                "raw":     raw,
                "host":    host,
                "message": msg,
                "ts":      parse_syslog_ts(raw),
            })

    print(f"  Loaded        : {len(events):,} events")
    if skipped_host:
        print(f"  Excluded hosts: {skipped_host:,} events")
    if skipped_empty:
        print(f"  Skipped empty : {skipped_empty:,} events")
    return events

# ── Templating ────────────────────────────────────────────────────────────────

def run_drain3(events):
    """Run drain3 on all events. Adds template_id and template_str in-place."""
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th               = DRAIN_SIM_THRESH
    cfg.drain_depth                = DRAIN_DEPTH
    cfg.parametrize_numeric_tokens = DRAIN_PARAMETRIZE_NUMERIC

    miner        = TemplateMiner(config=cfg)
    n            = len(events)
    report_every = max(1, n // 20)

    print(f"  Templating {n:,} events...", end="", flush=True)
    for i, ev in enumerate(events):
        result = miner.add_log_message(ev["message"])
        ev["template_id"]  = result["cluster_id"]
        ev["template_str"] = result["template_mined"]
        if (i + 1) % report_every == 0:
            print(f"\r  Templating {n:,} events... {(i+1)/n*100:.0f}%",
                  end="", flush=True)

    n_templates = len({ev["template_id"] for ev in events})
    print(f"\r  Templating complete: {n_templates:,} unique templates "
          f"from {n:,} events")
    return events

# ── Rarity scoring ────────────────────────────────────────────────────────────

def score_rarity(events, rarity_pct, max_count):
    """
    Flag events whose template count falls at or below the effective threshold.
    Effective threshold = min(percentile-derived value, max_count).
    Adds is_anomaly bool in-place. Returns (threshold, freq_dict).
    """
    freq = defaultdict(int)
    for ev in events:
        freq[ev["template_id"]] += 1

    sorted_counts = sorted(freq.values())
    idx           = max(0, int(len(sorted_counts) * rarity_pct / 100) - 1)
    pct_threshold = sorted_counts[idx]

    threshold = min(pct_threshold, max_count)

    rare_ids = {tid for tid, count in freq.items() if count <= threshold}
    for ev in events:
        ev["is_anomaly"] = ev["template_id"] in rare_ids

    n_anom = sum(ev["is_anomaly"] for ev in events)
    print(f"  Rarity threshold : <= {threshold} events "
          f"(pct={pct_threshold}, max_count cap={max_count})")
    print(f"  Anomalous        : {len(rare_ids):,} templates  |  "
          f"{n_anom:,} events ({n_anom/len(events)*100:.2f}%)")

    return threshold, dict(freq)

# ── Reboot detection ──────────────────────────────────────────────────────────

def detect_reboots(events):
    """
    Scan all events for reboot signals. For each host, record the timestamp
    of each detected reboot. Returns dict: host -> list of reboot datetimes.
    """
    reboots = defaultdict(list)
    for ev in events:
        if ev["ts"] and REBOOT_SIGNALS_RE.search(ev["raw"]):
            reboots[ev["host"]].append(ev["ts"])
    for host in reboots:
        reboots[host].sort()
    return dict(reboots)


def apply_reboot_suppression(noise_events, reboots):
    """
    For each anomalous event, check if it falls within REBOOT_SUPPRESS_WINDOW
    seconds after a detected reboot on the same host. If so, suppress it.

    Returns:
        kept          - anomalous events not suppressed
        reboot_lines  - synthetic reboot annotation lines (one per reboot)
        suppressed_n  - count of suppressed events
    """
    reboot_lines    = []
    suppressed_n    = 0
    kept            = []
    emitted_reboots = set()  # (host, reboot_ts) already announced

    for ev in noise_events:
        host = ev["host"]
        ts   = ev["ts"]

        if ts is None or host not in reboots:
            kept.append(ev)
            continue

        suppressed = False
        for rts in reboots[host]:
            delta = (ts - rts).total_seconds()
            if 0 <= delta <= REBOOT_SUPPRESS_WINDOW:
                # Emit a single reboot line the first time we see this reboot
                key = (host, rts)
                if key not in emitted_reboots:
                    emitted_reboots.add(key)
                    reboot_lines.append({
                        "ts":   rts,
                        "host": host,
                        "raw":  f"*** {host} rebooted at "
                                f"{rts.strftime('%a %b %d %H:%M:%S')} ***",
                        "synthetic": True,
                    })
                suppressed = True
                suppressed_n += 1
                break

        if not suppressed:
            kept.append(ev)

    return kept, reboot_lines, suppressed_n

# ── Report building ───────────────────────────────────────────────────────────

def time_range_str(events):
    """Return a human-readable time range string from event timestamps."""
    timestamps = [ev["ts"] for ev in events if ev["ts"] is not None]
    if not timestamps:
        return "unknown"
    earliest = min(timestamps)
    latest   = max(timestamps)
    fmt      = "%a %b %d %H:%M:%S"
    if earliest.date() == latest.date():
        return (f"{earliest.strftime(fmt)} - "
                f"{latest.strftime('%H:%M:%S')}")
    return f"{earliest.strftime(fmt)} - {latest.strftime(fmt)}"


def build_report(events, freq, threshold, rarity_pct, max_count,
                 input_path, reboots):
    run_ts    = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    total     = len(events)
    noise_raw = [ev for ev in events if ev["is_anomaly"]]

    # Apply reboot suppression
    kept, reboot_lines, suppressed_n = apply_reboot_suppression(
        noise_raw, reboots
    )

    # Merge kept anomalies with synthetic reboot lines, sort by timestamp
    all_findings = kept + reboot_lines
    all_findings.sort(key=lambda ev: ev["ts"] if ev.get("ts") else datetime.min)

    n_noise     = len(kept)
    n_synthetic = len(reboot_lines)
    pct_noise   = n_noise / total * 100 if total else 0

    # Per-host totals (original events only)
    host_total = defaultdict(int)
    host_noise = defaultdict(int)
    for ev in events:
        host_total[ev["host"]] += 1
    for ev in kept:
        host_noise[ev["host"]] += 1

    n_templates = len({ev["template_id"] for ev in kept})

    out = []

    # ── Header ──
    out.append(banner(f"syslog_hunt.py  |  Anomaly Report  |  {run_ts}"))

    # ── Summary ──
    out.append(section("Summary"))
    out.append(f"  Input              : {input_path.name}")
    out.append(f"  Scan range         : {time_range_str(events)}")
    out.append(f"  Total events       : {total:,}")
    out.append(f"  Rarity threshold   : <= {threshold} events")
    out.append(f"  Anomalous templates: {n_templates:,}")
    out.append(f"  Anomalous events   : {n_noise:,}  ({pct_noise:.2f}%)")
    if suppressed_n:
        out.append(f"  Reboot-suppressed  : {suppressed_n:,} events "
                   f"({n_synthetic} reboot(s) detected)")

    # ── Host breakdown ──
    out.append(section("Anomaly rate by host"))
    sorted_hosts = sorted(
        host_total.keys(),
        key=lambda h: host_noise.get(h, 0) / host_total[h],
        reverse=True,
    )
    for host in sorted_hosts:
        tot  = host_total[host]
        anom = host_noise.get(host, 0)
        rate = anom / tot * 100 if tot else 0
        bar  = "█" * min(40, int(rate * 4))
        out.append(
            f"  {host:<35}  {anom:>5,} / {tot:>8,}  ({rate:>5.2f}%)  {bar}"
        )

    # ── Findings ──
    n_findings = len(all_findings)
    out.append(section(f"Findings - {n_noise} anomalous events "
                       f"({n_templates} templates)"
                       + (f" + {n_synthetic} reboot(s)" if n_synthetic else "")))

    for ev in all_findings:
        out.append(f"  {ev['raw'][:200]}")

    out.append(banner("End of report"))
    return "\n".join(out) + "\n"

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Syslog structural anomaly detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Flat syslog file (one raw line per line)",
    )
    parser.add_argument(
        "--rarity", "-r",
        type=int,
        default=DEFAULT_RARITY_PCT,
        metavar="PCT",
        help=f"Bottom N percentile flagged as anomalous (default: {DEFAULT_RARITY_PCT})",
    )
    parser.add_argument(
        "--max-count", "-m",
        type=int,
        default=DEFAULT_MAX_COUNT,
        dest="max_count",
        help=f"Hard cap on template count (default: {DEFAULT_MAX_COUNT})",
    )
    parser.add_argument(
        "--exclude", "-x",
        nargs="+",
        default=[],
        metavar="HOST",
        help="Hosts to exclude (e.g. --exclude host1.example.com host2.example.com)",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Override output file path",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: file not found: {args.input}")
        sys.exit(1)

    exclude_hosts = set(args.exclude)

    # Output path
    out_dir = Path("./hunt_output")
    out_dir.mkdir(exist_ok=True)
    if args.out:
        outpath = args.out
    else:
        ts      = datetime.now().strftime("%Y%m%d_%H%M")
        stem    = args.input.stem
        outpath = out_dir / f"{stem}_anomalies_{ts}.txt"

    # ── Run ──
    print(banner(f"syslog_hunt.py  |  {args.input.name}"))
    print(f"  File      : {args.input}  "
          f"({args.input.stat().st_size / 1e6:.1f} MB)")
    print(f"  Rarity    : bottom {args.rarity}th percentile  "
          f"|  max_count cap={args.max_count}")
    if exclude_hosts:
        print(f"  Excluded  : {', '.join(sorted(exclude_hosts))}")
    print(f"  Output    : {outpath}")

    print(section("Stage 1 - Load"))
    events = load_syslog(args.input, exclude_hosts)
    if not events:
        print("No events loaded. Check file and host exclusions.")
        sys.exit(1)
    hosts = sorted({ev["host"] for ev in events})
    print(f"  Hosts     : {', '.join(hosts)}")
    print(f"  Range     : {time_range_str(events)}")

    print(section("Stage 2 - drain3 Templating"))
    events = run_drain3(events)

    print(section("Stage 3 - Rarity Scoring"))
    threshold, freq = score_rarity(events, args.rarity, args.max_count)

    print(section("Stage 4 - Reboot Detection"))
    reboots = detect_reboots(events)
    if reboots:
        for host, times in sorted(reboots.items()):
            for t in times:
                print(f"  {host}: reboot at {t.strftime('%a %b %d %H:%M:%S')}")
    else:
        print("  No reboots detected.")

    print(section("Stage 5 - Building Report"))
    report = build_report(
        events, freq, threshold,
        args.rarity, args.max_count,
        args.input, reboots,
    )

    outpath.write_text(report, encoding="utf-8")
    print(f"  Written   : {outpath}  "
          f"({outpath.stat().st_size / 1024:.1f} KB)")

    print(report)


if __name__ == "__main__":
    main()