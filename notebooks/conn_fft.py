#!/usr/bin/env python3
"""
conn_fft.py - weekly beaconing threat hunt
Zeek conn.log (ndjson) → scored flow report + plot

Usage:
    python beacon_hunt.py data/conn/conn.log
    python beacon_hunt.py data/conn/conn.log --min-conns 20 --top 30
    python beacon_hunt.py data/conn/conn.log --out-dir /tmp/hunt

Outputs (written to --out-dir, default ./hunt_output/):
    beacon_report_<timestamp>.txt   - full text report
    beacon_scores_<timestamp>.csv   - all scored flows
    beacon_plot_<timestamp>.png     - scatter + histogram
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")   # non-interactive backend for script use
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Flows to always suppress from scoring - known-good periodic infrastructure.
# Format: (dst_port, dst_ip)
ALLOWLIST_PORT_DST = {
    (53,   '192.0.2.53'),    # DNS resolver
    (123,  '192.0.2.53'),    # NTP
    (161,  '192.0.2.1'),     # SNMP → router
    (161,  '192.0.2.11'),    # SNMP → server
    (6556, '192.0.2.53'),    # checkmk agent
    (6556, '192.0.2.11'),    # checkmk agent
    (6556, '192.0.2.20'),    # checkmk agent
    (6556, '198.51.100.1'),  # checkmk agent
    (9997, '192.0.2.20'),    # Splunk forwarder
    (8443, '192.0.2.1'),     # router WebUI
    (2049, '192.0.2.11'),    # NFS
    (111,  '192.0.2.11'),    # portmapper
    (514,  '192.0.2.20'),    # syslog
    (8000, '192.0.2.20'),    # Splunk WebUI
    (8080, '192.0.2.11'),    # Pi-hole nebula-sync
}

# Known monitoring flows - labeled separately in the plot
KNOWN_MONITORING = {
    ('192.0.2.10', '192.0.2.1',  22),   # monitor → router SSH (MRTG)
    ('192.0.2.10', '192.0.2.53', 80),   # monitor → Pi-hole API
    ('192.0.2.10', '192.0.2.11', 80),   # monitor → Pi-hole API
    ('192.0.2.11', '192.0.2.1',  22),   # server → router SSH (MRTG)
}

# Score thresholds for triage tiers
THRESH_HIGH   = 0.5
THRESH_MEDIUM = 0.3


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def is_multicast_or_broadcast(ip: str) -> bool:
    if not isinstance(ip, str):
        return False
    return (
        ip.startswith('224.') or
        ip.startswith('239.') or
        ip.startswith('255.') or
        ip.endswith('.255') or
        ip.startswith('ff0') or
        ip.startswith('ff02')
    )


def load_and_filter(log_path: Path) -> tuple[pd.DataFrame, dict]:
    """Load conn.log, apply all filters, return clean DataFrame + stats dict."""
    print(f"[+] Loading {log_path} ...")
    df = pd.read_json(log_path, lines=True)
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    raw_rows = len(df)

    t_start = pd.to_datetime(df['ts'].min(), unit='s', utc=True)
    t_end   = pd.to_datetime(df['ts'].max(), unit='s', utc=True)
    span_h  = (df['ts'].max() - df['ts'].min()) / 3600

    print(f"    {raw_rows:,} rows  |  {t_start.strftime('%Y-%m-%d %H:%M')} → "
          f"{t_end.strftime('%Y-%m-%d %H:%M')}  ({span_h:.1f}h)")

    # 1. Established connections only
    df = df[df['conn_state'].isin(['SF', 'S1'])]

    # 2. Drop multicast/broadcast destinations
    df = df[~df['id.resp_h'].apply(is_multicast_or_broadcast)]

    # 3. Drop IPv6 link-local (NDP noise)
    df = df[~df['id.orig_h'].str.startswith('fe80:', na=False)]
    df = df[~df['id.resp_h'].str.startswith('fe80:', na=False)]

    # 4. Require originator (no mid-stream captures)
    df = df[df['local_orig'] == True]

    # 5. Require non-null bytes
    df = df[df['orig_bytes'].notna()]

    # 6. Drop allowlisted flows
    allowlist_mask = df.apply(
        lambda r: (int(r['id.resp_p']), r['id.resp_h']) in ALLOWLIST_PORT_DST,
        axis=1
    )
    df = df[~allowlist_mask]

    stats = {
        'raw_rows'  : raw_rows,
        'clean_rows': len(df),
        'dropped'   : raw_rows - len(df),
        'pct_drop'  : (raw_rows - len(df)) / raw_rows * 100,
        't_start'   : t_start,
        't_end'     : t_end,
        'span_h'    : span_h,
    }

    print(f"    After filters: {len(df):,} rows  "
          f"({stats['pct_drop']:.1f}% dropped)")
    return df.reset_index(drop=True), stats


# ---------------------------------------------------------------------------
# Flow grouping
# ---------------------------------------------------------------------------

def build_candidate_flows(df: pd.DataFrame, min_conns: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Group into (src, dst, port, proto) flows and return candidates above threshold."""
    flow_counts = (
        df.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'])
        .size()
        .reset_index(name='conn_count')
        .sort_values('conn_count', ascending=False)
    )
    candidates = flow_counts[flow_counts['conn_count'] >= min_conns].copy()
    df_cands = df.merge(
        candidates[['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto']],
        on=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'],
        how='inner'
    ).sort_values(['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'ts'])
    return candidates, df_cands


# ---------------------------------------------------------------------------
# FFT beacon scorer
# ---------------------------------------------------------------------------

def compute_beacon_score(ts_array: np.ndarray,
                         bin_size: int = 30,
                         min_period: int = 45,
                         max_period: int = 7200) -> dict | None:
    """
    Compute FFT-based beacon score for a single flow's connection timestamps.

    Approach:
        1. Bin timestamps into a regular time grid (count series)
        2. Apply FFT to find dominant periodic frequency
        3. Score using spectral ratio + peak prominence + jitter CV

    Why binning instead of raw inter-arrival deltas:
        Gaps produce massive delta outliers that corrupt FFT results.
        Binning represents gaps as zero-count bins, preserving periodicity.

    Why prominence in addition to spectral ratio:
        Sparse binary signals spread energy across harmonics, keeping the
        absolute spectral ratio low even for perfectly periodic flows.
        Prominence measures how much the peak rises above the local noise
        floor - robust to harmonic spreading.
    """
    if len(ts_array) < 10:
        return None

    t_start = ts_array.min()
    t_end   = ts_array.max()
    n_bins  = int((t_end - t_start) / bin_size) + 1

    bin_idx = ((ts_array - t_start) / bin_size).astype(int)
    counts  = np.zeros(n_bins)
    np.add.at(counts, bin_idx, 1)

    std = counts.std()
    if std == 0:
        return None

    counts_norm = (counts - counts.mean()) / std

    fft_mag = np.abs(np.fft.rfft(counts_norm))
    freqs   = np.fft.rfftfreq(n_bins, d=bin_size)
    fft_mag[0] = 0

    with np.errstate(divide='ignore'):
        periods = np.where(freqs > 0, 1.0 / freqs, np.inf)

    mask_range = (periods >= min_period) & (periods <= max_period)
    fft_masked = np.where(mask_range, fft_mag, 0)
    if fft_masked.max() == 0:
        return None

    peak_idx    = fft_masked.argmax()
    peak_period = periods[peak_idx]
    peak_power  = fft_mag[peak_idx]
    total_power = fft_mag[1:].sum()
    if total_power == 0:
        return None

    spectral_ratio = peak_power / total_power

    window = max(10, int(peak_idx * 0.05))
    lo     = max(1, peak_idx - window)
    hi     = min(len(fft_mag) - 1, peak_idx + window)
    local  = np.concatenate([fft_mag[lo:peak_idx], fft_mag[peak_idx+1:hi+1]])
    noise_floor     = np.median(local) if len(local) > 0 else 1.0
    prominence      = peak_power / (noise_floor + 1e-10)
    prominence_norm = min(prominence / 100.0, 1.0)

    deltas       = np.diff(ts_array)
    d_mean       = deltas.mean()
    d_std        = deltas.std()
    clean_deltas = deltas[np.abs(deltas - d_mean) < 3 * d_std]
    jitter_cv    = (clean_deltas.std() / clean_deltas.mean()
                    if len(clean_deltas) > 1 else 1.0)

    # Composite: 40% spectral ratio + 40% prominence + 20% jitter
    beacon_score = (
        0.4 * spectral_ratio +
        0.4 * prominence_norm +
        0.2 * (1.0 - min(jitter_cv, 1.0))
    )

    return {
        'dominant_period'  : round(peak_period, 1),
        'dominant_period_m': round(peak_period / 60, 2),
        'spectral_ratio'   : round(spectral_ratio, 4),
        'prominence'       : round(prominence, 2),
        'prominence_norm'  : round(prominence_norm, 4),
        'jitter_cv'        : round(jitter_cv, 4),
        'beacon_score'     : round(beacon_score, 4),
        'conn_count'       : len(ts_array),
        'occupancy'        : round((counts > 0).sum() / n_bins, 4),
    }


# ---------------------------------------------------------------------------
# Score all candidate flows
# ---------------------------------------------------------------------------

def score_flows(df_cands: pd.DataFrame) -> pd.DataFrame:
    results = []
    grouped = df_cands.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'])

    for (orig_h, resp_h, resp_p, proto), group in tqdm(
        grouped, desc="Scoring flows", unit="flow"
    ):
        ts_array = group['ts'].sort_values().values
        score = compute_beacon_score(ts_array)
        if score is None:
            continue

        bytes_s = group['orig_bytes'].dropna()
        bytes_cv = (bytes_s.std() / bytes_s.mean()
                    if len(bytes_s) > 1 and bytes_s.mean() > 0 else 1.0)

        results.append({
            'src_ip'      : orig_h,
            'dst_ip'      : resp_h,
            'dst_port'    : int(resp_p),
            'proto'       : proto,
            **score,
            'bytes_cv'    : round(bytes_cv, 4),
            'bytes_mean'  : round(bytes_s.mean(), 1) if len(bytes_s) > 0 else 0,
        })

    return (pd.DataFrame(results)
            .sort_values('beacon_score', ascending=False)
            .reset_index(drop=True))


# ---------------------------------------------------------------------------
# Classification for plot coloring
# ---------------------------------------------------------------------------

def classify(row) -> str:
    if (row.src_ip, row.dst_ip, row.dst_port) in KNOWN_MONITORING:
        return 'monitoring'
    if row.dst_port == 123:
        return 'ntp'
    if row.dst_port == 53:
        return 'dns'
    if row.beacon_score >= THRESH_HIGH:
        return 'high'
    if row.beacon_score >= THRESH_MEDIUM:
        return 'medium'
    return 'normal'


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------

def make_plot(df_scores: pd.DataFrame, stats: dict, out_path: Path):
    plt.style.use('dark_background')
    df_scores = df_scores.copy()
    df_scores['category'] = df_scores.apply(classify, axis=1)

    colors = {
        'monitoring': '#888888',
        'ntp'       : '#4a9eff',
        'dns'       : '#4aff9e',
        'high'      : '#ff4a4a',
        'medium'    : '#ffaa4a',
        'normal'    : '#ffffff',
    }
    labels = {
        'monitoring': 'Known monitoring',
        'ntp'       : 'NTP sync',
        'dns'       : 'DNS patterns',
        'high'      : f'High score (≥{THRESH_HIGH})',
        'medium'    : f'Medium score (≥{THRESH_MEDIUM})',
        'normal'    : 'Normal',
    }

    fig, axes = plt.subplots(1, 2, figsize=(18, 7))
    date_str = stats['t_start'].strftime('%Y-%m-%d') + ' - ' + stats['t_end'].strftime('%Y-%m-%d')
    fig.suptitle(f"Beacon Hunt  |  {date_str}  ({stats['span_h']:.1f}h)",
                 fontsize=13, y=1.01)

    # --- Left: score vs period bubble chart
    ax = axes[0]
    for cat in ['normal', 'dns', 'ntp', 'monitoring', 'medium', 'high']:
        sub = df_scores[df_scores['category'] == cat]
        if len(sub) == 0:
            continue
        sizes = np.clip(sub['conn_count'] / df_scores['conn_count'].max() * 800, 10, 800)
        ax.scatter(sub['dominant_period_m'], sub['beacon_score'],
                   s=sizes, c=colors[cat], alpha=0.6, edgecolors='none',
                   label=f"{labels[cat]} (n={len(sub)})")

    ax.axhline(THRESH_HIGH,   color='#ff4a4a', linestyle='--', linewidth=0.8,
               alpha=0.5, label=f'High threshold ({THRESH_HIGH})')
    ax.axhline(THRESH_MEDIUM, color='#ffaa4a', linestyle='--', linewidth=0.8,
               alpha=0.5, label=f'Medium threshold ({THRESH_MEDIUM})')

    # Annotate high scorers that aren't known monitoring
    for _, row in df_scores[df_scores['beacon_score'] >= THRESH_HIGH].iterrows():
        if classify(row) not in ('monitoring',):
            ax.annotate(
                f"{row.src_ip}→{row.dst_ip}:{row.dst_port}",
                xy=(row.dominant_period_m, row.beacon_score),
                xytext=(8, 0), textcoords='offset points',
                fontsize=6.5, color='white', alpha=0.85,
            )

    ax.set_xlabel('Dominant Period (minutes)', fontsize=11)
    ax.set_ylabel('Beacon Score', fontsize=11)
    ax.set_title('Beacon Score vs Period\n(bubble size = connection count)', fontsize=10)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.legend(fontsize=8, loc='upper right')

    # --- Right: score distribution histogram
    ax2 = axes[1]
    bins = np.linspace(0, df_scores['beacon_score'].max() + 0.01, 60)
    ax2.hist(df_scores['beacon_score'], bins=bins, color='#4a9eff',
             edgecolor='none', alpha=0.8)
    ax2.axvline(THRESH_HIGH,   color='#ff4a4a', linestyle='--',
                linewidth=1.2, label=f'High ({THRESH_HIGH})')
    ax2.axvline(THRESH_MEDIUM, color='#ffaa4a', linestyle='--',
                linewidth=1.2, label=f'Medium ({THRESH_MEDIUM})')

    n_high   = (df_scores['beacon_score'] >= THRESH_HIGH).sum()
    n_medium = ((df_scores['beacon_score'] >= THRESH_MEDIUM) &
                (df_scores['beacon_score'] < THRESH_HIGH)).sum()
    ax2.text(THRESH_HIGH + 0.01, ax2.get_ylim()[1] * 0.85,
             f"≥{THRESH_HIGH}: {n_high} flows\n≥{THRESH_MEDIUM}: {n_medium} flows",
             fontsize=9, color='white')

    ax2.set_xlabel('Beacon Score', fontsize=11)
    ax2.set_ylabel('Flow count', fontsize=11)
    ax2.set_title(f'Score Distribution\n({len(df_scores):,} candidate flows)', fontsize=10)
    ax2.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Plot saved → {out_path}")


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

def write_report(df_scores: pd.DataFrame, stats: dict,
                 log_path: Path, top_n: int, out_path: Path):

    n_high   = (df_scores['beacon_score'] >= THRESH_HIGH).sum()
    n_medium = ((df_scores['beacon_score'] >= THRESH_MEDIUM) &
                (df_scores['beacon_score'] < THRESH_HIGH)).sum()
    n_total  = len(df_scores)

    lines = []
    w = lines.append

    w("=" * 72)
    w("  BEACON THREAT HUNT REPORT")
    w("=" * 72)
    w(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"  Log file  : {log_path}")
    w(f"  Window    : {stats['t_start'].strftime('%Y-%m-%d %H:%M')} UTC  →  "
      f"{stats['t_end'].strftime('%Y-%m-%d %H:%M')} UTC  ({stats['span_h']:.1f}h)")
    w("")
    w("  DATA SUMMARY")
    w("  " + "-" * 40)
    w(f"  Raw conn.log rows  : {stats['raw_rows']:>10,}")
    w(f"  After filters      : {stats['clean_rows']:>10,}  ({stats['pct_drop']:.1f}% dropped)")
    w(f"  Candidate flows    : {n_total:>10,}  (≥20 connections)")
    w("")
    w("  TRIAGE SUMMARY")
    w("  " + "-" * 40)
    w(f"  HIGH   (score ≥ {THRESH_HIGH}) : {n_high:>5}  flows  ← investigate")
    w(f"  MEDIUM (score ≥ {THRESH_MEDIUM}) : {n_medium:>5}  flows  ← review")
    w(f"  NORMAL (score <  {THRESH_MEDIUM}) : {n_total - n_high - n_medium:>5}  flows")
    w("")

    # Score distribution
    w("  SCORE DISTRIBUTION")
    w("  " + "-" * 40)
    for lo, hi in [(0.5, 1.0), (0.3, 0.5), (0.2, 0.3), (0.1, 0.2), (0.0, 0.1)]:
        n = ((df_scores['beacon_score'] >= lo) & (df_scores['beacon_score'] < hi)).sum()
        bar = '█' * int(n / max(n_total, 1) * 40)
        w(f"  {lo:.1f}-{hi:.1f} : {n:5,}  {bar}")
    w("")

    # High priority flows
    high_flows = df_scores[df_scores['beacon_score'] >= THRESH_HIGH]
    if len(high_flows) > 0:
        w("  HIGH PRIORITY FLOWS  (score ≥ 0.5)")
        w("  " + "-" * 68)
        w(f"  {'SRC':<18} {'DST':<18} {'PORT':>5} {'PROTO':<5} "
          f"{'SCORE':>6} {'PERIOD':>8} {'PROM':>7} {'JITTER':>7} {'BYTES_CV':>8} {'CONNS':>6}")
        w("  " + "-" * 68)
        for _, r in high_flows.iterrows():
            flag = " ◄ KNOWN INFRA" if (r.src_ip, r.dst_ip, r.dst_port) in KNOWN_MONITORING else ""
            w(f"  {r.src_ip:<18} {r.dst_ip:<18} {int(r.dst_port):>5} {r.proto:<5} "
              f"{r.beacon_score:>6.4f} {r.dominant_period_m:>6.1f}m "
              f"{r.prominence:>7.1f} {r.jitter_cv:>7.4f} {r.bytes_cv:>8.4f} "
              f"{r.conn_count:>6}{flag}")
        w("")

    # Medium priority flows
    med_flows = df_scores[
        (df_scores['beacon_score'] >= THRESH_MEDIUM) &
        (df_scores['beacon_score'] <  THRESH_HIGH)
    ]
    if len(med_flows) > 0:
        w("  MEDIUM PRIORITY FLOWS  (0.3 ≤ score < 0.5)")
        w("  " + "-" * 68)
        w(f"  {'SRC':<18} {'DST':<18} {'PORT':>5} {'PROTO':<5} "
          f"{'SCORE':>6} {'PERIOD':>8} {'PROM':>7} {'JITTER':>7} {'BYTES_CV':>8} {'CONNS':>6}")
        w("  " + "-" * 68)
        for _, r in med_flows.iterrows():
            w(f"  {r.src_ip:<18} {r.dst_ip:<18} {int(r.dst_port):>5} {r.proto:<5} "
              f"{r.beacon_score:>6.4f} {r.dominant_period_m:>6.1f}m "
              f"{r.prominence:>7.1f} {r.jitter_cv:>7.4f} {r.bytes_cv:>8.4f} "
              f"{r.conn_count:>6}")
        w("")

    # Top N overall
    w(f"  TOP {top_n} FLOWS BY BEACON SCORE (all tiers)")
    w("  " + "-" * 68)
    w(f"  {'#':<4} {'SRC':<18} {'DST':<18} {'PORT':>5} {'PROTO':<5} "
      f"{'SCORE':>6} {'PERIOD':>8} {'CONNS':>6}")
    w("  " + "-" * 68)
    for i, (_, r) in enumerate(df_scores.head(top_n).iterrows(), 1):
        w(f"  {i:<4} {r.src_ip:<18} {r.dst_ip:<18} {int(r.dst_port):>5} {r.proto:<5} "
          f"{r.beacon_score:>6.4f} {r.dominant_period_m:>6.1f}m {r.conn_count:>6}")
    w("")
    w("=" * 72)
    w("  END OF REPORT")
    w("=" * 72)

    report_text = "\n".join(lines)
    out_path.write_text(report_text)
    print(report_text)
    print(f"\n[+] Report saved → {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="beacon threat hunt - Zeek conn.log → scored report"
    )
    parser.add_argument("log",        type=Path, help="Path to Zeek conn.log (ndjson)")
    parser.add_argument("--min-conns",type=int,  default=20,
                        help="Minimum connections per flow to score (default: 20)")
    parser.add_argument("--top",      type=int,  default=25,
                        help="Number of flows in top-N table (default: 25)")
    parser.add_argument("--out-dir",  type=Path, default=Path("hunt_output"),
                        help="Output directory (default: ./hunt_output/)")
    args = parser.parse_args()

    if not args.log.exists():
        print(f"[!] Log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- Run pipeline
    df_clean, stats = load_and_filter(args.log)

    print(f"[+] Grouping flows (min_conns={args.min_conns}) ...")
    candidates, df_cands = build_candidate_flows(df_clean, args.min_conns)
    print(f"    {len(candidates):,} candidate flows  |  "
          f"{len(df_cands):,} connection records")

    print(f"[+] Scoring {len(candidates):,} flows ...")
    df_scores = score_flows(df_cands)
    print(f"    Scored: {len(df_scores):,} flows")

    # --- Write outputs
    csv_path    = args.out_dir / f"beacon_scores_{stamp}.csv"
    report_path = args.out_dir / f"beacon_report_{stamp}.txt"
    plot_path   = args.out_dir / f"beacon_plot_{stamp}.png"

    df_scores.to_csv(csv_path, index=False)
    print(f"[+] CSV saved → {csv_path}")

    make_plot(df_scores, stats, plot_path)
    write_report(df_scores, stats, args.log, args.top, report_path)


if __name__ == "__main__":
    main()