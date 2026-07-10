#!/usr/bin/env python3
"""
dns_cluster.py - weekly DNS clustering threat hunt
Zeek dns.log (ndjson) → HDBSCAN cluster analysis + entropy-ranked noise report

Usage:
    python dns_cluster.py data/dns/dns.log
    python dns_cluster.py data/dns/dns.log --top 100 --min-size 300
    python dns_cluster.py data/dns/dns.log --out-dir /tmp/hunt

Outputs (written to --out-dir, default ./hunt_output/):
    dns_report_<timestamp>.txt    - full text report + top entropy domains
    dns_domains_<timestamp>.csv   - noise domains with entropy scores
    dns_plot_<timestamp>.png      - cluster size chart + entropy distribution
"""

import argparse
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import hdbscan
from sklearn.preprocessing import StandardScaler


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum cluster size for HDBSCAN - larger = fewer, more meaningful clusters
# 500 produced 299 clusters with heavy fragmentation; 2000 is more appropriate
# for a week of traffic (~600K post-whitelist queries)
MIN_CLUSTER_SIZE = 2000
# Minimum samples - controls how conservative cluster membership is
MIN_SAMPLES = 100

# Additional infrastructure noise to suppress from the entropy report
# (patterns that survive the whitelist but aren't interesting)
INFRA_SUPPRESS = (
    r'\.akam\.net$|\.edgekey\.net$|\.azure-dns\.com$'
    r'|\.nsone\.net$|\.windowsupdate\.com$'
)

# Triage threshold for entropy score - above this warrants a closer look
# Lowered from 2.5: typical noise peaks around 0.8-1.0; nothing exceeded 2.1
# in a calibration run, so 1.8 gives a practical weekly review list
THRESH_HIGH_ENTROPY = 1.8


# ---------------------------------------------------------------------------
# Known-good domain patterns (whitelist)
# Domains matching any of these are excluded before clustering.
# ---------------------------------------------------------------------------

PATTERNS = [
    ('reverse_dns',      r'\.in-addr\.arpa$'),
    ('ipv6_arpa',        r'\.ip6\.arpa$'),
    ('mdns_local',       r'\.local$'),
    ('mdns_service',     r'^_'),
    ('uuid',             r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('ntp',              r'pool\.ntp\.org$|\.ntp\.org$'),
    ('akamai',           r'\.akamai\.net$|\.akamaiedge\.net$|\.akamai\.com$'
                         r'|\.akamaihd\.net$|\.akadns\.net$|\.akamaized\.net$'
                         r'|\.akamaitechnologies\.com$'),
    ('apple_cdn',        r'\.apple\.com$|\.icloud\.com$|\.aaplimg\.com$|\.apple-dns\.net$'),
    ('aws',              r'\.amazonaws\.com$|\.awsglobalaccelerator\.com$|\.cloudfront\.net$'),
    ('google',           r'\.googlevideo\.com$|\.googleapis\.com$|\.gstatic\.com$'
                         r'|\.googleusercontent\.com$|\.googledomains\.com$|\.google\.com$'),
    ('azure',            r'\.azurefd\.net$|\.azureedge\.net$|\.cloudapp\.azure\.com$'
                         r'|\.azurewebsites\.net$|\.trafficmanager\.net$|\.windows\.net$'),
    ('sonos_ws',         r'conn-i-[0-9a-f]+\..*\.sonos\.com$'),
    ('amazon_video',     r'\.amazonvideo\.com$|\.amazon\.com$|\.amazonalexa\.com$|\.a2z\.com$'),
    ('oracle_idcs',      r'\.oraclecloud\.com$|\.oracle\.com$'),
    ('sonos',            r'\.sonos\.com$'),
    ('dropbox',          r'\.dropbox\.com$|\.dropbox-dns\.com$'),
    ('zoom',             r'\.zoom\.us$'),
    ('mozilla',          r'\.mozilla\.net$|\.mozilla\.org$|\.mozgcp\.net$'),
    ('microsoft',        r'\.microsoft\.com$|\.office\.com$|\.live\.com$'
                         r'|\.skype\.com$|\.msidentity\.com$'),
    ('fastly',           r'\.fastly\.net$|\.fastly-edge\.com$'),
    ('tinypass',         r'\.tinypass\.com$'),
    ('atlassian',        r'\.atlassian\.com$|\.atlassian-dev\.net$|\.atl-paas\.net$'),

    ('awsdns',           r'(^|\.)awsdns-\d+\.\w+(\.\w+)?$'),
    ('aws_ns',           r'ns-\d+\.awsdns'),
    ('awswaf',           r'(^|\.)awswaf\.com$'),
    ('ovh_ns',           r'ns\d+\.ovh\.net$|dns\d+\.ovh\.net$'),
    ('ultradns',         r'\.ultradns\.(net|com|org|info|co\.uk)$'),
    ('azure_ns',         r'ns\d+-\d+\.azure-dns\.(com|net|org|info)$'),
    ('backblaze',        r'pod-\d+-\d+-\d+\.backblaze\.com$'
                         r'|pod-\d{3}-\d{4}-\d{2}\.backblaze\.com$|ca\d+\.backblaze\.com$'),
    ('msedge',           r'\.t-msedge\.net$|\.fb-t-msedge\.net$'),
    ('nameservers',      r'^ns\d*[-\.]|\.awsdns-|\.ultradns\.|\.cloudns\.'
                         r'|\.constellix\.|\.digicertdns\.|\.domaincontrol\.'),
    ('diagnostic_dns',   r'\.prod\.diagnostic\.networking\.aws\.dev$'),
    ('oracledns',        r'\.dns\.oraclecloud\.net$'),
    ('sentinelone',      r'\.sentinelone\.net$'),
    ('hcaptcha',         r'\.hcaptcha\.com$'),
    ('sentry',           r'\.sentry\.io$'),
    ('attlocal',         r'\.attlocal\.net$'),
    ('msedge_cdn',       r'\.(ax|bx|ln)-\d+\.(ax|bx|ln)(-dc)?-msedge\.net$'),
    ('splunk_telemetry', r'(^|\.)scs\.splunk\.com$|(^|\.)splunk\.com$'),
    ('netdata',          r'(^|\.)netdata\.cloud$'),
    ('lenovo_mgmt',      r'(^|\.)lenovo\.com$'),
    ('vdinfo_iot',       r'(^|\.)vdinfo\.site$|(^|\.)kvaedit\.site$'),
    ('opendns_diag',     r'^debug\.opendns\.com$'),
    ('web_diag_aws',     r'(^|\.)diagnostic\.networking\.aws\.dev$'),
]

# Pre-compile for performance
_COMPILED_PATTERNS = [(label, re.compile(pat, re.IGNORECASE)) for label, pat in PATTERNS]


def is_whitelisted(query: str) -> bool:
    return any(pat.search(query) for _, pat in _COMPILED_PATTERNS)


def categorize(query: str) -> str:
    for label, pat in _COMPILED_PATTERNS:
        if pat.search(query):
            return label
    return 'uncategorized'


# ---------------------------------------------------------------------------
# Feature engineering helpers
# ---------------------------------------------------------------------------

def q_len(q):        return len(q)
def q_parts(q):      return len(q.split('.'))
def q_suffix_len(q): return len(q.split('.')[-1])
def q_domain_len(q):
    try:    return len(q.split('.')[-2])
    except: return 0


def summit(val):
    """Sum TTL list or pass through scalar."""
    if isinstance(val, (int, float)):
        return float(val)
    return np.array(val, dtype=np.float32).sum()


def entropy(s: str) -> float:
    """
    Composite entropy score for a domain label.
    Combines Shannon entropy with character class heuristics to
    distinguish DGA/random labels from human-readable ones.
    Higher score = more suspicious.
    """
    if not s:
        return 0.0
    s = s.lower()
    n = len(s)

    # Shannon entropy
    counts   = {c: s.count(c) for c in set(s)}
    probs    = [v / n for v in counts.values()]
    shannon  = -sum(p * math.log2(p) for p in probs)

    # Character class ratios
    digits       = sum(c.isdigit() for c in s) / n
    vowels       = sum(c in 'aeiou' for c in s) / n
    unique_ratio = len(set(s)) / n

    # Repetition penalty (runs like 'aaa', '111')
    max_run = run = 1
    for i in range(1, n):
        run = run + 1 if s[i] == s[i-1] else 1
        max_run = max(max_run, run)
    run_penalty = max_run / n

    # Normalize entropy (log2 of ~36-char alphabet a-z0-9)
    norm_entropy = shannon / math.log2(36)

    return (
        1.5 * norm_entropy +
        0.5 * unique_ratio +
        1.0 * digits       -
        0.5 * vowels       -
        0.3 * run_penalty
    )


# ---------------------------------------------------------------------------
# Load and prepare
# ---------------------------------------------------------------------------

def load_and_prepare(log_path: Path) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    Load dns.log, apply whitelist, engineer features.
    Returns (feature_df, query_series, stats_dict).
    """
    print(f"[+] Loading {log_path} ...")
    records = []
    skipped = 0
    with open(log_path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                skipped += 1
                if skipped <= 5:
                    print(f"    [!] Skipping line {i}: {e}")

    df_raw = pd.DataFrame(records)
    raw_rows = len(df_raw)

    t_start = pd.to_datetime(df_raw['ts'].min(), unit='s', utc=True)
    t_end   = pd.to_datetime(df_raw['ts'].max(), unit='s', utc=True)
    span_h  = (df_raw['ts'].max() - df_raw['ts'].min()) / 3600

    print(f"    {raw_rows:,} rows  |  {t_start.strftime('%Y-%m-%d %H:%M')} → "
          f"{t_end.strftime('%Y-%m-%d %H:%M')}  ({span_h:.1f}h)"
          + (f"  [{skipped} lines skipped]" if skipped else ""))

    # Internet DNS only (qclass=1), drop whitelisted domains
    df = df_raw[df_raw['qclass'] == 1].copy().reset_index(drop=True)
    before_wl = len(df)
    df = df[~df['query'].apply(is_whitelisted)].reset_index(drop=True)
    after_wl  = len(df)

    print(f"    After qclass filter + whitelist: {after_wl:,} rows "
          f"({before_wl - after_wl:,} whitelisted)")

    # Save queries before feature engineering drops the column
    qs = df['query'].copy()

    # Drop metadata columns not useful for clustering
    drop_cols = [c for c in """ts uid id.orig_h id.orig_p id.resp_h id.resp_p
                  proto qclass qclass_name qtype_name rcode_name
                  AA RD RA Z trans_id rejected""".split() if c in df.columns]
    df.drop(columns=drop_cols, inplace=True)

    # --- Feature engineering
    df['rtt']   = df['rtt'].fillna(df['rtt'].median())
    df['TTLs']  = df['TTLs'].fillna(0).apply(summit)
    df['rtt']   = np.log1p(df['rtt'])
    df['TTLs']  = np.log1p(df['TTLs'])
    df['rcode'] = df['rcode'].fillna(-1)

    df['qlen']    = qs.apply(q_len)
    df['qparts']  = qs.apply(q_parts)
    df['sufflen'] = qs.apply(q_suffix_len)
    df['domlen']  = qs.apply(q_domain_len)

    df['answers'] = df['answers'].apply(
        lambda x: len(x) if isinstance(x, list) else 0
    )
    df['TC'] = df['TC'].fillna(0).astype(int)

    # TLD one-hot (top 20 + 'other')
    df['TLD']    = qs.apply(lambda q: q.split('.')[-1])
    top_tlds     = df['TLD'].value_counts().nlargest(20).index
    df['TLD']    = df['TLD'].where(df['TLD'].isin(top_tlds), 'other')
    df           = pd.get_dummies(df, columns=['TLD'], drop_first=True)

    df.drop(columns='query', inplace=True)

    # Standardize numeric features
    num_cols = ['rtt', 'TTLs', 'qlen', 'qparts', 'sufflen', 'domlen', 'answers']
    df[num_cols] = (df[num_cols] - df[num_cols].mean()) / df[num_cols].std()

    stats = {
        'raw_rows'    : raw_rows,
        'after_wl'    : after_wl,
        'whitelisted' : before_wl - after_wl,
        'skipped'     : skipped,
        't_start'     : t_start,
        't_end'       : t_end,
        'span_h'      : span_h,
    }

    return df, qs, stats


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def run_clustering(df: pd.DataFrame,
                   min_cluster_size: int,
                   min_samples: int) -> np.ndarray:
    """Run HDBSCAN on feature matrix, return label array."""
    print(f"[+] Clustering {len(df):,} records "
          f"(min_cluster_size={min_cluster_size}, min_samples={min_samples}) ...")
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        core_dist_n_jobs=-1,
        prediction_data=True,
    )
    labels = clusterer.fit_predict(df.to_numpy())
    print(f"    Done.")
    return labels


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------

def make_plot(qs: pd.Series, labels: np.ndarray,
              noise_df: pd.DataFrame, stats: dict, out_path: Path):
    plt.style.use('dark_background')

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    date_str = (stats['t_start'].strftime('%Y-%m-%d') + ' - ' +
                stats['t_end'].strftime('%Y-%m-%d'))
    fig.suptitle(f"DNS Cluster Hunt  |  {date_str}  ({stats['span_h']:.1f}h)",
                 fontsize=13, y=1.01)

    # --- Left: cluster size bar chart
    ax = axes[0]
    cluster_ids   = sorted(set(labels))
    cluster_sizes = [np.sum(labels == c) for c in cluster_ids]

    # Separate noise from clusters for coloring
    colors = ['#ff4a4a' if c == -1 else '#4a9eff' for c in cluster_ids]
    bar_labels = [f'noise' if c == -1 else f'C{c}' for c in cluster_ids]

    bars = ax.bar(range(len(cluster_ids)), cluster_sizes, color=colors,
                  edgecolor='none', alpha=0.85)
    ax.set_xticks(range(len(cluster_ids)))
    ax.set_xticklabels(bar_labels, rotation=45, ha='right', fontsize=8)
    ax.set_xlabel('Cluster', fontsize=11)
    ax.set_ylabel('Query count', fontsize=11)
    ax.set_title(f'Cluster Sizes\n({len([c for c in cluster_ids if c >= 0])} clusters  '
                 f'+ {np.sum(labels == -1):,} noise)', fontsize=10)

    # Annotate bar values
    for bar, size in zip(bars, cluster_sizes):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 50,
                f'{size:,}', ha='center', va='bottom', fontsize=7, color='white')

    # --- Right: noise entropy distribution
    ax2 = axes[1]
    ax2.hist(noise_df['label_entropy'], bins=50,
             color='#4aff9e', edgecolor='none', alpha=0.8)
    ax2.axvline(THRESH_HIGH_ENTROPY, color='#ff4a4a', linestyle='--',
                linewidth=1.2,
                label=f'High threshold ({THRESH_HIGH_ENTROPY})')

    n_high = (noise_df['label_entropy'] >= THRESH_HIGH_ENTROPY).sum()
    ax2.text(THRESH_HIGH_ENTROPY + 0.05,
             ax2.get_ylim()[1] * 0.85,
             f"≥{THRESH_HIGH_ENTROPY}: {n_high:,} domains",
             fontsize=9, color='white')

    ax2.set_xlabel('Entropy Score', fontsize=11)
    ax2.set_ylabel('Domain count', fontsize=11)
    ax2.set_title(f'Noise Domain Entropy Distribution\n({len(noise_df):,} unclustered domains)',
                  fontsize=10)
    ax2.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Plot saved → {out_path}")


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

def write_report(qs: pd.Series, labels: np.ndarray,
                 noise_df: pd.DataFrame, stats: dict,
                 log_path: Path, top_n: int, out_path: Path):

    cluster_ids = sorted(c for c in set(labels) if c >= 0)
    n_clusters  = len(cluster_ids)
    n_noise     = int(np.sum(labels == -1))
    n_total     = len(labels)
    n_high      = int((noise_df['label_entropy'] >= THRESH_HIGH_ENTROPY).sum())

    lines = []
    w = lines.append

    w("=" * 72)
    w("  DNS CLUSTER THREAT HUNT REPORT")
    w("=" * 72)
    w(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"  Log file  : {log_path}")
    w(f"  Window    : {stats['t_start'].strftime('%Y-%m-%d %H:%M')} UTC  →  "
      f"{stats['t_end'].strftime('%Y-%m-%d %H:%M')} UTC  ({stats['span_h']:.1f}h)")
    w("")
    w("  DATA SUMMARY")
    w("  " + "-" * 40)
    w(f"  Raw dns.log rows   : {stats['raw_rows']:>10,}")
    w(f"  After whitelist    : {stats['after_wl']:>10,}  ({stats['whitelisted']:,} whitelisted)")
    w(f"  Clustered          : {n_total:>10,}")
    w("")
    w("  CLUSTERING SUMMARY")
    w("  " + "-" * 40)
    w(f"  Clusters found     : {n_clusters:>10,}")
    w(f"  Noise (unclustered): {n_noise:>10,}  ({n_noise/n_total*100:.1f}%)")
    w(f"  High entropy noise : {n_high:>10,}  (entropy ≥ {THRESH_HIGH_ENTROPY})")
    w("")

    # Cluster breakdown
    w("  CLUSTER BREAKDOWN")
    w("  " + "-" * 40)
    w(f"  {'ID':>4}  {'SIZE':>8}  {'PCT':>6}  SAMPLE DOMAINS")
    w("  " + "-" * 40)
    for cid in cluster_ids:
        mask    = labels == cid
        size    = mask.sum()
        pct     = size / n_total * 100
        samples = qs[mask].unique()[:4]
        sample_str = '  '.join(samples)
        w(f"  {cid:>4}  {size:>8,}  {pct:>5.1f}%  {sample_str}")
    w("")

    # Entropy distribution of noise
    w("  NOISE ENTROPY DISTRIBUTION")
    w("  " + "-" * 40)
    bins = [(3.0, 99), (2.5, 3.0), (2.0, 2.5), (1.5, 2.0), (0.0, 1.5)]
    for lo, hi in bins:
        n = ((noise_df['label_entropy'] >= lo) &
             (noise_df['label_entropy'] < hi)).sum()
        bar = '█' * int(n / max(len(noise_df), 1) * 40)
        hi_str = f"{hi:.1f}" if hi < 99 else " ∞ "
        w(f"  {lo:.1f}-{hi_str} : {n:6,}  {bar}")
    w("")

    # Top N high entropy domains
    w(f"  TOP {top_n} DOMAINS BY ENTROPY SCORE")
    w(f"  (unclustered noise only - whitelisted domains already excluded)")
    w("  " + "-" * 50)
    w(f"  {'ENTROPY':>8}  DOMAIN")
    w("  " + "-" * 50)
    for _, row in noise_df.head(top_n).iterrows():
        flag = "  ◄ HIGH" if row['label_entropy'] >= THRESH_HIGH_ENTROPY else ""
        w(f"  {row['label_entropy']:>8.3f}  {row['query']}{flag}")
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
        description="DNS cluster threat hunt - Zeek dns.log → cluster report"
    )
    parser.add_argument("log",           type=Path, help="Path to Zeek dns.log (ndjson)")
    parser.add_argument("--top",         type=int,  default=250,
                        help="Top N entropy domains in report (default: 250)")
    parser.add_argument("--min-size",    type=int,  default=MIN_CLUSTER_SIZE,
                        help=f"HDBSCAN min_cluster_size (default: {MIN_CLUSTER_SIZE})")
    parser.add_argument("--min-samples", type=int,  default=MIN_SAMPLES,
                        help=f"HDBSCAN min_samples (default: {MIN_SAMPLES})")
    parser.add_argument("--out-dir",     type=Path, default=Path("hunt_output"),
                        help="Output directory (default: ./hunt_output/)")
    args = parser.parse_args()

    if not args.log.exists():
        print(f"[!] Log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- Run pipeline
    df_features, qs, stats = load_and_prepare(args.log)

    labels = run_clustering(df_features, args.min_size, args.min_samples)

    # Build noise DataFrame with entropy scores
    noise_mask = labels == -1
    noise_queries = np.unique(qs[noise_mask].values)
    noise_df = pd.DataFrame({'query': noise_queries})
    noise_df['label_entropy'] = noise_df['query'].apply(
        lambda q: entropy(q.split('.')[0])
    )
    # Suppress remaining infra noise
    noise_df = noise_df[~noise_df['query'].str.contains(
        INFRA_SUPPRESS, case=False, regex=True
    )]
    noise_df = noise_df.sort_values('label_entropy', ascending=False).reset_index(drop=True)

    n_clusters = len(set(labels) - {-1})
    n_noise    = int(noise_mask.sum())
    print(f"    {n_clusters} clusters  |  {n_noise:,} noise records  "
          f"({n_noise/len(labels)*100:.1f}%)  |  "
          f"{len(noise_df):,} unique noise domains")

    # --- Write outputs
    csv_path    = args.out_dir / f"dns_domains_{stamp}.csv"
    report_path = args.out_dir / f"dns_report_{stamp}.txt"
    plot_path   = args.out_dir / f"dns_plot_{stamp}.png"

    noise_df.to_csv(csv_path, index=False)
    print(f"[+] CSV saved → {csv_path}")

    make_plot(qs, labels, noise_df, stats, plot_path)
    write_report(qs, labels, noise_df, stats, args.log, args.top, report_path)


if __name__ == "__main__":
    main()