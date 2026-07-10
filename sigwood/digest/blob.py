"""blob summariser - orient-before-the-hunt for unrecognized sources.

The blob path is the digest's escape hatch for inputs that have NO parser.
It describes bytes as bytes and extracts zero fields - not even a timestamp.
The moment any code reads a field it has become a parser, and parsers are a
separate component with a separate contract; the blob path exists precisely
so the operator can point digest at an unknown source and get a visibly
degraded card rather than an error and a shrug.

O(sample) rail (non-negotiable): the profiler reads ONE bounded sample and
profiles THAT. A 1 GB file and a 1 KB file cost the same. The only whole-file
fact is the on-disk size (a stat, free). Random seeks for plain files;
head-only decompressed prefix for gzip. drain3 - the only expensive item -
runs over the sampled lines, behind a quarantine flag, and is suppressed by a
meaninglessness floor when its output would be vacuous.

Identification cascade: magic bytes first (TERMINAL - content IS the
artifact; CONTAINER - bytes are compressed transport, decompress and look
underneath). Char-class profile next (binary or text, sample-derived
fraction). Shape-guess for text: a labeled best-guess (JSON / CSV / TSV /
HTML / key-value / long-lines / freeform) that drives the headline. Every
output is a GUESS, never a parsed claim.

Determinism: seek offsets are derived from file size (evenly spaced
fractions), so the same file always yields the same sample and the same
card. No unseeded randomness.

Per-file boundary discipline: blob today is single-file under the sniff
path. The decode-per-chunk discipline is preserved at the helper boundary so
a future multi-file return cannot silently merge line N of file A with
line 1 of file B and falsify line/template/token facts.
"""

from __future__ import annotations

import bz2
import gzip
import json
import lzma
import re
import statistics
from collections import Counter
from pathlib import Path

from sigwood.common.finding import BlobCard


# ── Calibration constants ────────────────────────────────────────────────────

# Plain-file sample budget. Head + K seeks; each seek reads a bounded byte
# window. Total bytes read ≤ _HEAD_BYTES + _SEEK_COUNT * _SEEK_BYTES + slack
# for "skip to next newline" tails. Bounded regardless of file size - the rail.
_HEAD_BYTES = 64 * 1024            # 64 KB head
_SEEK_COUNT = 5                    # 5 evenly-spaced seek points
_SEEK_BYTES = 32 * 1024            # 32 KB per seek
# A file must be larger than the head + seek budget by this factor to bother
# with seeks - smaller files are fully covered by the head alone.
_SEEK_MIN_SIZE = _HEAD_BYTES * 4

# Compressed (head-only) sample budget.
_DECOMPRESSED_PREFIX_BYTES = 256 * 1024  # 256 KB after decompression

# Hard cap on lines profiled. With ~80-char average lines and the head+seeks
# budget above, we expect well under this; the cap protects against
# pathological all-short-lines inputs (e.g. lots of empty lines).
_MAX_SAMPLED_LINES = 8000

# Line-length shape gate (unchanged).
_SHAPE_CV_GATE = 0.5

# Token / template caps.
_TOP_TEMPLATE_N = 6
_TOP_TOKENS_N = 10

# drain3 engine config - mirrors the syslog detector's defaults; do not import
# from detectors/syslog.py, blob is upstream of any parsed frame.
_DRAIN_SIM_TH = 0.5
_DRAIN_DEPTH = 4
_DRAIN_PARAMETRIZE_NUMERIC = True

# QUARANTINE switch. When False, drain3 does not run and Templates slot
# vanishes on every blob card - the renderer copes because every template
# field is Optional. Flip to False from the perf probe if sampled-drain3
# proves too slow.
_BLOB_DRAIN3_ENABLED = True

# Meaninglessness floor: when distinct_templates / sampled_lines exceeds this
# ratio, the output is nearly 1-template-per-line - freeform that does not
# template. Suppress the result; renderer vanishes the slot. Better silent
# than vacuous ("~480 distinct structures over 500 lines" tells nothing).
_TEMPLATE_RATIO_FLOOR = 0.5

# Char-class binary floor: a non-magic sample that is NOT clean UTF-8 AND whose
# printable-byte share falls below this reads as binary, not a text log - route it
# to the binary card rather than letting the text cascade call it "freeform text"
# with mojibake tokens (the honesty rail: never paint binary as a log). The
# utf8-clean guard spares heavily-multibyte text (CJK/emoji), whose continuation
# bytes count as non-printable but decode cleanly; single-byte text logs sit far
# above the floor (>95% printable).
_BINARY_PRINTABLE_FLOOR = 70.0

# Printable byte set: TAB, LF, CR, plus space..tilde (0x20..0x7E).
_PRINTABLE_BYTES = frozenset(b"\t\n\r") | frozenset(range(0x20, 0x7F))

# 256-entry translation table - 0x01 for printable, 0x00 for everything else.
# Lets us count printables in C via bytes.translate + bytes.count instead of
# a Python-level loop over every byte. Operates on the sample only.
_PRINTABLE_TRANSLATE = bytes(
    1 if i in _PRINTABLE_BYTES else 0
    for i in range(256)
)


# ── Shape-guess patterns (compiled once; never recompiled in the line loop) ───
# HTML/XML: a line that (stripped) BEGINS with a markup tag - `<tag` / `</tag` /
# `<!DOCTYPE` / `<?xml` - NOT a mid-line `<...>` token (the over-claim bug).
_HTML_TAG_RE = re.compile(r"^<[/!?A-Za-z]")
# key=value (permissive): leads with `key=value` (logfmt / .env). A digit-led
# timestamp key never matches, so a `=`-free `2024-... ` log line rejects.
_KV_EQ_RE = re.compile(r"^[A-Za-z_][\w.-]*\s*=\s*\S")
# key: value (STRICT): a bareword-key colon-space pair; >=2 per line is a
# config-ish density. `installd[123]:` has a `[` after the word -> not a bareword
# colon; a single `kernel: prose` log line has ONE pair -> rejects.
_KV_COLON_RE = re.compile(r"(?:^|\s)[A-Za-z_][\w.-]*:\s")


# ── Magic-byte signature table ──────────────────────────────────────────────
#
# Hand-rolled, zero dependency. TERMINAL = content IS the artifact (image,
# binary, document) - no point profiling text underneath, because there is
# none. CONTAINER = bytes are compressed transport - switch to the
# decompressed-head path and profile the content shape underneath.
#
# Order matters within each list: longer/more-specific prefixes first. Each
# entry is (prefix_bytes, label).
#
# Container support: gzip, bzip2, xz - all stdlib (gzip / bz2 / lzma). The
# magic-byte ID is authoritative; suffix is a fast-path hint only (see
# _open_log_bytes). zstd is DEFERRED - no stdlib opener before Python 3.14,
# would add a dependency for a blob-nicety; revisit when the toolchain
# minimum bumps.

_TERMINAL_MAGIC: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff",      "JPEG image"),
    (b"GIF87a",            "GIF image"),
    (b"GIF89a",            "GIF image"),
    (b"%PDF-",             "PDF document"),
    (b"\x7fELF",           "ELF binary"),
    (b"PK\x03\x04",        "zip archive"),
    (b"PK\x05\x06",        "zip archive (empty)"),
    (b"PK\x07\x08",        "zip archive (spanned)"),
    (b"\xca\xfe\xba\xbe",  "Java class file"),
    (b"\x00asm",           "WebAssembly module"),
    (b"SQLite format 3\x00", "SQLite database"),
]

_CONTAINER_MAGIC: list[tuple[bytes, str]] = [
    (b"\x1f\x8b",          "gzip"),
    (b"\xfd7zXZ\x00",      "xz"),
    (b"BZh",               "bzip2"),
]

# Suffix → container label fast-path. The magic table above is the canonical
# identifier; this mapping just lets us skip the magic read on the well-named
# common case. A correctly-named .gz / .bz2 / .xz file is opened directly via
# the matching stdlib opener; an UNKNOWN suffix (or a misnamed .log that
# happens to be xz-compressed) is identified by magic and routed to the same
# opener - see summarize_blob and _open_log_bytes.
_SUFFIX_TO_CONTAINER: dict[str, str] = {
    ".gz":  "gzip",
    ".bz2": "bzip2",
    ".xz":  "xz",
}


# ── File openers ────────────────────────────────────────────────────────────

def _open_log_bytes(path: Path, container_label: str | None = None):
    """Open a plain or container-compressed file in binary mode.

    Parallel to common.loader._open_log but bytes-mode - the blob path needs
    pre-decode access for the char-class profile and the strict UTF-8 probe.

    ``container_label`` is the magic-derived container kind (one of
    ``"gzip"``, ``"bzip2"``, ``"xz"``) when the caller already identified
    the file as compressed. When ``None``, the path suffix is consulted as a
    fast-path hint; an unmatched suffix opens the file plain. Magic-driven
    callers should pass ``container_label`` explicitly so a misnamed
    container (xz bytes in ``mystery.log``) routes to the correct opener.
    """
    if container_label is None:
        container_label = _SUFFIX_TO_CONTAINER.get(path.suffix.lower())
    if container_label == "gzip":
        return gzip.open(path, "rb")
    if container_label == "bzip2":
        return bz2.open(path, "rb")
    if container_label == "xz":
        return lzma.open(path, "rb")
    return path.open("rb")


# ── Sampling ────────────────────────────────────────────────────────────────

def _read_head(path: Path) -> bytes:
    """Read the first _HEAD_BYTES bytes of a plain file."""
    with path.open("rb") as fh:
        return fh.read(_HEAD_BYTES)


def _read_seek(path: Path, offset: int) -> bytes:
    """Seek to offset, read a hard-bounded window, return content after the
    first newline within that window.

    O(sample) rail: total bytes pulled from disk is EXACTLY _SEEK_BYTES per
    seek, regardless of where the next newline lives. An unbounded
    ``readline()`` here would scan to EOF on a long-line / no-newline file
    (5 MB single-line file pulled 13 MB through readline()), breaking the
    rail. The discipline: read the bounded window in ONE call; if a newline
    lives inside it, return the post-newline slice (a clean line boundary);
    if not, this seek yielded no usable lines - return an empty chunk and
    let the cascade fall back to the head sample.
    """
    with path.open("rb") as fh:
        fh.seek(offset)
        window = fh.read(_SEEK_BYTES)
    nl = window.find(b"\n")
    if nl < 0:
        return b""
    return window[nl + 1:]


def _sample_plain_body(
    path: Path, head: bytes, st_size: int,
) -> tuple[list[bytes], int]:
    """Read deterministic body-seek chunks for a plain file.

    Returns (body_chunks, sample_read_count). The caller already has the
    head bytes - avoids a duplicate head read.

    Seek offsets are evenly spaced fractions of the file size - deterministic
    by construction; the same file → the same sample. No RNG. For small
    files (≤ _SEEK_MIN_SIZE), skip the seeks; the head alone covers them.
    """
    if st_size <= _SEEK_MIN_SIZE:
        return [], 1

    body_chunks: list[bytes] = []
    # Evenly spaced offsets in (head_end, st_size). Use (k / (K+1)) * st_size
    # so seeks land at 1/6, 2/6, 3/6, 4/6, 5/6 of the file when K=5.
    for k in range(1, _SEEK_COUNT + 1):
        offset = (st_size * k) // (_SEEK_COUNT + 1)
        # Don't seek into the head region - we already have it.
        if offset < _HEAD_BYTES:
            continue
        body_chunks.append(_read_seek(path, offset))
    return body_chunks, 1 + len(body_chunks)


def _sample_compressed(path: Path, container_label: str | None = None) -> bytes:
    """Decompress up to _DECOMPRESSED_PREFIX_BYTES of a compressed file.

    HEAD-ONLY by construction - random seek into a compressed stream is
    invalid for all three supported containers (gzip / bzip2 / xz). The
    bound here is the decompressed prefix size, not the on-disk size; a
    container that decompresses to many GB still costs O(sample) here.

    ``container_label`` is forwarded to ``_open_log_bytes``; pass it
    explicitly when the kind came from magic ID so a misnamed file routes
    correctly.
    """
    with _open_log_bytes(path, container_label) as fh:
        return fh.read(_DECOMPRESSED_PREFIX_BYTES)


# ── Char-class profile (over RAW sampled bytes - sample fact, not whole-file) ─

def _char_class_profile(sample: bytes) -> tuple[float, float]:
    """Return (printable_pct, nonprintable_pct) over the raw sample bytes.

    Printable ≡ TAB, LF, CR, or any byte in [0x20, 0x7E]. Everything else -
    other control characters, 0x7F, the entire 0x80-0xFF range - counts as
    non-printable. This is a SAMPLE fact (computed over the bounded sample
    only). Do not optimize it into a whole-file scan "for accuracy" - that
    would break the O(sample) rail. The Bytes row is honest as a
    sample-derived fraction; sampling bias is acceptable for orientation.
    """
    if not sample:
        return 0.0, 0.0
    translated = sample.translate(_PRINTABLE_TRANSLATE)
    printable = translated.count(b"\x01")
    pct = printable / len(sample) * 100.0
    return pct, 100.0 - pct


# ── UTF-8 cleanness probe ───────────────────────────────────────────────────

def _utf8_probe(sample: bytes) -> bool:
    """True iff the sample decodes strictly as UTF-8.

    A single strict decode over the concatenated sample. The downstream
    line-level decode (in _decode_lines) uses errors="replace" so the
    profiler is robust to non-UTF-8 bytes - but the renderer only claims
    "UTF-8 clean" when this probe succeeded.

    Per-file note: if multi-file blob ever returns, this concatenation
    becomes a boundary problem - probe per-file and AND the results.
    Today's caller passes a single file's sample, so a flat concat is fine.
    """
    if not sample:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# ── Line decoding ───────────────────────────────────────────────────────────

def _decode_lines(chunk: bytes) -> list[str]:
    """Decode a sample chunk and split to lines, errors=replace.

    Splitlines (no keepends) on the replacement-decoded text. One chunk at a
    time so callers that pass multiple chunks (head + seek chunks for plain)
    preserve per-chunk boundaries - never merge the tail of one chunk with
    the head of the next.
    """
    if not chunk:
        return []
    return chunk.decode("utf-8", errors="replace").splitlines()


# ── Line-length shape ───────────────────────────────────────────────────────

def _line_length_shape(
    lengths: list[int],
) -> tuple[float, float, int, int, float, str]:
    """Return (mean, median, p95, max, stdev, shape) for line lengths.

    ``shape`` is exactly ``"uniform"`` or ``"varied"``. A blob with fewer
    than two lines, or a mean of zero, characterises as ``"uniform"`` (no
    variance to call out). p95 is the 95th percentile of the sample's line
    lengths; for very small samples (< 20 lines) ``statistics.quantiles``
    falls back to a single-quantile estimate via max.
    """
    if not lengths:
        return 0.0, 0.0, 0, 0, 0.0, "uniform"
    mean = statistics.fmean(lengths)
    median = float(statistics.median(lengths))
    max_len = max(lengths)
    # 95th percentile. statistics.quantiles(n=20) interpolates between data
    # points (exclusive method), which can EXTRAPOLATE past max on small
    # samples - e.g. lengths=[1, 100] yields p95=184 with max=100. p95 is
    # supposed to be an order statistic FROM the sample, never beyond it.
    # Need at least 20 data points to land a 95th percentile inside the
    # observed range without extrapolation; below that, collapse to max.
    # The `min(..., max_len)` clamp is belt-and-braces against any other
    # degenerate input that survives the threshold.
    if len(lengths) >= 20:
        p95 = min(int(statistics.quantiles(lengths, n=20)[18]), max_len)
    else:
        p95 = max_len
    if len(lengths) < 2 or mean == 0.0:
        return mean, median, p95, max_len, 0.0, "uniform"
    stdev = statistics.stdev(lengths)
    cv = stdev / mean
    shape = "varied" if cv >= _SHAPE_CV_GATE else "uniform"
    return mean, median, p95, max_len, stdev, shape


# ── Magic-byte identification ────────────────────────────────────────────────

def _magic_id(head: bytes) -> tuple[str | None, str | None, bytes | None]:
    """Return (kind, label, prefix_bytes) where kind ∈ {"terminal","container",None}.

    Compares the first ~16 bytes against the hand-rolled signature tables.
    TERMINAL hits win immediately and skip the text-shape cascade.
    CONTAINER hits switch the caller into decompressed-prefix mode.
    """
    for prefix, label in _TERMINAL_MAGIC:
        if head.startswith(prefix):
            return "terminal", label, prefix
    for prefix, label in _CONTAINER_MAGIC:
        if head.startswith(prefix):
            return "container", label, prefix
    return None, None, None


# ── Shape-guess cascade ─────────────────────────────────────────────────────

def _shape_guess(body_lines: list[str], all_lines: list[str]) -> str:
    """Return a labeled best-guess of the text's shape.

    Input rule: prefer body (seek) lines when available - they avoid being
    fooled by a preamble (Zeek #-header, CSV header row). Fall back to the
    full bounded sample for compressed files (head-only) and small plain
    files (no useful seek body). Never returns None; returns "freeform
    text" as the floor. Output is ALWAYS a guess, never a parsed claim.
    """
    lines = body_lines if body_lines else all_lines
    # Strip empty lines for the structural tests; do not modify the input.
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return "freeform text"

    # JSON: first non-blank starts with { or [, AND a sampled line parses.
    first = non_empty[0].lstrip()
    if first and first[0] in "{[":
        # Try a small handful of lines so the test is cheap.
        for candidate in non_empty[:5]:
            try:
                json.loads(candidate)
                return "JSON"
            except (ValueError, TypeError):
                continue

    # CSV / TSV: consistent delimiter count across the body, ≥ 1 columns.
    for delim, name in ((",", "CSV"), ("\t", "TSV")):
        counts = [ln.count(delim) for ln in non_empty]
        # Require at least one delimiter per line on most lines, and tight
        # consistency: the dominant count covers ≥ 80% of lines.
        nonzero = [c for c in counts if c >= 1]
        if not nonzero:
            continue
        top_count, top_freq = Counter(nonzero).most_common(1)[0]
        if top_freq / len(counts) >= 0.8:
            cols = top_count + 1
            return f"{name}, ~{cols} columns"

    # HTML / XML: lines that (stripped) BEGIN with a markup tag, on >= half.
    # A mid-line `<...>` token (e.g. an Apple `<private>`) does not count.
    tag_lines = sum(1 for ln in non_empty if _HTML_TAG_RE.match(ln.strip()))
    if tag_lines / len(non_empty) >= 0.5:
        return "HTML/XML"

    # key=value (permissive) or >=2 bareword key: value pairs (strict): a
    # config-ish line, NOT a timestamp-led log line. The letter-led key rejects a
    # digit-led ts key (both `2024-06-28 ...` and `2024-06-28T12:00:00...`).
    kv_lines = 0
    for ln in non_empty:
        s = ln.strip()
        if _KV_EQ_RE.match(s) or len(_KV_COLON_RE.findall(s)) >= 2:
            kv_lines += 1
    if kv_lines / len(non_empty) >= 0.6:
        return "key-value text"

    # Long lines / minified.
    mean_len = sum(len(ln) for ln in non_empty) / len(non_empty)
    if mean_len >= 400:
        return f"very long lines (mean {int(mean_len)} chars), possibly minified"

    return "freeform text"


# ── Template structure (drain3) - QUARANTINED + FLOORED ─────────────────────

def _template_structure(
    lines: list[str],
) -> tuple[int, float, int, int] | None:
    """Return (distinct, top_coverage_pct, top_n, singletons) or None.

    Quarantine: returns None when _BLOB_DRAIN3_ENABLED is False (drain3
    dormant). Renderer copes - Templates slot vanishes.

    Meaninglessness floor: returns None when distinct/total exceeds
    _TEMPLATE_RATIO_FLOOR - the input is freeform that doesn't template,
    and saying "~480 distinct templates over 500 lines" is the opposite of
    helpful. Better silent than vacuous.

    drain3 runs over the SAMPLE only. The caller passes the sampled lines,
    never the whole file.
    """
    if not _BLOB_DRAIN3_ENABLED or not lines:
        return None

    try:
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
    except ImportError as exc:
        raise ImportError(
            "drain3 is required for the digest blob path. "
            "Run: pip install drain3"
        ) from exc

    cfg = TemplateMinerConfig()
    cfg.drain_sim_th               = _DRAIN_SIM_TH
    cfg.drain_depth                = _DRAIN_DEPTH
    cfg.parametrize_numeric_tokens = _DRAIN_PARAMETRIZE_NUMERIC

    miner = TemplateMiner(config=cfg)
    counts: Counter[int] = Counter()
    for line in lines:
        result = miner.add_log_message(line)
        counts[int(result["cluster_id"])] += 1

    distinct = len(counts)
    total = sum(counts.values())
    if total == 0:
        return None

    # Meaninglessness floor: near-1:1 templates means freeform.
    if distinct / total >= _TEMPLATE_RATIO_FLOOR:
        return None

    top_counts = counts.most_common(_TOP_TEMPLATE_N)
    top_sum = sum(c for _, c in top_counts)
    top_coverage = top_sum / total * 100.0
    singletons = sum(1 for c in counts.values() if c == 1)
    return distinct, top_coverage, _TOP_TEMPLATE_N, singletons


# ── Top literal tokens (over the sample) ─────────────────────────────────────

def _top_tokens(lines: list[str]) -> list[tuple[str, int]]:
    """Top-N most frequent whitespace-split tokens over the sampled lines.

    Frequency only - no field semantics. The renderer labels this block
    "[literal]" so no reader mistakes counts for parsed fields.
    """
    counter: Counter[str] = Counter()
    for line in lines:
        counter.update(line.split())
    return list(counter.most_common(_TOP_TOKENS_N))


# ── Top-level JSON object keys (over the sample) ────────────────────────────

def _json_field_names(lines: list[str]) -> list[str] | None:
    """First-seen union of top-level JSON object keys across sampled lines.

    O(sample): iterates the already-held sample, no new I/O. For each
    non-blank line that parses as a JSON OBJECT (dict root), walks its
    top-level keys and accumulates them in first-appearance order
    (dedup-preserving-first-seen). Catches optional fields that only
    appear on some rows (e.g. dhcp's ``host_name``).

    Returns None when NO sampled line parses to a dict - top-level JSON
    arrays / scalars / malformed JSON / empty sample. The caller treats
    None as "fall back to the existing tokens row."

    Names only - never reads a value. This is a structural description
    of the bytes' shape (one rung deeper than ``shape: JSON``), strictly
    more rail-respecting than the token dump it replaces, and inherently
    privacy-safe.
    """
    seen_set: set[str] = set()
    seen_list: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        for key in obj.keys():
            if key not in seen_set:
                seen_set.add(key)
                seen_list.append(str(key))
    return seen_list if seen_list else None


# ── Public entry point ──────────────────────────────────────────────────────

def summarize_blob(path: Path) -> BlobCard:
    """Describe the byte stream at ``path`` as bytes. Returns a BlobCard.

    Reads a bounded sample (head + deterministic seeks for plain;
    decompressed prefix for gzip) and profiles THAT. The only whole-file
    fact is byte_size (a stat). Terminal magic hits (PNG, PDF, ELF, etc.)
    short-circuit the text cascade - text slots stay None and the renderer
    vanishes them.
    """
    st_size = path.stat().st_size

    # ── Read head + classify magic ──────────────────────────────────────
    #
    # Container routing is magic-authoritative; suffix is just a fast-path
    # hint so a well-named .gz / .bz2 / .xz skips the head read entirely.
    # An UNKNOWN suffix (e.g. xz bytes in "mystery.log") falls to the
    # magic check, which carries the container label so _sample_compressed
    # opens with the correct stdlib opener.
    suffix_kind = _SUFFIX_TO_CONTAINER.get(path.suffix.lower())
    if suffix_kind is not None:
        # Suffix fast-path: trust the extension, decompress directly. Total
        # bytes pulled this branch = _DECOMPRESSED_PREFIX_BYTES (one read).
        is_compressed = True
        head = _sample_compressed(path, suffix_kind)
        # If the decompressed prefix happens to start with terminal magic
        # (gzipped PNG? unusual), the later _magic_id call still profiles
        # the content as terminal - we route on what is THERE.
        sample_read_count = 1
        body_chunks: list[bytes] = []
    else:
        # Read head ONCE - used for both magic ID and (if no container hit)
        # the sample. Reading it twice would falsify the O(sample) byte
        # budget test as well as do unnecessary work.
        head = _read_head(path)
        kind, label, _prefix = _magic_id(head[:16])
        if kind == "container":
            # Magic-driven container detection on a misnamed file. The
            # label IS the container kind (one of "gzip" / "bzip2" / "xz"
            # - the canonical strings in _SUFFIX_TO_CONTAINER); forward it
            # so the opener routes correctly. Two bounded reads total
            # (head + compressed prefix); rail honored.
            is_compressed = True
            head = _sample_compressed(path, label)
            sample_read_count = 1
            body_chunks = []
        else:
            is_compressed = False
            body_chunks, sample_read_count = _sample_plain_body(
                path, head, st_size,
            )

    # Concatenated sample bytes - used for char-class and UTF-8 probe.
    # Per-file: blob is single-file under sniff today; this concat is over
    # ONE file's chunks, which is fine. Multi-file return would need
    # per-file probes; flagged in the helper docstring.
    sample_bytes = head + b"".join(body_chunks)

    # ── Terminal magic ID on the decompressed head's leading bytes ──────
    # For compressed inputs, we ID the CONTENT under decompression, so the
    # head here is the decompressed prefix. A terminal hit there means the
    # gzipped content is itself a binary artifact (rare but coherent).
    kind, file_type_guess, file_type_magic = _magic_id(head[:16])

    # ── Char-class + UTF-8 on the sample ────────────────────────────────
    printable_pct, nonprintable_pct = _char_class_profile(sample_bytes)
    utf8_clean = _utf8_probe(sample_bytes)

    # Decode lines per chunk (boundary discipline preserved).
    head_lines = _decode_lines(head)
    body_lines: list[str] = []
    for chunk in body_chunks:
        body_lines.extend(_decode_lines(chunk))
    all_sampled_lines = head_lines + body_lines

    # Cap line count (pathological short-line inputs).
    if len(all_sampled_lines) > _MAX_SAMPLED_LINES:
        all_sampled_lines = all_sampled_lines[:_MAX_SAMPLED_LINES]
        # Trim body_lines proportionally - head_lines first, then body.
        if len(head_lines) >= _MAX_SAMPLED_LINES:
            head_lines = head_lines[:_MAX_SAMPLED_LINES]
            body_lines = []
        else:
            remaining = _MAX_SAMPLED_LINES - len(head_lines)
            body_lines = body_lines[:remaining]

    sampled_line_count = len(all_sampled_lines)

    # ── Terminal binary path: skip text cascade, vanish text slots ──────
    if kind == "terminal":
        return BlobCard(
            source_name=path.name,
            byte_size=st_size,
            sampled_line_count=sampled_line_count,
            sample_read_count=sample_read_count,
            is_compressed=is_compressed,
            printable_pct=printable_pct,
            nonprintable_pct=nonprintable_pct,
            utf8_clean=utf8_clean,
            file_type_guess=file_type_guess,
            file_type_magic=file_type_magic,
            shape_guess=None,
        )

    # ── Char-class binary path: no magic, but the sample reads as binary ──
    # A non-magic sample that is NOT clean UTF-8 AND is predominantly non-printable
    # is binary - render the binary card (text slots vanish, like the terminal
    # path but with no file-type ID) rather than forcing the text cascade to call
    # it "freeform text" with mojibake tokens. The utf8-clean guard spares
    # heavily-multibyte text; see _BINARY_PRINTABLE_FLOOR.
    if not utf8_clean and printable_pct < _BINARY_PRINTABLE_FLOOR:
        return BlobCard(
            source_name=path.name,
            byte_size=st_size,
            sampled_line_count=sampled_line_count,
            sample_read_count=sample_read_count,
            is_compressed=is_compressed,
            printable_pct=printable_pct,
            nonprintable_pct=nonprintable_pct,
            utf8_clean=utf8_clean,
            file_type_guess=None,   # no magic ID - a char-class verdict only
            file_type_magic=None,
            shape_guess=None,       # binary → text slots vanish
        )

    # ── Text path: shape-guess, line stats, tokens, templates ───────────
    shape_guess = _shape_guess(body_lines, all_sampled_lines)

    lengths = [len(ln) for ln in all_sampled_lines]
    mean_len, median_len, p95_len, max_len, stdev_len, shape = _line_length_shape(
        lengths
    )

    tokens = _top_tokens(all_sampled_lines)

    # JSON shape-guess only: extract top-level object key NAMES (never
    # values) for the renderer's `fields:` row. On non-JSON shapes and on
    # JSON-of-arrays/scalars this stays None, and the renderer falls back
    # to the existing `tokens:` row.
    if shape_guess == "JSON":
        json_field_names = _json_field_names(all_sampled_lines)
    else:
        json_field_names = None

    template_result = _template_structure(all_sampled_lines)
    if template_result is None:
        distinct = top_cov = top_n = singletons = None
    else:
        distinct, top_cov, top_n, singletons = template_result

    return BlobCard(
        source_name=path.name,
        byte_size=st_size,
        sampled_line_count=sampled_line_count,
        sample_read_count=sample_read_count,
        is_compressed=is_compressed,
        printable_pct=printable_pct,
        nonprintable_pct=nonprintable_pct,
        utf8_clean=utf8_clean,
        file_type_guess=None,
        file_type_magic=None,
        shape_guess=shape_guess,
        mean_line_length=mean_len,
        median_line_length=median_len,
        line_length_p95=p95_len,
        max_line_length=max_len,
        line_length_stdev=stdev_len,
        line_length_shape=shape,
        top_tokens=tokens,
        json_field_names=json_field_names,
        distinct_templates=distinct,
        top_template_coverage_pct=top_cov,
        top_template_n=top_n,
        singleton_template_count=singletons,
    )
