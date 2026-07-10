"""Tests for the shared digest stats module.

Two purposes:
  1. Lock the seam - `_rate` and `_share` behave correctly at their gates
     and floors, and the constants live where they should.
  2. Prevent regressions of the factoring - `_rate` has a single source
     of truth (function identity across all three importing cards), and
     `RATE_FLOOR` resolves to the same numeric value everywhere.

The existing tests/test_digest_{dns,syslog,cloudtrail}.py suites continuing
to pass UNCHANGED is the compatibility proof that Fix 2 was
behavior-preserving. These tests layer additional invariants at the
boundary.
"""

from __future__ import annotations

import pandas as pd

from sigwood.digest import _stats
from sigwood.digest import cloudtrail as ct
from sigwood.digest import dns
from sigwood.digest import syslog


# ─── Sharing invariants ─────────────────────────────────────────────────────

def test_rate_identity_across_cards() -> None:
    """All three cards reference the same `_rate` function object - no
    shadowing copies. Function identity is meaningful here: any future
    re-introduction of a local copy would break `is`."""
    assert ct._rate is _stats._rate
    assert dns._rate is _stats._rate
    assert syslog._rate is _stats._rate


def test_rate_floor_value_across_cards() -> None:
    """RATE_FLOOR is an immutable float; check by equality, not `is`.
    Identity on a float is brittle and misleading."""
    assert (
        ct.RATE_FLOOR
        == dns.RATE_FLOOR
        == syslog.RATE_FLOOR
        == _stats.RATE_FLOOR
        == 0.01
    )


def test_share_gate_value() -> None:
    """SHARE_GATE lives in _stats and is the canonical 0.80 threshold."""
    assert _stats.SHARE_GATE == 0.80
    assert ct.SHARE_GATE is _stats.SHARE_GATE  # constant re-import, same float


# ─── _rate behavior ─────────────────────────────────────────────────────────

def test_rate_dashes_below_population_floor() -> None:
    """POPULATION_FLOOR is 5 - a 4-event mask returns None regardless of
    fraction."""
    mask = pd.Series([True, True, True, True])
    contributor = pd.Series(["x", "x", "x", "x"])
    assert _stats._rate(mask, contributor) is None


def test_rate_dashes_when_kind_count_is_zero() -> None:
    """Above floor but no matching events - return None even though the
    population is fine."""
    mask = pd.Series([False] * 20)
    contributor = pd.Series(["x"] * 20)
    assert _stats._rate(mask, contributor) is None


def test_rate_dashes_below_rate_floor() -> None:
    """200 events with 1 hit = 0.5% < RATE_FLOOR (1%) → dashes."""
    mask = pd.Series([False] * 199 + [True])
    contributor = pd.Series(["x"] * 199 + ["badcode"])
    assert _stats._rate(mask, contributor) is None


def test_rate_speaks_with_top_contributor() -> None:
    """50 events, 10 errored (20%), contributor "AccessDenied" is the mode
    among the errored subset - returns (0.20, "AccessDenied")."""
    mask = pd.Series([False] * 40 + [True] * 10)
    contributor = pd.Series(
        ["clean"] * 40 + ["AccessDenied"] * 7 + ["ValidationException"] * 3
    )
    result = _stats._rate(mask, contributor)
    assert result is not None
    fraction, top = result
    assert fraction == 0.20
    assert top == "AccessDenied"


def test_rate_drops_nan_contributors_in_mode() -> None:
    """Top contributor lookup ignores NaN values among matching rows -
    matches the dns/syslog/cloudtrail contract before factoring."""
    mask = pd.Series([True] * 10 + [False] * 90)
    contributor = pd.Series(
        ["alice"] * 5 + [float("nan")] * 5 + ["x"] * 90
    )
    result = _stats._rate(mask, contributor)
    assert result is not None
    fraction, top = result
    assert top == "alice"
    assert fraction == 0.10


# ─── _share behavior ───────────────────────────────────────────────────────

def test_share_speaks_on_single_distinct_value_at_100_percent() -> None:
    """One distinct entity at 100% → speaks. Critically, NO population
    floor - the share statistic exists to surface concentration, and
    low cardinality is the signal, not noise."""
    counts = pd.Series([10], index=["203.0.113.99"])
    result = _stats._share(counts, total=10)
    assert result is not None
    entity, top_share = result
    assert entity == "203.0.113.99"
    assert top_share == 1.0


def test_share_speaks_on_two_distinct_values_with_dominant() -> None:
    """99/100 = 99% concentration on 2 distinct entities → speaks. The
    OLD cliff floor would suppress this; the NEW share statistic does not."""
    counts = pd.Series([99, 1], index=["203.0.113.99", "203.0.113.10"])
    result = _stats._share(counts, total=100)
    assert result is not None
    entity, top_share = result
    assert entity == "203.0.113.99"
    assert top_share == 0.99


def test_share_speaks_exactly_at_gate() -> None:
    """80% at SHARE_GATE = 0.80 → speaks (>=, not >)."""
    counts = pd.Series([80, 20], index=["a", "b"])
    result = _stats._share(counts, total=100)
    assert result is not None
    entity, top_share = result
    assert entity == "a"
    assert top_share == 0.80


def test_share_dashes_just_below_gate() -> None:
    """79.9% just below SHARE_GATE → dashes."""
    counts = pd.Series([799, 201], index=["a", "b"])
    assert _stats._share(counts, total=1000) is None


def test_share_dashes_on_diffuse_distribution() -> None:
    """No single entity above the gate → dashes."""
    counts = pd.Series([30, 25, 20, 15, 10],
                       index=["a", "b", "c", "d", "e"])
    assert _stats._share(counts, total=100) is None


def test_share_defensive_returns_on_empty_or_zero_total() -> None:
    assert _stats._share(pd.Series([], dtype=int), total=0) is None
    assert _stats._share(pd.Series([], dtype=int), total=100) is None
    assert _stats._share(pd.Series([5], index=["a"]), total=0) is None


def test_share_defensive_return_on_nan_rank1() -> None:
    """A NaN top count is meaningless - return None rather than crashing
    or returning a NaN-share."""
    counts = pd.Series([float("nan")], index=["a"])
    assert _stats._share(counts, total=10) is None


# ─── select_insights_and_fields behavior ────────────────────────────────────
#
# The shared selection helper that the four schema summarisers all use.
# Only suppress from fields when an insight actually ran (formatter present
# AND used). Missing formatter keeps the slot in fields, preserving "each
# fact appears exactly once."

from sigwood.common.finding import DigestSlot


def _cliff_slot(label: str, *, ratio: float, magnitude: float = 1.0) -> DigestSlot:
    return DigestSlot(
        label=label, statistic="cliff",
        cells=["entity-a", f"{int(magnitude)}", f"{ratio:.1f}x"],
        entity="entity-a", magnitude=magnitude, ratio=ratio,
    )


def _dist_slot(label: str, cells_text: str) -> DigestSlot:
    return DigestSlot(label=label, statistic="dist", cells=[cells_text])


def _nonspeaking(label: str, statistic: str = "cliff") -> DigestSlot:
    return DigestSlot(label=label, statistic=statistic)


def test_select_promotes_top_three_by_salience() -> None:
    """Speaking cliff slots sort by ratio desc; top-3 with a formatter
    become insights. Non-promoted cliff slot stays in fields."""
    slots = [
        _cliff_slot("a", ratio=5.0),
        _cliff_slot("b", ratio=10.0),
        _cliff_slot("c", ratio=2.0),
        _cliff_slot("d", ratio=20.0),
    ]
    formatters = {label: (lambda s, l=label: f"{l}-insight") for label in "abcd"}
    insights, fields = _stats.select_insights_and_fields(slots, formatters)
    # Top 3 by ratio desc: d (20), b (10), a (5). c is not promoted.
    assert insights == ["d-insight", "b-insight", "a-insight"]
    assert [f.label for f in fields] == ["c"]


def test_select_dist_slots_pass_through_unfiltered() -> None:
    """Dist slots never produce insights; they always pass through to
    fields when they have cells."""
    slots = [
        _dist_slot("qtype-mix", "A 50% · AAAA 30%"),
        _cliff_slot("client-volume", ratio=5.0),
    ]
    formatters = {"client-volume": lambda s: "client-volume-insight"}
    insights, fields = _stats.select_insights_and_fields(slots, formatters)
    assert insights == ["client-volume-insight"]
    # qtype-mix not promoted; client-volume promoted → suppressed.
    assert [f.label for f in fields] == ["qtype-mix"]


def test_select_missing_formatter_keeps_slot_as_field() -> None:
    """A gating slot whose label has no formatter falls through to fields
    instead of vanishing. 'Each fact appears exactly once' must not lose
    facts to a missing formatter."""
    slots = [
        _cliff_slot("with-fmt", ratio=10.0),
        _cliff_slot("no-fmt", ratio=20.0),  # higher salience but no fmt
    ]
    formatters = {"with-fmt": lambda s: "with-fmt-insight"}
    insights, fields = _stats.select_insights_and_fields(slots, formatters)
    # no-fmt ranks first by salience but cannot become an insight; it
    # falls through to fields. with-fmt is the only promoted slot.
    assert insights == ["with-fmt-insight"]
    assert [f.label for f in fields] == ["no-fmt"]


def test_select_non_speaking_slots_omitted_from_both() -> None:
    """A slot with cells=None vanishes from BOTH insights and fields -
    the renderer never sees the non-speaking state."""
    slots = [
        _cliff_slot("speaks", ratio=10.0),
        _nonspeaking("silent"),
    ]
    formatters = {"speaks": lambda s: "speaks-insight"}
    insights, fields = _stats.select_insights_and_fields(slots, formatters)
    assert insights == ["speaks-insight"]
    assert [f.label for f in fields] == []


def test_select_all_speaking_promoted_yields_empty_fields() -> None:
    """The syslog mock case: every speaking slot becomes an insight, so
    the fields block is empty. Card ends on the last insight."""
    slots = [
        _cliff_slot("a", ratio=5.0),
        _cliff_slot("b", ratio=10.0),
        _cliff_slot("c", ratio=2.0),
    ]
    formatters = {label: (lambda s, l=label: f"{l}-insight") for label in "abc"}
    insights, fields = _stats.select_insights_and_fields(slots, formatters)
    assert len(insights) == 3
    assert fields == []


def test_select_share_and_rate_salience_share_bypasses_population_floor() -> None:
    """share salience uses raw percentage; rate salience uses fraction /
    RATE_FLOOR. A heavily concentrated share (90%) outranks a modest
    cliff (5x)."""
    share = DigestSlot(
        label="source-ip", statistic="share",
        cells=["x", "90%"], entity="x", magnitude=90.0, ratio=None,
    )
    cliff = _cliff_slot("event-source", ratio=5.0)
    formatters = {
        "source-ip": lambda s: f"share-{s.magnitude:.0f}",
        "event-source": lambda s: f"cliff-{s.ratio:.0f}",
    }
    insights, _ = _stats.select_insights_and_fields([share, cliff], formatters)
    assert insights == ["share-90", "cliff-5"]
