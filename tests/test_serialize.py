"""to_jsonable - the single serialization owner (the invalid-JSON bug fix)."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone

import numpy as np
import pytest

from sigwood.outputs._serialize import jsonable_to_human, to_jsonable


def test_numpy_int_becomes_json_int() -> None:
    v = to_jsonable(np.int64(42))
    assert v == 42
    assert isinstance(v, int) and not isinstance(v, bool)


def test_numpy_bool_becomes_python_bool() -> None:
    v = to_jsonable(np.bool_(True))
    assert v is True
    assert isinstance(v, bool)


def test_python_bool_not_coerced_to_int() -> None:
    # bool is an int subclass - bool MUST be checked before int.
    assert to_jsonable(True) is True
    assert to_jsonable(False) is False


def test_float_nan_becomes_none() -> None:
    assert to_jsonable(float("nan")) is None
    assert to_jsonable(np.float64("nan")) is None


def test_float_inf_becomes_none() -> None:
    assert to_jsonable(float("inf")) is None
    assert to_jsonable(float("-inf")) is None


def test_finite_float_passes_through() -> None:
    assert to_jsonable(np.float64(0.61)) == pytest.approx(0.61)
    assert to_jsonable(0.0) == 0.0


def test_set_becomes_sorted_list() -> None:
    assert to_jsonable({3, 1, 2}) == [1, 2, 3]
    assert to_jsonable(frozenset({2, 1})) == [1, 2]


def test_heterogeneous_set_does_not_raise() -> None:
    # plain sorted({1, "a"}) raises TypeError; key=repr must keep it safe.
    out = to_jsonable({1, "a"})
    assert isinstance(out, list)
    assert set(out) == {1, "a"}


def test_datetime_becomes_isoformat() -> None:
    dt = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    assert to_jsonable(dt) == dt.isoformat()


def test_ndarray_becomes_list() -> None:
    assert to_jsonable(np.array([1, 2, 3])) == [1, 2, 3]
    # nested values are recursed (numpy floats normalised)
    assert to_jsonable(np.array([1.5, 2.5])) == [1.5, 2.5]


def test_nested_recurse() -> None:
    value = {
        "score": np.float64(0.5),
        "ok": np.bool_(False),
        "states": {"SF", "S1"},
        "bad": float("nan"),
        "nested": {"count": np.int64(7)},
    }
    out = to_jsonable(value)
    assert out["score"] == pytest.approx(0.5)
    assert out["ok"] is False
    assert sorted(out["states"]) == ["S1", "SF"]
    assert out["bad"] is None
    assert out["nested"]["count"] == 7


def test_pandas_nat_becomes_none() -> None:
    pd = pytest.importorskip("pandas")
    assert to_jsonable(pd.NaT) is None


def test_pandas_timestamp_becomes_iso() -> None:
    pd = pytest.importorskip("pandas")
    ts = pd.Timestamp("2026-06-01T12:00:00Z")
    assert to_jsonable(ts) == ts.isoformat()


def test_dict_keys_stringified() -> None:
    assert to_jsonable({1: "a", 2: "b"}) == {"1": "a", "2": "b"}


def test_result_is_json_serializable() -> None:
    # The real proof: the whole normalised structure is valid JSON with allow_nan=False.
    value = {
        "i": np.int64(1), "f": np.float64(2.5), "nan": float("nan"),
        "b": np.bool_(True), "s": {1, 2}, "arr": np.array([1, 2]),
        "dt": datetime(2026, 6, 1, tzinfo=timezone.utc),
    }
    encoded = json.dumps(to_jsonable(value), allow_nan=False)
    decoded = json.loads(encoded)
    assert decoded["nan"] is None
    assert decoded["i"] == 1
    assert decoded["b"] is True


def test_never_raises_on_unknown_object() -> None:
    class Weird:
        def __repr__(self) -> str:
            return "weird-thing"

    assert to_jsonable(Weird()) == "weird-thing"


# ── jsonable_to_human - the shared csv/html value renderer ───────────────────
def test_jsonable_to_human_separators_and_sorted_dict() -> None:
    value = {"b": 2, "a": [1, True]}
    # csv style (tight) vs html style (spaced); dict keys sorted, bool lowercased.
    assert jsonable_to_human(value, item_sep=",", kv_sep=":") == "a:1,true,b:2"
    assert jsonable_to_human(value, item_sep=", ", kv_sep=": ") == "a: 1, true, b: 2"


def test_jsonable_to_human_none_and_scalars() -> None:
    assert jsonable_to_human(None, item_sep=",", kv_sep=":") == ""
    assert jsonable_to_human(False, item_sep=",", kv_sep=":") == "false"
    assert jsonable_to_human(0.5, item_sep=",", kv_sep=":") == "0.5"
