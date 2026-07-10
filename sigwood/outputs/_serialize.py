"""The single serialization owner - ``to_jsonable`` normalizes any value to a
JSON-safe form.

The ``json`` and ``csv`` handlers both route evidence through here so the two
machine surfaces cannot drift on type handling. This is THE fix for the
invalid-JSON bug class (``np.int64`` -> ``"42"`` string, ``np.bool_`` -> ``"True"``
string, ``float('nan')`` -> bare ``NaN`` = invalid JSON, ``set`` -> repr).

``to_jsonable`` NEVER raises - the last resort is ``str(value)``. numpy / pandas
are duck-typed (never imported at module load), so this module imports cleanly
without them installed.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any


def _is_pandas_na(value: Any) -> bool:
    """``True`` iff ``value`` is a pandas NA / NaT scalar. Defensive: returns
    ``False`` when pandas is absent or ``pd.isna`` is given a non-scalar (an
    array result has ``__len__`` and is not a missing-value sentinel)."""
    try:
        import pandas as pd  # local - keep the module import-light

        result = pd.isna(value)
    except Exception:
        return False
    if hasattr(result, "__len__"):  # array-like result -> not a scalar NA
        return False
    return bool(result)


def to_jsonable(value: Any) -> Any:
    """Return a JSON-serialisable form of ``value``. Never raises.

    Rules (order matters):
      - ``None`` -> ``None``.
      - ``bool`` (incl. ``numpy.bool_`` via the scalar branch) -> Python ``bool``.
        Checked BEFORE ``int`` because ``bool`` is an ``int`` subclass.
      - Python ``int`` -> ``int``.
      - ``float`` (incl. ``numpy.float64``, a ``float`` subclass): ``nan`` / ``inf``
        -> ``None``; else ``float``.
      - ``str`` -> ``str``.
      - ``datetime`` -> ``.isoformat()``.
      - ``list`` / ``tuple`` -> ``[to_jsonable(x) ...]``.
      - ``set`` / ``frozenset`` -> elements sorted by a SAFE ``key=repr`` (so a
        heterogeneous ``{1, "a"}`` cannot raise), then ``[to_jsonable(x) ...]``.
      - ``dict`` -> ``{str(k): to_jsonable(v)}``.
      - pandas ``NaT`` / ``NA`` scalar -> ``None``; pandas ``Timestamp`` (any
        object exposing ``.isoformat``) -> ``.isoformat()``.
      - numpy ``ndarray`` (``.tolist()``) -> list, recursed.
      - numpy scalar (``.item()``) -> the Python scalar, re-applied.
      - anything else -> ``str(value)`` (last resort).
    """
    if value is None:
        return None
    if isinstance(value, bool):  # BEFORE int - bool is an int subclass
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):  # also catches numpy.float64 (float subclass)
        if math.isnan(value) or math.isinf(value):
            return None
        return float(value)
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        # pandas NaT is a datetime subclass; like nan it is not equal to itself.
        if value != value:
            return None
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [to_jsonable(x) for x in value]
    if isinstance(value, (set, frozenset)):
        return [to_jsonable(x) for x in sorted(value, key=repr)]
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}

    # pandas missing-value sentinels (NaT / NA) collapse to null.
    if _is_pandas_na(value):
        return None

    # pandas Timestamp (and any datetime-like exposing isoformat).
    iso = getattr(value, "isoformat", None)
    if callable(iso) and not isinstance(value, (str, bytes)):
        try:
            return iso()
        except Exception:
            pass

    # numpy ndarray -> nested list.
    tolist = getattr(value, "tolist", None)
    if callable(tolist) and not isinstance(value, (str, bytes)):
        try:
            listed = tolist()
        except Exception:
            listed = None
        if isinstance(listed, list):
            return [to_jsonable(x) for x in listed]
        if listed is not None:  # 0-d array -> a scalar
            return to_jsonable(listed)

    # numpy scalar (np.int64 / np.bool_ / np.float64-as-object) -> Python scalar.
    item = getattr(value, "item", None)
    if callable(item) and not isinstance(value, (str, bytes)):
        try:
            return to_jsonable(item())
        except Exception:
            pass

    return str(value)  # last resort - never raise


def jsonable_to_human(value: Any, *, item_sep: str, kv_sep: str) -> str:
    """Render a ``to_jsonable``-normalised value as a compact human string -
    no braces / brackets / quotes / Python ``repr``.

    The single owner shared by the csv worklist (``item_sep=","``, ``kv_sep=":"``)
    and the html reading report (``item_sep=", "``, ``kv_sep=": "``) so the two
    human surfaces stay in lockstep. Operates DOWNSTREAM of ``to_jsonable``, so the
    input is already JSON-native (``None`` / ``bool`` / ``int`` / ``float`` /
    ``str`` / ``list`` / ``dict``). ``dict`` items are sorted by their
    already-string keys for determinism.
    """
    if value is None:
        return ""
    if isinstance(value, bool):  # BEFORE int - bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return item_sep.join(
            jsonable_to_human(x, item_sep=item_sep, kv_sep=kv_sep) for x in value
        )
    if isinstance(value, dict):
        return item_sep.join(
            f"{key}{kv_sep}{jsonable_to_human(val, item_sep=item_sep, kv_sep=kv_sep)}"
            for key, val in sorted(value.items())
        )
    return str(value)
