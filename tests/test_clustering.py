"""Tests for the HDBSCAN backend shim - resolution and exposure only.

Contract under test (sigwood.common.clustering):

1. ``HDBSCAN`` is exposed as a class at module level, constructable with the
   standard ``min_cluster_size=`` and ``min_samples=`` kwargs and exposing
   ``fit_predict``.
2. ``ACTIVE_BACKEND`` is one of ``{"fast_hdbscan", "hdbscan"}`` and matches
   whichever backend is actually importable in the current environment, in
   the same priority order the shim itself uses.
3. When ``fast_hdbscan`` is force-blocked at import time, the shim falls
   back to stock ``hdbscan`` and reports ``ACTIVE_BACKEND == "hdbscan"``.

Clustering numerics and equivalence between the two backends are out of
scope - that lives with the dns detector tests.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from sigwood.common import clustering


def _expected_backend_in_env() -> str:
    """Resolve the expected backend in the same priority order as the shim.

    Mirrors the shim's logic exactly so the assertion fails clearly if the
    environment has no clustering backend installed.
    """
    try:
        import fast_hdbscan  # noqa: F401
        return "fast_hdbscan"
    except ImportError:
        try:
            import hdbscan  # noqa: F401
            return "hdbscan"
        except ImportError as e:
            pytest.fail(
                "Neither fast_hdbscan nor hdbscan is importable in the test "
                "environment. A clustering backend (fast_hdbscan on 64-bit "
                "platforms, stock hdbscan elsewhere or via the [hdbscan] extra) "
                "must be present for the shim to resolve. Original error: "
                f"{e!r}"
            )


def test_shim_exposes_constructable_hdbscan_class():
    cls = clustering.HDBSCAN
    assert isinstance(cls, type), "HDBSCAN must be exposed as a class, not a factory"
    instance = cls(min_cluster_size=5, min_samples=2)
    assert hasattr(instance, "fit_predict"), "HDBSCAN instance must expose fit_predict"


def test_active_backend_is_one_of_expected_strings():
    assert clustering.ACTIVE_BACKEND in {"fast_hdbscan", "hdbscan"}


def test_active_backend_matches_environment():
    assert clustering.ACTIVE_BACKEND == _expected_backend_in_env()


def test_import_error_names_arch_selected_backend_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "fast_hdbscan", None)
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    try:
        with pytest.raises(ImportError) as excinfo:
            importlib.reload(clustering)

        message = str(excinfo.value)
        assert "No HDBSCAN backend available" in message
        assert "neither 'fast_hdbscan' nor 'hdbscan'" in message
        assert "sigwood installs one automatically" in message
        assert "sigwood[fast]" in message
        assert "sigwood[hdbscan]" in message
        assert "base dependency" not in message
    finally:
        sys.modules.pop("fast_hdbscan", None)
        sys.modules.pop("hdbscan", None)
        importlib.reload(clustering)


def test_fallback_resolves_to_hdbscan_when_fast_hdbscan_blocked(monkeypatch):
    """Force-block fast_hdbscan and reload; the shim must fall through to hdbscan.

    Uses the standard ``sys.modules[name] = None`` sentinel pattern: when the
    import machinery sees None in ``sys.modules`` for a name, it raises
    ``ModuleNotFoundError`` rather than attempting to resolve the module.
    That gives us deterministic fallback coverage regardless of whether
    fast_hdbscan is actually installed on disk.
    """
    try:
        import hdbscan  # noqa: F401
    except ImportError:
        pytest.skip("stock hdbscan not importable")

    monkeypatch.setitem(sys.modules, "fast_hdbscan", None)
    try:
        importlib.reload(clustering)
        assert clustering.ACTIVE_BACKEND == "hdbscan"
        cls = clustering.HDBSCAN
        assert isinstance(cls, type)
        instance = cls(min_cluster_size=5, min_samples=2)
        assert hasattr(instance, "fit_predict")
    finally:
        sys.modules.pop("fast_hdbscan", None)
        importlib.reload(clustering)
