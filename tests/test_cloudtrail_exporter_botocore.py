"""Botocore-gated tests for the CloudTrail S3 exporter framework.

These tests construct real botocore exception classes (ClientError,
NoCredentialsError, MissingDependencyException, EndpointConnectionError) to
exercise the centralized boto-error translation rail in
sigwood.exporters.cloudtrail._translate_boto_errors. They are split off
behind a module-level importorskip so the bulk mock-only suite in
tests/test_cloudtrail_exporter.py runs on a base checkout without botocore.

The FakeS3Client / _gz_envelope helpers are shared via tests._cloudtrail_fakes
(no botocore in that module). All bucket names and account IDs are obviously
fake.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

# Gate the whole module: skip on a base checkout without botocore.
botocore_exc = pytest.importorskip("botocore.exceptions")

from sigwood.exporters import cloudtrail as ct

from tests._cloudtrail_fakes import FakeS3Client, _gz_envelope


def _make_client_error(code: str) -> botocore_exc.ClientError:
    return botocore_exc.ClientError(
        {"Error": {"Code": code, "Message": code}}, "Op"
    )


def test_access_denied_in_sibling_branch_does_not_abort_pull(monkeypatch) -> None:
    """An AccessDenied on a non-CloudTrail sibling must NOT abort the run.

    Common bucket-policy pattern: CloudTrail/ is readable to the analyst, ELB/
    is restricted. Without pruning, the walker would descend into
    elasticloadbalancing/, trigger AccessDenied, and abort the entire pull
    with the auth-error ValueError. With pruning, the sibling is never listed.
    """
    client = FakeS3Client()
    ct_base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    client.add_object(ct_base + "obj1.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T01:00:00Z", "eventName": "Good"},
    ]))
    # Booby-trap: listing inside the ELB branch raises AccessDenied.
    client.set_list_error_for_prefix(
        "AWSLogs/000000000000/elasticloadbalancing/",
        _make_client_error("AccessDenied"),
    )
    # Make sure the ELB prefix actually appears as a CommonPrefix when listing
    # the account level - we need a key under it for the fake to surface it.
    client.add_object(
        "AWSLogs/000000000000/elasticloadbalancing/marker", b"",
    )
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)

    # Must complete cleanly - the sibling AccessDenied must never fire.
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)
    assert meta["units"] == 1
    assert events[0]["eventName"] == "Good"


# ── auth errors take priority over bad-object handling ──────────────────────


def test_auth_error_from_list_path(monkeypatch) -> None:
    client = FakeS3Client()
    client.set_list_error(_make_client_error("AccessDenied"))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="AWS credentials not found or expired"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_auth_error_from_get_path_aborts_run(monkeypatch) -> None:
    """A denied get_object must NOT be downgraded to bad-object skip-and-warn."""
    client = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    client.add_object(base + "obj1.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T01:00:00Z", "eventName": "x"},
    ]))
    client.set_get_object_error(base + "obj1.json.gz", _make_client_error("ExpiredToken"))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="AWS credentials not found or expired"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_no_credentials_error_handled(monkeypatch) -> None:
    client = FakeS3Client()
    client.set_list_error(botocore_exc.NoCredentialsError())
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="AWS credentials not found or expired"):
        ct.fetch({}, cfg, since, until, verbose=False)


# ── MissingDependencyException + BotoCoreError sweep (actionable-error rail) ──


def _missing_dep_exc() -> botocore_exc.MissingDependencyException:
    """Mirror the real-world SSO/login-provider message."""
    return botocore_exc.MissingDependencyException(
        msg="Using the login credential provider requires an additional dependency. "
            "Please install with `pip install 'botocore[crt]'`"
    )


def test_missing_dependency_at_client_construction_maps_to_actionable_error(
    monkeypatch,
) -> None:
    """MissingDependencyException at boto3.client() must become an actionable ValueError."""
    def _raise(_svc):
        raise _missing_dep_exc()

    monkeypatch.setattr(ct.boto3, "client", _raise)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError) as exc_info:
        ct.fetch({}, cfg, since, until, verbose=False)
    msg = str(exc_info.value)
    assert "botocore[crt]" in msg
    assert "credential provider" in msg
    # The original botocore detail must be embedded so the user sees the exact
    # missing piece (it varies - login vs SSO vs other providers).
    assert "login credential provider" in msg


def test_missing_dependency_at_list_call_maps_to_actionable_error(
    monkeypatch,
) -> None:
    """A list-call MissingDependencyException must map the same way (not propagate raw)."""
    client = FakeS3Client()
    client.set_list_error(_missing_dep_exc())
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="botocore\\[crt\\]"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_missing_dependency_at_get_call_maps_to_actionable_error(
    monkeypatch,
) -> None:
    """A get_object MissingDependencyException must abort with the actionable message,
    NOT be downgraded to the corrupt-object skip-and-warn path."""
    client = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    client.add_object(base + "obj1.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T01:00:00Z", "eventName": "x"},
    ]))
    client.set_get_object_error(base + "obj1.json.gz", _missing_dep_exc())
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="botocore\\[crt\\]"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_generic_botocore_error_is_wrapped(monkeypatch) -> None:
    """A long-tail BotoCoreError subclass must become 'AWS error during CloudTrail export'."""
    client = FakeS3Client()
    client.set_list_error(
        botocore_exc.EndpointConnectionError(endpoint_url="https://example.invalid")
    )
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError) as exc_info:
        ct.fetch({}, cfg, since, until, verbose=False)
    msg = str(exc_info.value)
    assert "AWS error during CloudTrail export" in msg
    # Original detail embedded for diagnosis
    assert "example.invalid" in msg


def test_non_auth_client_error_is_wrapped(monkeypatch) -> None:
    """A non-auth ClientError (e.g. NoSuchBucket) must be wrapped, not propagated raw."""
    client = FakeS3Client()
    client.set_list_error(_make_client_error("NoSuchBucket"))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError) as exc_info:
        ct.fetch({}, cfg, since, until, verbose=False)
    msg = str(exc_info.value)
    assert "AWS error during CloudTrail export" in msg
    assert "NoSuchBucket" in msg
