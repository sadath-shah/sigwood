"""Shared FakeS3Client + envelope helpers for CloudTrail exporter tests.

Lives here (not in either test file) so that the always-run mock test set in
tests/test_cloudtrail_exporter.py does not transitively import botocore, while
the botocore-gated set in tests/test_cloudtrail_exporter_botocore.py can reuse
the same fakes. No botocore reference in this module.
"""

from __future__ import annotations

import gzip
import json
from typing import Any


def _gz_envelope(records: list[dict]) -> bytes:
    """Encode a {"Records": [...]} envelope as gzipped JSON."""
    return gzip.compress(json.dumps({"Records": records}).encode("utf-8"))


class _Body:
    def __init__(self, content: bytes):
        self._content = content

    def read(self) -> bytes:
        return self._content


class _FakePaginator:
    def __init__(
        self,
        data: dict[str, dict[str, Any]],
        log: list[str] | None = None,
        prefix_errors: dict[str, Exception] | None = None,
    ):
        self.data = data
        self.log = log if log is not None else []
        self.prefix_errors = prefix_errors or {}

    def paginate(self, Bucket: str, Prefix: str = "", Delimiter: str | None = None):
        self.log.append(Prefix)
        if Prefix in self.prefix_errors:
            raise self.prefix_errors[Prefix]
        keys = [k for k in self.data if k.startswith(Prefix)]
        if Delimiter == "/":
            common = set()
            contents = []
            for key in keys:
                rest = key[len(Prefix):]
                if "/" in rest:
                    common.add(Prefix + rest.split("/", 1)[0] + "/")
                else:
                    contents.append({"Key": key, "Size": self.data[key]["size"]})
            yield {
                "CommonPrefixes": [{"Prefix": p} for p in sorted(common)],
                "Contents": contents,
            }
        else:
            yield {
                "Contents": [
                    {"Key": k, "Size": self.data[k]["size"]} for k in sorted(keys)
                ],
            }


class FakeS3Client:
    """Minimal in-memory S3 stub: list_objects_v2 (via paginator) + get_object."""

    def __init__(self, data: dict[str, dict[str, Any]] | None = None):
        self.data: dict[str, dict[str, Any]] = data or {}
        self.get_object_keys: list[str] = []
        self._get_object_errors: dict[str, Exception] = {}
        self._list_error: Exception | None = None
        self.list_prefix_log: list[str] = []
        self._list_error_for_prefix: dict[str, Exception] = {}

    def add_object(self, key: str, body: bytes, size: int | None = None) -> None:
        self.data[key] = {"body": body, "size": size if size is not None else len(body)}

    def add_year_root_marker(self, prefix: str) -> None:
        """Force a 'CommonPrefix' under ``prefix`` for a YYYY/ directory.

        Adds a synthetic '__keep__' key so listing finds the directory.
        """
        self.data[f"{prefix}__keep__"] = {"body": b"", "size": 0}

    def set_get_object_error(self, key: str, exc: Exception) -> None:
        self._get_object_errors[key] = exc

    def set_list_error(self, exc: Exception) -> None:
        self._list_error = exc

    def set_list_error_for_prefix(self, prefix: str, exc: Exception) -> None:
        """Raise ``exc`` when list_objects_v2 is called with exactly ``prefix``."""
        self._list_error_for_prefix[prefix] = exc

    def get_paginator(self, op: str):
        if op != "list_objects_v2":
            raise NotImplementedError(op)
        if self._list_error is not None:
            err = self._list_error

            class _ErrorPaginator:
                def paginate(self, **_):
                    raise err

            return _ErrorPaginator()
        return _FakePaginator(
            self.data, self.list_prefix_log, self._list_error_for_prefix
        )

    def get_object(self, Bucket: str, Key: str):
        self.get_object_keys.append(Key)
        if Key in self._get_object_errors:
            raise self._get_object_errors[Key]
        return {"Body": _Body(self.data[Key]["body"])}
