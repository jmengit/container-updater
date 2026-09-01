from datetime import UTC, datetime

import pytest

from unraid_updater.resolver.release import (
    ResolutionError,
    change_class,
    normalize_digest,
    parse_version,
    release_identity,
    resolve_timestamp,
)


def test_parse_version_requires_three_components_and_ignores_prerelease():
    assert parse_version("v1.2.3-rc.1") == (1, 2, 3)
    assert parse_version("1.2") is None
    assert parse_version("latest") is None


def test_change_class_uses_installed_to_final_target():
    assert change_class("1.9.0", "2.0.1") == "major"
    assert change_class("1.2.3", "1.3.0") == "minor"
    assert change_class("1.2.3", "1.2.4") == "patch"


def test_digest_requires_full_sha256_and_normalizes_case():
    digest = "sha256:" + "A" * 64
    assert normalize_digest(digest) == "sha256:" + "a" * 64
    with pytest.raises(ResolutionError):
        normalize_digest("sha256:" + "a" * 63)


def test_timestamp_prefers_authoritative_metadata():
    result = resolve_timestamp({"published_at": "2026-01-02T03:04:05Z"}, first_seen_at="2026-02-01T00:00:00Z")
    assert result.confidence == "authoritative"
    assert result.source == "published_at"
    assert result.value == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_timestamp_falls_back_conservatively_or_is_unknown():
    result = resolve_timestamp({"published_at": "not-a-date"}, first_seen_at="2026-02-01T00:00:00Z")
    assert result.confidence == "first_seen_conservative"
    assert resolve_timestamp({}, first_seen_at="2026-02-01T00:00:00Z", fallback_enabled=False).value is None


def test_identity_requires_exact_repository_and_tag():
    with pytest.raises(ResolutionError):
        release_identity(repository="", tag="1.0.0")
    identity = release_identity(repository="owner/app", tag="1.0.0", digest="sha256:" + "b" * 64)
    assert identity.digest == "sha256:" + "b" * 64
    assert identity.match_method == "exact_tag"
