from __future__ import annotations

import pytest

from unraid_updater.research_vnext import ResearchValidationError, build_report, github_source


def test_none_mode_skips_without_network_or_evidence() -> None:
    report = build_report(revision="r1", mode="none")
    assert report["status"] == "skipped_by_policy"
    assert report["evidence"] == []


def test_notes_report_is_bounded_deduplicated_and_hashed() -> None:
    report = build_report(
        revision="r1",
        mode="notes",
        source="https://github.com/acme/widget.git",
        evidence=[
            {"url": "https://github.com/acme/widget/releases/tag/v1.0.1", "title": "release", "excerpt": "x"},
            {"url": "https://github.com/acme/widget/releases/tag/v1.0.1", "title": "duplicate"},
        ],
    )
    assert report["source"] == "https://github.com/acme/widget"
    assert len(report["evidence"]) == 1
    assert len(report["report_hash"]) == 64


def test_sources_and_modes_fail_closed() -> None:
    with pytest.raises(ResearchValidationError):
        github_source("http://github.com/acme/widget")
    with pytest.raises(ResearchValidationError):
        github_source("https://github.com/acme/widget?token=secret")
    with pytest.raises(ResearchValidationError):
        build_report(revision="r1", mode="deep")
    with pytest.raises(ResearchValidationError):
        build_report(revision="r1", mode="none", evidence=[{"url": "https://example.com"}])
