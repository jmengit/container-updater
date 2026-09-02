from __future__ import annotations

import base64
import json
from io import BytesIO

import pytest

from unraid_updater.research import (
    ResearchConfig,
    ResearchError,
    _release_range,
    _repo,
    analyze,
    collect_github_evidence,
)


def test_collection_includes_repository_documents(monkeypatch) -> None:
    def fake(url, **_kwargs):
        if url.endswith("/releases?per_page=30"):
            return []
        if "search/issues" in url:
            return {"items": []}
        if url.endswith("/repos/example/project"):
            return {"default_branch": "main"}
        if "/contents/README.md?" in url:
            return {
                "type": "file",
                "html_url": "https://github.com/example/project/blob/main/README.md",
                "content": base64.b64encode(b"breaking changes").decode(),
            }
        raise ResearchError("not found")

    monkeypatch.setattr("unraid_updater.research._request", fake)
    evidence = collect_github_evidence("example/project", "1", "2")
    assert evidence["documents"][0]["name"] == "README.md"
    assert evidence["documents"][0]["content"] == "breaking changes"


def test_repository_is_restricted_to_github_owner_name() -> None:
    assert _repo("https://github.com/example/project.git") == "example/project"
    with pytest.raises(ResearchError):
        _repo("https://evil.example/internal")


def test_release_range_includes_every_version_after_current_through_candidate() -> None:
    rows = [{"tag_name": value} for value in ("v1.7.2", "v1.7.1", "v1.6.0", "v1.5.8")]
    selected, description = _release_range(rows, "v1.5.8", "v1.7.1")
    assert [row["tag_name"] for row in selected] == ["v1.7.1", "v1.6.0"]
    assert description == "v1.5.8 through v1.7.1"


def test_collection_marks_changelog_summary_and_range(monkeypatch) -> None:
    def fake(url, **_kwargs):
        if url.endswith("/releases?per_page=30"):
            return [{"tag_name": "v1.1.0", "body": "important", "html_url": "https://github.com/example/project/releases/tag/v1.1.0"}]
        if "search/issues" in url:
            return {"items": []}
        if url.endswith("/repos/example/project"):
            return {"default_branch": "main"}
        raise ResearchError("not found")
    monkeypatch.setattr("unraid_updater.research._request", fake)
    evidence = collect_github_evidence(
        "example/project", "v1.0.0", "v1.1.0", summarize_changelog=True,
    )
    assert evidence["changelog_summary_requested"] is True
    assert evidence["release_range"] == "v1.0.0 through v1.1.0"
    assert [row["tag"] for row in evidence["releases"]] == ["v1.1.0"]


def test_analysis_rejects_fabricated_citation(monkeypatch) -> None:
    payload = {"choices": [{"message": {"content": json.dumps({
        "recommendation": "proceed_to_human_approval", "risk": "low", "confidence": "high",
        "summary": "ok", "breaking_changes": [], "reported_regressions": [],
        "required_actions": [], "citations": [{"url": "https://evil.example", "claim": "safe"}],
    })}}]}

    class Response(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    monkeypatch.setattr("unraid_updater.research.urlopen", lambda *a, **k: Response(json.dumps(payload).encode()))
    evidence = {"releases": [{"url": "https://github.com/example/project/releases/1"}], "issues": []}
    with pytest.raises(ResearchError, match="unsupported citation"):
        analyze(ResearchConfig("http://llm/v1", "secret", "test"), evidence)


def test_analysis_is_always_marked_advisory(monkeypatch) -> None:
    url = "https://github.com/example/project/releases/1"
    result = {
        "recommendation": "manual_review", "risk": "medium", "confidence": "medium",
        "summary": "review", "breaking_changes": [], "reported_regressions": [],
        "required_actions": [], "citations": [{"url": url, "claim": "release"}],
    }

    class Response(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    payload = {"choices": [{"message": {"content": json.dumps(result)}}]}
    monkeypatch.setattr("unraid_updater.research.urlopen", lambda *a, **k: Response(json.dumps(payload).encode()))
    report = analyze(ResearchConfig("http://llm/v1", "secret", "test"), {"releases": [{"url": url}], "issues": []})
    assert report["advisory_only"] is True
    assert report["recommendation"] == "manual_review"
