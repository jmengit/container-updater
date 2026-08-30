from __future__ import annotations

import base64
import json
from io import BytesIO

import pytest

from unraid_updater.research import (
    ResearchConfig,
    ResearchError,
    _repo,
    analyze,
    collect_github_evidence,
)


def test_collection_includes_repository_documents(monkeypatch) -> None:
    def fake(url, **_kwargs):
        if url.endswith("/releases?per_page=10"):
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
