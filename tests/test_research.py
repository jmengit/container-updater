from __future__ import annotations

import json
from io import BytesIO

import pytest

from unraid_updater.research import ResearchConfig, ResearchError, _repo, analyze


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
