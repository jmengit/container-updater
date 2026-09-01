"""Bounded GitHub evidence collection and optional advisory-only LLM analysis."""
from __future__ import annotations

import base64
import json
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class ResearchError(RuntimeError):
    """Raised when required research cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class ResearchConfig:
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    github_token: str = ""
    verify_tls: bool = True
    timeout_seconds: int = 30
    max_issues: int = 12
    llm_headers: tuple[tuple[str, str], ...] = ()


def _request(url: str, *, token: str = "", body: dict[str, Any] | None = None,
             verify_tls: bool = True, timeout: int = 30,
             extra_headers: tuple[tuple[str, str], ...] = ()) -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "container-updater/0.5"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(dict(extra_headers))
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    context = None if verify_tls else ssl._create_unverified_context()
    try:
        with urlopen(Request(url, data=data, headers=headers), context=context, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ResearchError(f"request failed for {urlparse(url).netloc}: {exc}") from exc


def _repo(value: str) -> str:
    value = value.strip().removesuffix(".git")
    if "github.com/" in value:
        value = value.split("github.com/", 1)[1]
    value = value.strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ResearchError("research repository must be owner/name on github.com")
    return value


def collect_github_evidence(repository: str, current: str, candidate: str, *,
                            token: str = "", max_issues: int = 12,
                            timeout: int = 30) -> dict[str, Any]:
    """Collect bounded public GitHub evidence; never follows arbitrary source URLs."""
    repo = _repo(repository)
    api = f"https://api.github.com/repos/{repo}"
    releases = _request(f"{api}/releases?per_page=10", token=token, timeout=timeout)
    release_rows = [{
        "name": row.get("name") or row.get("tag_name"),
        "tag": row.get("tag_name"), "published_at": row.get("published_at"),
        "url": row.get("html_url"), "body": (row.get("body") or "")[:12000],
        "prerelease": bool(row.get("prerelease")),
    } for row in releases[:10]]
    terms = " ".join(x for x in [candidate, "regression breaking bug"] if x).strip()
    query = f"repo:{repo} is:issue {terms}"[:240]
    issues = _request(
        "https://api.github.com/search/issues?" + urlencode({"q": query, "sort": "updated", "per_page": max_issues}),
        token=token, timeout=timeout,
    )
    issue_rows = [{
        "number": row.get("number"), "title": row.get("title"), "state": row.get("state"),
        "updated_at": row.get("updated_at"), "url": row.get("html_url"),
        "labels": [label.get("name") for label in row.get("labels", [])],
        "body": (row.get("body") or "")[:6000],
    } for row in issues.get("items", [])[:max_issues]]
    repo_meta = _request(api, token=token, timeout=timeout)
    default_branch = str(repo_meta.get("default_branch") or "main")
    documents = []
    for filename in ("README.md", "CHANGELOG.md", "CHANGES.md", "HISTORY.md", "UPGRADING.md"):
        try:
            row = _request(
                f"{api}/contents/{filename}?ref={default_branch}", token=token, timeout=timeout
            )
        except ResearchError:
            continue
        if row.get("type") != "file" or not row.get("content"):
            continue
        try:
            content = base64.b64decode(str(row["content"])).decode(
                "utf-8", errors="replace"
            )[:20000]
        except (ValueError, TypeError):
            continue
        documents.append({"name": filename, "url": row.get("html_url"), "content": content})
    return {
        "repository": repo, "current": current, "candidate": candidate,
        "collected_at": datetime.now(UTC).isoformat(), "releases": release_rows,
        "issues": issue_rows, "documents": documents,
    }


def analyze(config: ResearchConfig, evidence: dict[str, Any]) -> dict[str, Any]:
    """Request structured advisory analysis from an OpenAI-compatible API."""
    if not config.llm_base_url or not config.llm_model:
        raise ResearchError("LLM endpoint and model are required")
    prompt = (
        "You are an advisory container-update risk analyst. Use only the supplied evidence. "
        "Never approve or execute an update. Return JSON with recommendation (hold|manual_review|proceed_to_human_approval), "
        "risk (low|medium|high|critical), confidence (low|medium|high), summary, breaking_changes, "
        "reported_regressions, required_actions, and citations. Every citation must contain a URL from the evidence. "
        "Missing or contradictory evidence requires manual_review or hold.\nEVIDENCE:\n"
        + json.dumps(evidence, separators=(",", ":"))[:90000]
    )
    body = {
        "model": config.llm_model, "temperature": 0, "stream": False,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": prompt}],
    }
    url = config.llm_base_url.rstrip("/") + "/chat/completions"
    response = _request(url, token=config.llm_api_key, body=body,
                        verify_tls=config.verify_tls, timeout=config.timeout_seconds,
                        extra_headers=config.llm_headers)
    try:
        result = json.loads(response["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ResearchError("LLM returned invalid structured output") from exc
    allowed_urls = {
        row.get("url")
        for section in ("releases", "issues", "documents")
        for row in evidence.get(section, [])
    }
    citations = result.get("citations", [])
    if not isinstance(citations, list) or any(not isinstance(c, dict) or c.get("url") not in allowed_urls for c in citations):
        raise ResearchError("LLM returned an unsupported citation")
    if result.get("recommendation") not in {"hold", "manual_review", "proceed_to_human_approval"}:
        raise ResearchError("LLM returned an invalid recommendation")
    result["advisory_only"] = True
    result["model"] = config.llm_model
    result["analyzed_at"] = datetime.now(UTC).isoformat()
    return result


def assess(config: ResearchConfig, repository: str, current: str, candidate: str) -> dict[str, Any]:
    evidence = collect_github_evidence(repository, current, candidate, token=config.github_token,
                                       max_issues=config.max_issues, timeout=config.timeout_seconds)
    return {"evidence": evidence, "analysis": analyze(config, evidence)}
