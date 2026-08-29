from __future__ import annotations

from unraid_updater import portainer


def test_portainer_inventory_groups_endpoint_and_stack(monkeypatch) -> None:
    replies = {
        "/api/endpoints": [{"Id": 2, "Name": "remote-vm"}],
        "/api/endpoints/2/docker/containers/json?all=1": [{
            "Id": "abcdef1234567890", "Names": ["/paperclip"], "State": "running",
            "Status": "Up 2 hours (healthy)", "Image": "example/paperclip:1.2.3",
            "ImageID": "sha256:123", "Labels": {"com.docker.compose.project": "paperclip"},
        }],
    }
    monkeypatch.setattr(portainer, "_get", lambda _instance, path: replies[path])
    rows = portainer.inventory({"name": "RackNerd", "url": "https://host", "token": "secret"})
    assert rows == [{
        "container": "paperclip", "state": "running", "image": "example/paperclip:1.2.3",
        "image_id": "sha256:123", "health": "Up 2 hours (healthy)", "template_path": "",
        "template_hash": "", "provider": "portainer", "provider_name": "RackNerd",
        "endpoint_id": 2, "endpoint_name": "remote-vm", "managed_by": "Portainer stack",
        "stack": "paperclip",
    }]


def test_portainer_endpoint_allowlist(monkeypatch) -> None:
    monkeypatch.setattr(portainer, "_get", lambda _instance, path: (
        [{"Id": 1, "Name": "one"}, {"Id": 2, "Name": "two"}]
        if path == "/api/endpoints" else []
    ))
    assert portainer.inventory({
        "url": "https://host", "token": "secret", "endpoint_ids": [2]
    }) == []