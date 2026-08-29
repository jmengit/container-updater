from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.merge_unraid_template import merge


def test_merge_preserves_user_values_and_adds_new_fields(tmp_path: Path) -> None:
    shipped = tmp_path / "shipped.xml"
    installed = tmp_path / "installed.xml"
    output = tmp_path / "merged.xml"
    shipped.write_text(
        "<Container><Repository>app:2</Repository>"
        '<Config Name="Admin Username" Target="ADMIN_USERNAME">default</Config>'
        '<Config Name="Admin Password" Target="ADMIN_PASSWORD"></Config>'
        '<Config Name="New" Target="NEW_FIELD">new</Config></Container>'
    )
    installed.write_text(
        "<Container><Repository>app:1</Repository>"
        '<Config Name="Admin Username" Target="ADMIN_USERNAME">changed-user</Config>'
        '<Config Name="Admin Password" Target="ADMIN_PASSWORD">changed-pass</Config>'
        "</Container>"
    )
    merge(shipped, installed, output)
    root = ET.parse(output).getroot()
    values = {node.get("Target"): node.text or "" for node in root.findall("Config")}
    assert root.findtext("Repository") == "app:2"
    assert values["ADMIN_USERNAME"] == "changed-user"
    assert values["ADMIN_PASSWORD"] == "changed-pass"
    assert values["NEW_FIELD"] == "new"
