from __future__ import annotations

import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path

_SCRIPT = Path(__file__).parents[1] / "scripts" / "merge_unraid_template.py"
_SPEC = importlib.util.spec_from_file_location("merge_unraid_template", _SCRIPT)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
merge = _MODULE.merge


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
