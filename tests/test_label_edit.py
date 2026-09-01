from pathlib import Path

import pytest

from unraid_updater.label_edit import (
    LabelEditError,
    apply_policy_labels,
    parse_template_labels,
    policy_diff,
    runtime_labels_match,
)

LABELS = {
    "io.jmengit.upgrade.version": "minor",
    "io.jmengit.upgrade.policy": "manual",
    "io.jmengit.upgrade.research": "none",
}


def test_parse_and_apply_preserves_unrelated_xml(tmp_path: Path) -> None:
    path = tmp_path / "app.xml"
    path.write_text("<Container><Name>app</Name><Labels><Label>custom=x</Label><Label>io.jmengit.upgrade.version=patch</Label></Labels><Repository>repo/app:1</Repository></Container>")
    assert parse_template_labels(path)["custom"] == "x"
    apply_policy_labels(path, LABELS)
    text = path.read_text()
    assert "custom=x" in text and "Repository" in text
    assert "io.jmengit.upgrade.version=minor" in text
    assert "io.jmengit.upgrade.policy=manual" in text


def test_diff_is_scoped_and_parity_is_policy_scoped() -> None:
    assert set(policy_diff({"custom": "a", **LABELS}, {"custom": "b", **LABELS, "io.jmengit.upgrade.version": "major"})) == {"io.jmengit.upgrade.version"}
    assert runtime_labels_match({**LABELS, "custom": "a"}, {**LABELS, "custom": "b"})


def test_root_escape_rejected(tmp_path: Path) -> None:
    with pytest.raises(LabelEditError):
        apply_policy_labels(tmp_path / "../outside.xml", LABELS, template_root=tmp_path)
    with pytest.raises(LabelEditError):
        apply_policy_labels(tmp_path / "missing.xml", LABELS)


def test_backup_created(tmp_path: Path) -> None:
    path = tmp_path / "app.xml"
    path.write_text("<Container><Labels></Labels></Container>")
    apply_policy_labels(path, LABELS)
    assert path.with_suffix(".xml.bak").exists()
    assert parse_template_labels(path)["io.jmengit.upgrade.policy"] == "manual"


def test_invalid_xml_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text("not xml")
    with pytest.raises(LabelEditError):
        parse_template_labels(path)
