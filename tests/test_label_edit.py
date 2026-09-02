from pathlib import Path

import pytest

from unraid_updater.label_edit import (
    LabelEditError,
    apply_policy_labels,
    github_source_hint,
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


def test_apply_migrates_owned_labels_to_extra_params_and_preserves_unrelated(tmp_path: Path) -> None:
    path = tmp_path / "app.xml"
    path.write_text(
        "<Container><Repository>app:latest</Repository>"
        "<ExtraParams>--cpus 2 --label wud.watch=true "
        "--label io.jmengit.upgrade.risk=low --label=custom=x</ExtraParams>"
        "<Label>io.jmengit.upgrade.policy=auto</Label><Label>other=y</Label></Container>"
    )
    apply_policy_labels(path, {**LABELS, "io.jmengit.upgrade.source": "https://github.com/example/app"})
    text = path.read_text()
    labels = parse_template_labels(path)
    assert "--cpus 2" in text
    assert "wud.watch=true" in text and "custom=x" in text and "other=y" in text
    assert "io.jmengit.upgrade.risk" not in text
    assert "<Label>io.jmengit.upgrade.policy" not in text
    assert labels["io.jmengit.upgrade.policy"] == "manual"
    assert labels["io.jmengit.upgrade.source"] == "https://github.com/example/app"


def test_invalid_extra_params_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "app.xml"
    path.write_text('<Container><ExtraParams>--label "unterminated</ExtraParams></Container>')
    with pytest.raises(LabelEditError, match="ExtraParams"):
        apply_policy_labels(path, LABELS)


def test_ghcr_source_is_only_a_suggestion() -> None:
    assert github_source_hint("ghcr.io/hargata/lubelogger:v1.7.1") == {
        "url": "https://github.com/hargata/lubelogger",
        "status": "suggested from GHCR namespace; not verified",
        "verified": False,
    }
    assert github_source_hint("ghcr.io/org/team/image:latest")["url"] == ""
    assert github_source_hint("docker.io/example/app:latest")["url"] == ""


def test_invalid_xml_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text("not xml")
    with pytest.raises(LabelEditError):
        parse_template_labels(path)
