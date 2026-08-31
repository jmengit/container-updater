from datetime import UTC, datetime, timedelta

import pytest

from unraid_updater.vnext_policy import (
    ExecutionPolicy,
    LabelPolicy,
    ResearchMode,
    UpdateVersion,
    change_class,
    hold_decision,
    validate_global_holds,
)


def labels(**extra):
    values = {
        "io.jmengit.upgrade.version": "minor",
        "io.jmengit.upgrade.policy": "manual",
        "io.jmengit.upgrade.research": "none",
    }
    values.update(extra)
    return values


def test_label_policy_requires_and_validates_labels():
    policy = LabelPolicy.from_labels(labels(**{"io.jmengit.upgrade.hold-days": "0"}))
    assert policy.version is UpdateVersion.MINOR
    assert policy.policy is ExecutionPolicy.MANUAL
    assert policy.research is ResearchMode.NONE
    assert policy.hold_days == 0
    with pytest.raises(ValueError):
        LabelPolicy.from_labels({})
    with pytest.raises(ValueError):
        LabelPolicy.from_labels(labels(**{"io.jmengit.upgrade.hold-days": "366"}))
    with pytest.raises(ValueError):
        LabelPolicy.from_labels(labels(**{"io.jmengit.upgrade.source": "https://example.com/x/y"}))


def test_installed_to_final_target_classification():
    assert change_class("1.9.0", "2.0.1") == "major"
    assert change_class("1.2.0", "1.4.0") == "minor"
    assert change_class("1.2.0", "1.2.3") == "patch"
    assert change_class("latest", "edge") == "unknown"


def test_two_part_hold_uses_later_deadline_and_override():
    now = datetime(2026, 8, 31, tzinfo=UTC)
    line = now - timedelta(days=20)
    target = now - timedelta(days=1)
    decision = hold_decision(
        installed="1.9.0", target="2.0.1", line_release_at=line,
        target_release_at=target, global_holds={"patch": 2, "minor": 7, "major": 14}, now=now,
    )
    assert decision.change_class == "major"
    assert decision.eligible_at == target + timedelta(days=14)
    assert not decision.eligible
    override = hold_decision(
        installed="1.9.0", target="2.0.1", line_release_at=line,
        target_release_at=target, global_holds={"patch": 2, "minor": 7, "major": 14},
        override_days=0, now=now,
    )
    assert override.eligible


def test_global_holds_fail_closed():
    assert validate_global_holds({"patch": "2", "minor": 7, "major": 14})["major"] == 14
    with pytest.raises(ValueError):
        validate_global_holds({"patch": 2, "minor": 7, "major": 366})
    with pytest.raises(ValueError):
        validate_global_holds({"patch": 2, "minor": 7})
