"""Focused rule tests for CloudTrail regional coverage."""

from __future__ import annotations

from auditor.rules.cloudtrail_rules import evaluate


CONFIG = {
    "cloudtrail": {
        "require_trail": True,
        "require_multi_region": False,
        "require_log_validation": False,
        "check_logging_status": False,
    }
}


def _data(region: str, *trails: dict, readable: bool = True, errors=None) -> dict:
    return {
        "region": region,
        "trails": list(trails),
        "trails_readable": readable,
        "errors": errors or [],
    }


def _rule_ids(data: dict) -> set[str]:
    return {finding.rule_id for finding in evaluate(data, CONFIG, run_id="test")}


def test_multi_region_trail_from_home_region_covers_a_secondary_region():
    data = _data(
        "us-east-2",
        {
            "name": "org-trail",
            "arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
            "home_region": "us-east-1",
            "is_multi_region": True,
        },
    )

    assert "CT-001" not in _rule_ids(data)


def test_single_region_trail_in_another_region_does_not_cover_evaluated_region():
    data = _data(
        "us-east-2",
        {
            "name": "regional-trail",
            "arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/regional-trail",
            "home_region": "us-east-1",
            "is_multi_region": False,
        },
    )

    findings = evaluate(data, CONFIG, run_id="test")
    ct001 = next(finding for finding in findings if finding.rule_id == "CT-001")
    assert ct001.evidence["region"] == "us-east-2"


def test_single_region_trail_covers_its_home_region():
    data = _data(
        "us-east-1",
        {
            "name": "regional-trail",
            "home_region": "us-east-1",
            "is_multi_region": False,
        },
    )

    assert "CT-001" not in _rule_ids(data)


def test_unreadable_trail_collection_does_not_create_ct001():
    for code, category in (
        ("AccessDenied", "access_denied"),
        ("ThrottlingException", "throttled"),
    ):
        data = _data(
            "us-east-2",
            readable=False,
            errors=[{"code": code, "category": category}],
        )

        assert "CT-001" not in _rule_ids(data)
