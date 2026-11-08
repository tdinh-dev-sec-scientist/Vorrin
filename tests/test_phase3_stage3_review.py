"""Recording the Stage 3 review produces evidence the Stage 3 gate accepts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from phase3.stage_gates import _validate_stage_record

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "stage3_review", ROOT / "scripts/record_phase3_stage3_review.py"
)
review = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(review)
REVIEWED_AT = "2026-11-08T10:00:00-05:00"
RIN_CATEGORIES = (
    "prompt_injection",
    "hostile_evidence",
    "secret_leakage",
    "citation_grounding",
    "unsupported_question",
    "response_schema",
    "provider_error_fallback",
)
BANNERS = (
    "partial_scan",
    "failed_scan",
    "stale_data",
    "publication_blocked",
    "api_unavailable",
    "rin_unavailable",
    "rin_over_budget",
    "kill_switch_static_mode",
)


def _write(path: Path, value) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def workspace(tmp_path):
    shutil.copytree(ROOT / "docs/evidence", tmp_path / "docs/evidence")
    evidence = tmp_path / "docs/evidence/stage3"
    for name in ("guardrail-policy-review.json", "bedrock-logging-review.json"):
        (evidence / name).unlink(missing_ok=True)
    arn_sha = hashlib.sha256(b"arn:aws:bedrock:us-east-1:111122223333:guardrail/abc").hexdigest()
    controls = {
        "prompt_attack_filter": True,
        "off_scope_topics": ["Unrelated requests"],
        "sensitive_data_filter": True,
    }
    _write(
        evidence / "guardrail-configuration.json",
        {
            "schema_version": 1,
            "guardrail_arn_sha256": arn_sha,
            "published_version": "3",
            "input_controls": controls,
            "output_controls": controls,
        },
    )
    categories = [
        "input_prompt_attack",
        "input_sensitive_data",
        "input_off_scope",
        "output_prompt_attack",
        "output_sensitive_data",
        "output_off_scope",
    ]
    cases = [
        {"case_id": c, "category": c, "expected_action": "BLOCK", "observed_action": "BLOCK", "passed": True}
        for c in categories
    ]
    cases.append(
        {
            "case_id": "safe",
            "category": "safe_in_scope",
            "expected_action": "ALLOW",
            "observed_action": "ALLOW",
            "passed": True,
        }
    )
    _write(
        evidence / "guardrail-evaluation.json",
        {
            "schema_version": 1,
            "guardrail_arn_sha256": arn_sha,
            "published_version": "3",
            "passed": True,
            "case_count": len(cases),
            "cases": cases,
        },
    )
    _write(
        evidence / "bedrock-logging-settings.json",
        {"schema_version": 1, "enabled": False, "includes_prompt_content": False, "retention_days": None},
    )
    _write(
        evidence / "external-provider-logging-settings.json",
        {
            "schema_version": 1,
            "provider": "none",
            "enabled": False,
            "includes_prompt_content": False,
            "retention_days": None,
        },
    )
    for name in ("browser-network", "lighthouse", "accessibility"):
        _write(evidence / f"source-reports/{name}.json", {"schema_version": 1, "report": name})
    tls_sha = _write(evidence / "source-reports/external-tls.json", {"schema_version": 1, "report": "tls"})
    drafts = tmp_path / "build/phase3/stage3"
    _write(
        drafts / "external-tls-scan.json",
        {
            "schema_version": 1,
            "provider": "Mozilla HTTP Observatory API v2 (headers)",
            "scanned_at": "2026-11-08T09:00:00-05:00",
            "tls_result": "pass",
            "security_headers_result": "pass",
            "source_report_evidence_path": "stage3/source-reports/external-tls.json",
            "source_report_sha256": tls_sha,
        },
    )
    headers = dict.fromkeys(
        (
            "strict_transport_security",
            "content_security_policy",
            "x_content_type_options",
            "referrer_policy",
            "frame_ancestors",
        ),
        True,
    )
    _write(
        drafts / "transport-security.json",
        {"schema_version": 1, "http_redirect_status": 301, "https_status": 200, "headers": headers},
    )
    _write(
        drafts / "privacy-accessibility.json",
        {
            "schema_version": 1,
            "unapproved_third_party_requests": [],
            "pages_checked": ["dashboard", "finding", "rin"],
        },
    )
    _write(
        drafts / "rin-evaluation.json",
        {
            "schema_version": 1,
            "test_suite_sha256": "a" * 64,
            "cases": [{"case_id": c, "category": c, "passed": True} for c in RIN_CATEGORIES],
        },
    )
    _write(
        drafts / "quota-fallbacks.json",
        {
            "schema_version": 1,
            "per_session_limit": 10,
            "daily_invocation_limit": 19,
            "monthly_budget_usd": 5.0,
            "cases": {
                k: {"limit_reached": True, "response_mode": "fixture"}
                for k in ("session", "daily", "monthly_budget")
            },
        },
    )
    _write(
        drafts / "failure-banners.json",
        {"schema_version": 1, "test_suite_sha256": "b" * 64, "rendered_states": dict.fromkeys(BANNERS, True)},
    )
    return tmp_path, drafts


def test_dry_run_validates_without_writing(workspace):
    root, drafts = workspace
    before = (root / "docs/evidence/phase3-stage-acceptance.json").read_bytes()
    review.record_review(root, drafts, "Reviewer", confirm=False, reviewed_at=REVIEWED_AT)
    assert (root / "docs/evidence/phase3-stage-acceptance.json").read_bytes() == before
    assert not (root / "docs/evidence/stage3/guardrail-policy-review.json").exists()


def test_confirmed_review_passes_the_stage3_gate(workspace):
    root, drafts = workspace
    review.record_review(root, drafts, "Reviewer", confirm=True, reviewed_at=REVIEWED_AT)
    manifest = json.loads((root / "docs/evidence/phase3-stage-acceptance.json").read_text())
    record = manifest["stages"]["stage3"]
    assert record["status"] == "passed" and all(record["criteria"].values())
    assert _validate_stage_record(
        "stage3",
        record,
        root=root,
        expected_daily_invocation_limit=19,
        expected_monthly_budget_usd=5.0,
        require_runtime_bindings=True,
    )
    for name in ("transport-security", "rin-evaluation", "guardrail-policy-review", "bedrock-logging-review"):
        document = json.loads((root / f"docs/evidence/stage3/{name}.json").read_text())
        assert (document["reviewed_by"], document["reviewed_at"]) == ("Reviewer", REVIEWED_AT)


def test_a_changed_tls_report_is_refused(workspace):
    root, drafts = workspace
    _write(root / "docs/evidence/stage3/source-reports/external-tls.json", {"tampered": True})
    with pytest.raises(review.ReviewError, match="changed after the transport check"):
        review.record_review(root, drafts, "Reviewer", confirm=True, reviewed_at=REVIEWED_AT)


def test_failing_evidence_writes_nothing(workspace):
    root, drafts = workspace
    banners = json.loads((drafts / "failure-banners.json").read_text())
    banners["rendered_states"]["stale_data"] = False
    _write(drafts / "failure-banners.json", banners)
    before = (root / "docs/evidence/phase3-stage-acceptance.json").read_bytes()
    with pytest.raises(review.ReviewError, match="Stage 3 gate rejects"):
        review.record_review(root, drafts, "Reviewer", confirm=True, reviewed_at=REVIEWED_AT)
    assert (root / "docs/evidence/phase3-stage-acceptance.json").read_bytes() == before


def test_missing_collector_output_is_named(workspace):
    root, drafts = workspace
    (drafts / "rin-evaluation.json").unlink()
    with pytest.raises(review.ReviewError, match="rin-evaluation.json"):
        review.record_review(root, drafts, "Reviewer", confirm=False, reviewed_at=REVIEWED_AT)
