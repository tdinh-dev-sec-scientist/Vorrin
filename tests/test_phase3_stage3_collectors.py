"""Stage 3 browser collectors: banner states, network privacy, and accessibility checks."""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


banners = _load("phase3_stage3_banners")
browser_check = _load("phase3_stage3_browser")


def test_banner_states_match_the_stage3_evidence_schema():
    from phase3 import stage_evidence

    assert set(banners.STATES) == stage_evidence._FAILURE_BANNER_STATES


@pytest.mark.parametrize(
    ("state", "check"),
    [
        ("partial_scan", lambda body: body["freshness"]["latest_attempt_status"] == "UNKNOWN"),
        ("failed_scan", lambda body: body["freshness"]["latest_attempt_status"] == "ERROR"),
        ("stale_data", lambda body: body["freshness"]["stale"] is True),
        ("publication_blocked", lambda body: body["freshness"]["publication_paused"] is True),
        (
            "fresh",
            lambda body: (
                body["freshness"]["stale"] is False and body["freshness"]["latest_attempt_status"] is None
            ),
        ),
    ],
)
def test_latest_responses_come_from_the_public_api(state, check):
    status, headers, body = banners.latest_response(state, datetime.now(UTC))
    assert status == 200 and headers == {}
    assert check(json.loads(body))


def test_outage_static_mode_and_rin_responses():
    now = datetime.now(UTC)
    assert banners.latest_response("api_unavailable", now)[0] == 503
    assert banners.latest_response("kill_switch_static_mode", now)[1] == {"X-Phase3-Static-Mode": "true"}
    assert banners.rin_response_for("rin_over_budget")[0] == 429
    assert json.loads(banners.rin_response_for("rin_over_budget")[1])["reason_code"] == "DAILY_LIMIT"
    assert json.loads(banners.rin_response_for("rin_unavailable")[1])["reason_code"] == "ProviderUnavailable"


@pytest.fixture(scope="module")
def chromium():
    sync_api = pytest.importorskip("playwright.sync_api")
    if not (ROOT / "build/phase3/web/index.html").is_file():
        pytest.skip("console bundle is not built")
    with sync_api.sync_playwright() as playwright:
        try:
            launched = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        except Exception as exc:  # pragma: no cover - depends on the local browser install
            pytest.skip(f"Chromium unavailable: {exc}")
        yield launched
        launched.close()


@pytest.mark.parametrize("state", banners.STATES)
def test_every_failure_state_is_shown_in_the_browser(chromium, state):
    assert banners.check_state(chromium, state, datetime.now(UTC)) is True


def test_a_missing_banner_is_reported(chromium, monkeypatch):
    monkeypatch.setattr(banners, "_expected", lambda _state: ("source-label", "text that never appears"))
    assert banners.check_state(chromium, "partial_scan", datetime.now(UTC)) is False


def test_urls_are_stripped_of_queries_and_fragments():
    url = "https://auth.example/oauth2/authorize?code=secret&state=x#id_token=abc"
    assert browser_check.strip_url(url) == "https://auth.example/oauth2/authorize"


def test_unapproved_origins_are_reported_once():
    requests = [
        {"url": "https://vorrin.example/api/latest"},
        {"url": "https://fonts.example/a.woff"},
        {"url": "https://fonts.example/b.woff"},
    ]
    assert browser_check.unapproved(requests, {"https://vorrin.example"}) == ["https://fonts.example"]


def test_only_serious_and_critical_axe_violations_block():
    results = {
        "dashboard": [{"id": "region", "impact": "moderate"}, {"id": "color-contrast", "impact": "serious"}]
    }
    assert browser_check.blocking_violations(results) == ["dashboard: color-contrast (serious)"]


def test_lighthouse_thresholds_and_screenshot_removal():
    report = {
        "categories": {"accessibility": {"score": 0.96}, "best-practices": {"score": 0.8}},
        "audits": {"final-screenshot": {}, "color-contrast": {}},
        "fullPageScreenshot": {},
    }
    assert browser_check.lighthouse_failures(report) == ["Lighthouse best-practices 0.8 is below 0.9"]
    slim = browser_check.slim_lighthouse(report)
    assert "final-screenshot" not in slim["audits"] and "fullPageScreenshot" not in slim


def test_vendored_axe_is_the_pinned_release():
    import hashlib

    data = (ROOT / "tools/vendor/axe-core/axe.min.js").read_bytes()
    assert (
        hashlib.sha256(data).hexdigest() == "20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878"
    )
    assert b"axe v4.14.0" in data[:300]
    assert (ROOT / "tools/vendor/axe-core/LICENSE").is_file()
