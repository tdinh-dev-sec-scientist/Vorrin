#!/usr/bin/env python3
"""Prove the console shows every Stage 3 failure state, in a real browser.

    python3 scripts/build_phase3_web.py
    python3 scripts/phase3_stage3_banners.py

Loads the built console bundle (build/phase3/web) in Chromium with the
production security headers, and answers its API calls with responses made
by the real public API code (phase3.public_api.public_response) or, for Rin,
with the exact bodies phase3.rin_service returns. No AWS access is needed.
For each failure state it checks the text the visitor actually sees:

    partial_scan             latest attempt UNKNOWN  -> "Incomplete scan"
    failed_scan              latest attempt ERROR    -> "Latest scan failed"
    stale_data               snapshot over 24 hours  -> "snapshot stale"
    publication_blocked      publication PAUSED      -> "Publication paused"
    api_unavailable          /api/latest returns 503 -> "Saved fixture data"
    kill_switch_static_mode  static-mode header      -> "Static mode active"
    rin_unavailable          /api/rin provider down  -> prepared fixture answer
    rin_over_budget          /api/rin DAILY_LIMIT    -> prepared fixture answer

The unreviewed result goes to build/phase3/stage3/failure-banners.json;
test_suite_sha256 is the SHA-256 of this file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phase3.public_api import public_response  # noqa: E402
from phase3.redaction import redact_snapshot  # noqa: E402

WEB = ROOT / "build/phase3/web"
OUTPUT = ROOT / "build/phase3/stage3/failure-banners.json"
ORIGIN = "https://console.vorrin.test"
# The production response headers (infra/phase3/control-plane/stage3.tf).
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
RIN_FALLBACK = "Live answers are paused."
STATES = (
    "partial_scan",
    "failed_scan",
    "stale_data",
    "publication_blocked",
    "api_unavailable",
    "rin_unavailable",
    "rin_over_budget",
    "kill_switch_static_mode",
)


def _report(completed: datetime) -> dict[str, Any]:
    stamp = completed.isoformat()
    finding = {
        "fingerprint": "a111111111111111",
        "control_id": "S3-001",
        "scanner": "account-access-auditor",
        "scanner_rule_id": "S3-001",
        "source_type": "aws",
        "resource_reference": "bucket:demo",
        "severity": "HIGH",
        "title": "S3 bucket public access block is incomplete",
        "description": "Two of the four S3 Block Public Access settings are disabled.",
        "evidence": {"restrict_public_buckets": False},
        "remediation": "Enable all four S3 Block Public Access settings.",
        "references": [{"type": "compliance", "framework": "CIS AWS Foundations", "id": "2.1.4"}],
        "lifecycle_state": "open",
        "detected_at": stamp,
        "account_ref": {"provider": "aws", "id": "000000000000"},
        "service": "s3",
        "region": "us-east-1",
    }
    return {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": [
                {"account_id": "000000000000", "service": "s3", "region": "us-east-1", "complete": True}
            ],
        },
        "summary": {},
        "contract": {
            "scan_run": {
                "run_id": "banner-check",
                "status": "FAIL",
                "gate_status": "NOT_CONFIGURED",
                "started_at": stamp,
                "completed_at": stamp,
                "regions": ["us-east-1"],
                "scanner_versions": {"account-access-auditor": "1.0.0"},
            },
            "findings": [finding],
        },
        "drift": [],
    }


class _Store:
    def __init__(self, snapshot, attempt):
        self.snapshot, self.attempt = snapshot, attempt

    def get_latest(self):
        return self.snapshot, self.attempt

    def list_runs(self, limit):
        del limit
        return []


def latest_response(state: str, now: datetime) -> tuple[int, dict[str, str], str]:
    """The /api/latest answer for one state, made by the real public API code."""
    if state == "api_unavailable":
        return 503, {}, json.dumps({"error": "PUBLIC_DATA_UNAVAILABLE"})
    completed = now - (timedelta(hours=30) if state == "stale_data" else timedelta(minutes=20))
    snapshot = redact_snapshot(_report(completed), secrets.token_bytes(32))
    attempt = None
    later = (now - timedelta(minutes=5)).isoformat()
    if state == "partial_scan":
        attempt = {
            "status": "UNKNOWN",
            "completed_at": later,
            "affected_services": [{"service": "s3", "status": "UNKNOWN"}],
        }
    elif state == "failed_scan":
        attempt = {"status": "ERROR", "completed_at": later}
    elif state == "publication_blocked":
        attempt = {"status": "FAIL", "completed_at": later, "publication_status": "PAUSED"}
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"}, store=_Store(snapshot, attempt), now=now
    )
    headers = {"X-Phase3-Static-Mode": "true"} if state == "kill_switch_static_mode" else {}
    return response["statusCode"], headers, response["body"]


def rin_response_for(state: str) -> tuple[int, str]:
    """Bodies phase3.rin_service returns when the provider is down or the daily cap is spent."""
    if state == "rin_over_budget":
        body = {
            "status": "UNAVAILABLE",
            "reason_code": "DAILY_LIMIT",
            "message": "Rin is using the local fixture fallback.",
        }
        return 429, json.dumps(body)
    body = {
        "status": "UNAVAILABLE",
        "reason_code": "ProviderUnavailable",
        "message": "Rin is using the local fixture fallback.",
    }
    return 200, json.dumps(body)


def _expected(state: str) -> tuple[str, str]:
    """(element id, text that must appear) for the banner states."""
    return {
        "partial_scan": ("source-label", "Incomplete scan"),
        "failed_scan": ("source-label", "Latest scan failed"),
        "stale_data": ("source-detail", "snapshot stale"),
        "publication_blocked": ("source-label", "Publication paused"),
        "api_unavailable": ("source-label", "Saved fixture data"),
        "kill_switch_static_mode": ("source-label", "Static mode active"),
    }[state]


def check_state(browser, state: str, now: datetime) -> bool:
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    rin_calls = []

    def route(request_route):
        request = request_route.request
        path = request.url.removeprefix(ORIGIN).split("?", 1)[0]
        if not request.url.startswith(ORIGIN):
            request_route.abort()
            return
        if path == "/api/latest":
            latest_state = "fresh" if state.startswith("rin_") else state
            status, headers, body = latest_response(latest_state, now)
            request_route.fulfill(
                status=status, headers={"Content-Type": "application/json", **headers}, body=body
            )
            return
        if path == "/api/rin":
            rin_calls.append(1)
            status, body = rin_response_for(state)
            request_route.fulfill(status=status, headers={"Content-Type": "application/json"}, body=body)
            return
        file = (WEB / (path.lstrip("/") or "index.html")).resolve()
        if not file.is_relative_to(WEB.resolve()) or not file.is_file():
            request_route.fulfill(status=404, body="")
            return
        content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        request_route.fulfill(
            status=200, headers={"Content-Type": content_type, **SECURITY_HEADERS}, body=file.read_bytes()
        )

    page.route("**/*", route)
    try:
        page.goto(f"{ORIGIN}/", wait_until="networkidle")
        if not state.startswith("rin_"):
            element, text = _expected(state)
            page.wait_for_function(
                "([id, text]) => (document.getElementById(id) || {}).textContent.includes(text)",
                arg=[element, text],
                timeout=10_000,
            )
            return True
        page.wait_for_function(
            "() => (document.getElementById('source-label') || {}).textContent === 'Live redacted AWS data'",
            timeout=10_000,
        )
        page.locator("#assistant-launcher").click()
        page.locator("#assistant-input").fill("Why is this risky?")
        page.keyboard.press("Enter")
        page.wait_for_function(
            "(text) => [...document.querySelectorAll('#assistant-messages > *')].some(n => n.textContent.includes(text))",
            arg=RIN_FALLBACK,
            timeout=10_000,
        )
        return len(rin_calls) == 1
    except Exception as exc:
        print(f"       {state}: {type(exc).__name__}: {str(exc).splitlines()[0]}")
        return False
    finally:
        context.close()


def suite_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.parse_args(argv)
    if not (WEB / "index.html").is_file():
        print("error: build the console first: python3 scripts/build_phase3_web.py", file=sys.stderr)
        return 1
    from playwright.sync_api import sync_playwright

    now = datetime.now(UTC)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        try:
            rendered = {state: check_state(browser, state, now) for state in STATES}
        finally:
            browser.close()
    for state, passed in rendered.items():
        print(f"{'ok  ' if passed else 'FAIL'} {state}")
    if not all(rendered.values()):
        print("\nA failure state was not shown; nothing was written.")
        return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = {"schema_version": 1, "test_suite_sha256": suite_sha256(), "rendered_states": rendered}
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nAll {len(rendered)} failure states were shown. Wrote {OUTPUT.relative_to(ROOT)} (unreviewed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
