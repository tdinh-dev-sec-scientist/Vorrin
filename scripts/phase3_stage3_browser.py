#!/usr/bin/env python3
"""Capture Stage 3 browser privacy and accessibility evidence from the live console.

    python3 scripts/phase3_stage3_browser.py --url https://vorrin.truongdinh.dev/

Needs Node.js (for Lighthouse, run with npx) and Playwright's Chromium.

1. A Chromium window opens and the script clicks Sign in. You sign in
   yourself; the script never sees credentials. Sign-in happens on the
   AWS-hosted Cognito pages, which are outside this check.
2. Once the console shows "Sign out", every request the console makes is
   logged while the script opens the three pages Stage 3 names:
   dashboard (Overview), finding (Findings with one finding open), and rin
   (the Rin assistant after one question). Any request to an origin other
   than the console or its Cognito domain is an unapproved third-party
   request.
3. axe-core 4.14.0 (vendored in tools/vendor/axe-core) audits each page.
4. Lighthouse audits the console's signed-out page (the same bundle) for
   performance, accessibility, best practices, and SEO.

Evidence passes only with no unapproved third-party requests, no serious or
critical axe violations, and Lighthouse accessibility and best-practices
scores of at least 90. The source reports go to
docs/evidence/stage3/source-reports/ (query strings and fragments removed)
and the unreviewed summary to build/phase3/stage3/privacy-accessibility.json.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "docs/evidence/stage3/source-reports"
SUMMARY = ROOT / "build/phase3/stage3/privacy-accessibility.json"
AXE = ROOT / "tools/vendor/axe-core/axe.min.js"
AXE_VERSION = "4.14.0"
LIGHTHOUSE = "lighthouse@12.8.2"
SIZE = {"width": 1440, "height": 810}
MIN_LIGHTHOUSE = {"accessibility": 0.9, "best-practices": 0.9}
BLOCKING_IMPACTS = {"serious", "critical"}
# Lighthouse report fields that only hold page screenshots.
SCREENSHOT_AUDITS = ("screenshot-thumbnails", "final-screenshot", "full-page-screenshot")


def strip_url(url: str) -> str:
    """Origin and path only: drop query strings and fragments (auth codes, tokens)."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def unapproved(requests: list[dict[str, str]], approved: set[str]) -> list[str]:
    return sorted({origin(item["url"]) for item in requests if origin(item["url"]) not in approved})


def blocking_violations(axe_results: dict[str, list[dict[str, Any]]]) -> list[str]:
    return sorted(
        f"{page}: {violation['id']} ({violation.get('impact')})"
        for page, violations in axe_results.items()
        for violation in violations
        if violation.get("impact") in BLOCKING_IMPACTS
    )


def lighthouse_failures(report: dict[str, Any]) -> list[str]:
    failures = []
    for category, minimum in MIN_LIGHTHOUSE.items():
        score = (report.get("categories", {}).get(category) or {}).get("score")
        if not isinstance(score, (int, float)) or score < minimum:
            failures.append(f"Lighthouse {category} {score} is below {minimum}")
    return failures


def slim_lighthouse(report: dict[str, Any]) -> dict[str, Any]:
    audits = report.get("audits", {})
    for name in SCREENSHOT_AUDITS:
        audits.pop(name, None)
    report.pop("fullPageScreenshot", None)
    report.pop("i18n", None)
    return report


def run_axe(page) -> list[dict[str, Any]]:
    page.evaluate(AXE.read_text(encoding="utf-8"))
    results = page.evaluate(
        "async () => { const r = await axe.run(document, {resultTypes: ['violations']});"
        " return r.violations.map(v => ({id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, targets: v.nodes.slice(0, 5).map(n => n.target.join(' '))})); }"
    )
    return results


def browse(url: str, *, no_login: bool, sign_in_minutes: float, headless: bool) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    requests: list[dict[str, str]] = []
    recording = {"on": False}
    axe_results: dict[str, list[dict[str, Any]]] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=headless,
            args=[f"--window-size={SIZE['width']},{SIZE['height'] + 90}"],
            executable_path=os.environ.get("CHROMIUM_PATH") or None,
        )
        context = browser.new_context(viewport=SIZE)
        page = context.new_page()

        def log(request):
            if recording["on"]:
                requests.append(
                    {"method": request.method, "url": strip_url(request.url), "type": request.resource_type}
                )

        context.on("request", log)
        page.goto(url, wait_until="domcontentloaded")
        auth_origin = None
        if not no_login:
            button = page.locator("#auth-button")
            button.wait_for(state="visible", timeout=30_000)
            if (page.locator("#auth-label").text_content() or "").strip() != "Sign out":
                button.click()
            print("Sign in in the browser window. The check starts when the console shows 'Sign out'.")
            page.wait_for_function(
                "() => (document.getElementById('auth-label') || {}).textContent === 'Sign out'",
                timeout=int(sign_in_minutes * 60_000),
            )
            config = page.evaluate(
                "async () => { const r = await fetch('/auth-config.json', {cache: 'no-store'}); return r.ok ? r.json() : null; }"
            )
            for value in (config or {}).values():
                if isinstance(value, str) and value.startswith("https://") and "amazoncognito.com" in value:
                    auth_origin = origin(value)
        recording["on"] = True
        page.reload(wait_until="networkidle")
        if not no_login:
            page.wait_for_function(
                "() => (document.getElementById('auth-label') || {}).textContent === 'Sign out'",
                timeout=60_000,
            )
        page.wait_for_timeout(1500)
        page.locator('#sidebar [data-view="overview"]').first.click()
        page.wait_for_timeout(1500)
        axe_results["dashboard"] = run_axe(page)

        page.locator('#sidebar [data-view="findings"]').first.click()
        page.wait_for_timeout(1000)
        rows = page.locator("#view-root").get_by_role("button").filter(has_text="S3")
        if rows.count():
            rows.first.click()
            page.wait_for_timeout(1500)
        axe_results["finding"] = run_axe(page)
        page.keyboard.press("Escape")

        page.locator("#assistant-launcher").click()
        page.locator("#assistant-input").fill("Why is this risky and how do I fix it?")
        page.keyboard.press("Enter")
        page.wait_for_timeout(6000)
        axe_results["rin"] = run_axe(page)
        recording["on"] = False
        context.close()
        browser.close()
    approved = {origin(url)} | ({auth_origin} if auth_origin else set())
    return {"requests": requests, "approved_origins": sorted(approved), "axe": axe_results}


def run_lighthouse(url: str) -> dict[str, Any]:
    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError("Node.js is required for Lighthouse: install it (brew install node) and run again")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        chrome = os.environ.get("CHROMIUM_PATH") or playwright.chromium.executable_path
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "lighthouse.json"
        subprocess.run(
            [
                npx,
                "--yes",
                LIGHTHOUSE,
                url,
                "--quiet",
                "--no-enable-error-reporting",
                "--output=json",
                f"--output-path={output}",
                "--only-categories=performance,accessibility,best-practices,seo",
                "--chrome-flags=--headless=new --no-sandbox",
            ],
            check=True,
            env={**os.environ, "CHROME_PATH": chrome},
            timeout=300,
        )
        return json.loads(output.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--no-login", action="store_true", help="local rehearsal without sign-in")
    parser.add_argument("--headless", action="store_true", help="only with --no-login")
    parser.add_argument("--sign-in-minutes", type=float, default=5)
    args = parser.parse_args(argv)
    if args.headless and not args.no_login:
        parser.error("--headless needs --no-login: you sign in in a visible window")
    if not args.url.startswith("https://") and not args.no_login:
        parser.error("--url must be the HTTPS console address")

    browsed = browse(
        args.url, no_login=args.no_login, sign_in_minutes=args.sign_in_minutes, headless=args.headless
    )
    lighthouse = slim_lighthouse(run_lighthouse(args.url))

    third_party = unapproved(browsed["requests"], set(browsed["approved_origins"]))
    axe_blocking = blocking_violations(browsed["axe"])
    lighthouse_problems = lighthouse_failures(lighthouse)
    print(
        f"Requests logged: {len(browsed['requests'])} (approved origins: {', '.join(browsed['approved_origins'])})"
    )
    print(f"Unapproved third-party origins: {third_party or 'none'}")
    for page, violations in browsed["axe"].items():
        summary = (
            ", ".join(f"{v['id']} ({v['impact']}) at {', '.join(v.get('targets', []))}" for v in violations)
            or "none"
        )
        print(f"axe {page}: {summary}")
    for category, data in lighthouse.get("categories", {}).items():
        print(f"Lighthouse {category}: {round((data.get('score') or 0) * 100)}")
    problems = [f"third-party request to {item}" for item in third_party] + axe_blocking + lighthouse_problems
    if problems:
        print("\nNot written. Fix these first:\n  " + "\n  ".join(problems))
        return 1

    write_json(
        REPORTS / "browser-network.json",
        {
            "schema_version": 1,
            "approved_origins": browsed["approved_origins"],
            "pages": ["dashboard", "finding", "rin"],
            "requests": browsed["requests"],
        },
    )
    write_json(
        REPORTS / "accessibility.json",
        {"schema_version": 1, "tool": f"axe-core {AXE_VERSION}", "pages": browsed["axe"]},
    )
    write_json(REPORTS / "lighthouse.json", lighthouse)
    write_json(
        SUMMARY,
        {
            "schema_version": 1,
            "unapproved_third_party_requests": [],
            "pages_checked": ["dashboard", "finding", "rin"],
        },
    )
    print("\nWrote source-reports/browser-network.json, accessibility.json, lighthouse.json")
    print(f"Wrote {SUMMARY.relative_to(ROOT)} (unreviewed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
