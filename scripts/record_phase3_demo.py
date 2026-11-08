#!/usr/bin/env python3
"""Record a hands-free walkthrough of the Vorrin console for the demo video.

    pip install playwright && python3 -m playwright install chromium
    python3 scripts/record_phase3_demo.py --url https://d1gjme6ojxhjqb.cloudfront.net/

A Chromium window opens on the console. Sign in yourself (email, password,
authenticator code): the script never sees or stores credentials. As soon as
the console shows "Sign out", it drives the tour on its own with a visible
cursor and slow typing, then saves a 1920x1080 video:

    build/demo/console-walkthrough.webm

Tour: Overview, AWS Accounts, Security Scans, Findings (search "S3" and open
the finding), Drift History, Security & Limits, then Rin: it opens the
assistant and asks three questions. The sign-in part is at the start of the
video; trim it or keep it as the "invite-only with MFA" scene.

Use --no-login with a local build (scripts/build_phase3_web.py) to rehearse.
"""

from __future__ import annotations

import argparse
import os
import shutil
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "build/demo/console-walkthrough.webm"
SIZE = {"width": 1920, "height": 1080}

# A visible cursor: recorded video does not include the OS pointer.
CURSOR_SCRIPT = """
(() => {
  const install = () => {
    if (document.getElementById('demo-cursor')) return;
    const dot = document.createElement('div');
    dot.id = 'demo-cursor';
    dot.style.cssText = 'position:fixed;left:0;top:0;width:22px;height:22px;margin:-11px 0 0 -11px;'
      + 'border-radius:50%;background:rgba(135,71,149,.35);border:2px solid #c99be0;'
      + 'pointer-events:none;z-index:2147483647;transition:transform .12s ease;';
    document.documentElement.appendChild(dot);
    addEventListener('mousemove', e => { dot.style.left = e.clientX + 'px'; dot.style.top = e.clientY + 'px'; }, true);
    addEventListener('mousedown', () => { dot.style.transform = 'scale(.7)'; }, true);
    addEventListener('mouseup', () => { dot.style.transform = 'scale(1)'; }, true);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install); else install();
})();
"""


class Tour:
    def __init__(self, page, pace: float) -> None:
        self.page = page
        self.pace = pace

    def pause(self, seconds: float) -> None:
        time.sleep(seconds * self.pace)

    def glide_to(self, locator) -> None:
        box = locator.bounding_box()
        if box:
            self.page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=30)
        self.pause(0.4)

    def click(self, locator) -> None:
        locator.scroll_into_view_if_needed()
        self.glide_to(locator)
        locator.click()
        self.pause(1.2)

    def view(self, name: str, linger: float = 4.0) -> None:
        self.click(self.page.locator(f'#sidebar [data-view="{name}"]').first)
        self.page.mouse.move(1100, 500, steps=25)
        self.pause(linger)

    def scroll(self, pixels: int, linger: float = 2.5) -> None:
        for _ in range(10):
            self.page.mouse.wheel(0, pixels / 10)
            time.sleep(0.05)
        self.pause(linger)

    def type(self, locator, text: str) -> None:
        self.click(locator)
        locator.press_sequentially(text, delay=70)
        self.pause(0.8)


def wait_for_sign_in(page, timeout_minutes: float) -> None:
    print("Sign in in the browser window. The tour starts when the console shows 'Sign out'.")
    page.wait_for_function(
        "() => (document.getElementById('auth-label') || {}).textContent === 'Sign out'",
        timeout=int(timeout_minutes * 60_000),
    )


def run_tour(tour: Tour) -> None:
    page = tour.page
    tour.pause(2.5)
    tour.view("overview", 5)
    tour.scroll(500, 3)
    tour.scroll(-500, 1)
    tour.view("aws-accounts", 5)
    tour.view("security-scans", 4)
    tour.view("findings", 3)
    tour.type(page.locator("#global-search"), "S3")
    tour.pause(2)
    rows = page.locator("#view-root").get_by_role("button").filter(has_text="S3")
    if rows.count():
        tour.click(rows.first)
        tour.pause(4)
        tour.scroll(400, 3)
        tour.scroll(400, 3)
        page.keyboard.press("Escape")
        tour.pause(1)
    page.locator("#global-search").fill("")
    tour.view("drift-history", 5)
    tour.scroll(400, 3)
    tour.view("security-limits", 4)
    tour.scroll(500, 3)
    tour.view("findings", 2)

    tour.click(page.locator("#assistant-launcher"))
    tour.pause(2)
    for question in (
        "What is the top finding?",
        "How do I fix the S3 public access finding?",
        "How does Rin keep my data safe?",
    ):
        tour.type(page.locator("#assistant-input"), question)
        page.keyboard.press("Enter")
        tour.pause(6)
        page.locator("#assistant-messages").evaluate(
            "node => node.scrollTo({top: node.scrollHeight, behavior: 'smooth'})"
        )
        tour.pause(3)
    tour.pause(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--no-login", action="store_true", help="skip waiting for sign-in (local rehearsal)")
    parser.add_argument("--headless", action="store_true", help="only with --no-login")
    parser.add_argument("--pace", type=float, default=1.0, help="multiply every pause (e.g. 1.3 is slower)")
    parser.add_argument("--sign-in-minutes", type=float, default=5)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    if args.headless and not args.no_login:
        parser.error("--headless needs --no-login: you sign in in a visible window")

    from playwright.sync_api import sync_playwright

    video_dir = args.output.parent / ".raw"
    video_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=args.headless,
            args=["--window-size=1920,1160"],
            executable_path=os.environ.get("CHROMIUM_PATH") or None,
        )
        context = browser.new_context(
            viewport=SIZE,
            record_video_dir=str(video_dir),
            record_video_size=SIZE,
            color_scheme="dark",
        )
        context.add_init_script(CURSOR_SCRIPT)
        page = context.new_page()
        page.goto(args.url, wait_until="domcontentloaded")
        try:
            if not args.no_login:
                wait_for_sign_in(page, args.sign_in_minutes)
            run_tour(Tour(page, args.pace))
        finally:
            video = page.video
            context.close()
            browser.close()
        source = Path(video.path())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), args.output)
    shutil.rmtree(video_dir, ignore_errors=True)
    print(f"Saved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
