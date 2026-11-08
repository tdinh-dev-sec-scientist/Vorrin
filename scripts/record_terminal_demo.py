#!/usr/bin/env python3
"""Record the real Rin evaluation runs as a terminal video, without VHS.

    aws sso login --profile vorrin-admin
    python3 scripts/record_terminal_demo.py --profile vorrin-admin

Runs, for real, the Guardrail suite and Rin's adversarial evaluation (Claude
Haiku on Amazon Bedrock with the published Guardrail; a few cents), captures
their exact output, then plays it back in a terminal-style page in Chromium:
the command is typed, the output lines appear in order, and Playwright saves
a 1280x720 video:

    build/demo/rin-terminal.webm

Nothing in the output is edited. Neither command prints an account ID or ARN.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "build/demo/rin-terminal.webm"
SIZE = {"width": 1280, "height": 720}
MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:#1e1f29;font:15px/1.45 Menlo,Monaco,'Courier New',monospace;color:#f8f8f2}
.bar{height:34px;background:#2b2d3a;display:flex;align-items:center;padding:0 14px;gap:8px}
.dot{width:12px;height:12px;border-radius:50%}
.title{margin-left:12px;color:#9aa0b5;font-size:13px}
#screen{padding:18px 26px;height:calc(100vh - 70px);overflow:hidden;white-space:pre-wrap;word-break:break-word}
.prompt{color:#bd93f9}.comment{color:#6272a4}.ok{color:#50fa7b}.fail{color:#ff5555}
.dim{color:#9aa0b5}.hl{color:#f1fa8c}
</style></head><body>
<div class="bar"><span class="dot" style="background:#ff5f56"></span><span class="dot" style="background:#ffbd2e"></span>
<span class="dot" style="background:#27c93f"></span><span class="title">vorrin — Rin red-team evaluation</span></div>
<div id="screen"></div>
<script>
const steps = __STEPS__;
const screen = document.getElementById('screen');
const sleep = ms => new Promise(r => setTimeout(r, ms));
function line(text, cls) {
  const div = document.createElement('div');
  if (cls) div.className = cls;
  div.textContent = text;
  screen.appendChild(div);
  while (screen.scrollHeight > screen.clientHeight && screen.firstChild) screen.removeChild(screen.firstChild);
  return div;
}
function styleFor(text) {
  if (/^ok\\b/.test(text)) return 'ok';
  if (/^FAIL\\b/.test(text)) return 'fail';
  if (/PROMPT_ATTACK|All \\d+ cases passed|topic /.test(text)) return 'hl';
  if (/^\\s+(answer|cited|guardrail):/.test(text)) return 'dim';
  return '';
}
(async () => {
  await sleep(800);
  for (const step of steps) {
    line('# ' + step.comment, 'comment');
    await sleep(500);
    const cmd = line('', '');
    const prompt = document.createElement('span'); prompt.className = 'prompt'; prompt.textContent = 'vorrin $ ';
    cmd.appendChild(prompt);
    const typed = document.createElement('span'); cmd.appendChild(typed);
    for (const ch of step.command) { typed.textContent += ch; await sleep(18); }
    await sleep(700);
    for (const out of step.output) { line(out, styleFor(out)); await sleep(/answer:/.test(out) ? 900 : 140); }
    await sleep(3500);
    screen.innerHTML = '';
  }
  document.title = 'done';
})();
</script></body></html>"""


def run(command: list[str]) -> list[str]:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
    lines = (result.stdout + result.stderr).rstrip("\n").splitlines()
    if result.returncode != 0:
        print("\n".join(lines))
        raise SystemExit(f"error: {' '.join(command[1:3])} failed; nothing was recorded")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--guardrail-version", default="3")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    python = sys.executable
    guardrail_cmd = [
        "scripts/phase3_rin_guardrail.py",
        "evaluate",
        "--profile",
        args.profile,
        "--version",
        args.guardrail_version,
    ]
    rin_cmd = [
        "scripts/phase3_rin_evaluation.py",
        "--profile",
        args.profile,
        "--model",
        MODEL,
        "--guardrail-version",
        args.guardrail_version,
    ]
    print("Running the Guardrail suite (about 30 seconds)…")
    guardrail_out = run([python, *guardrail_cmd])
    print("Running Rin's adversarial evaluation with Claude Haiku (about 1 minute)…")
    rin_out = run([python, *rin_cmd])
    steps = [
        {
            "comment": "Rin's Bedrock Guardrail: 26 attack and must-allow cases",
            "command": "python3 " + " ".join(guardrail_cmd),
            "output": guardrail_out,
        },
        {
            "comment": "Rin end to end: Claude Haiku on Amazon Bedrock + the published Guardrail",
            "command": "python3 " + " ".join(rin_cmd),
            "output": rin_out,
        },
    ]
    page_html = PAGE.replace("__STEPS__", json.dumps(steps))

    from playwright.sync_api import sync_playwright

    print("Recording the playback…")
    with tempfile.TemporaryDirectory() as directory:
        page_file = Path(directory) / "terminal.html"
        page_file.write_text(page_html, encoding="utf-8")
        video_dir = Path(directory) / "video"
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
            context = browser.new_context(
                viewport=SIZE, record_video_dir=str(video_dir), record_video_size=SIZE
            )
            page = context.new_page()
            page.goto(page_file.as_uri())
            page.wait_for_function("() => document.title === 'done'", timeout=600_000)
            video = page.video
            context.close()
            browser.close()
            source = Path(video.path())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), args.output)
    print(f"Saved {args.output.relative_to(ROOT) if args.output.is_relative_to(ROOT) else args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
