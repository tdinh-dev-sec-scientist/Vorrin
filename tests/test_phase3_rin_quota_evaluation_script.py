"""The quota fallback evaluation runs the real quota and kill-switch code."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "quota_evaluation", ROOT / "scripts/phase3_rin_quota_evaluation.py"
)
quota_evaluation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(quota_evaluation)


def test_every_cap_falls_back_to_fixtures():
    assert quota_evaluation.evaluate(12) == {"session": True, "daily": True, "monthly_budget": True}


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ((5, 1.10, 5.50, 3072, 600), 19),
        ((10, 1.10, 5.50, 4096, 600), 34),
        ((1000, 0.01, 0.01, 512, 128), 1000),
        ((5, 0, 0, 512, 128), 0),
    ],
)
def test_daily_cap_matches_the_terraform_formula(args, expected):
    assert quota_evaluation.daily_cap(*args) == expected


def test_daily_cap_formula_is_the_one_terraform_uses():
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")
    assert re.search(r"var\.provider_monthly_budget_usd \* 0\.8 / 30\) / local\.rin_request_cost_usd", stage3)
    assert "min(\n    1000," in stage3
    assert "/ 1000000" in stage3


def test_a_broken_quota_writer_is_reported(monkeypatch):
    monkeypatch.setattr(quota_evaluation, "consume_quota", lambda *_args: {"allowed": True, "reason": "OK"})
    cases = quota_evaluation.evaluate(5)
    assert cases["session"] is False and cases["daily"] is False
