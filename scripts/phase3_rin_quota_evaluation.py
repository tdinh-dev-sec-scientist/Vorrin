#!/usr/bin/env python3
"""Prove Rin falls back to fixtures at the session, daily, and budget caps.

    python3 scripts/phase3_rin_quota_evaluation.py --monthly-budget-usd 5 \\
        --input-price-per-million 1.10 --output-price-per-million 5.50 \\
        --max-input-tokens 3072 --max-output-tokens 600

Runs Rin's request handler with the real quota writer (phase3.quotas) and
budget kill switch (phase3.kill_switch) against DynamoDB emulated by Moto,
so it needs no AWS credentials and calls no model. The daily cap is computed
with the same formula Terraform uses for PHASE3_RIN_DAILY_CAP, so pass the
same values you will set in the GitHub variables:

    PHASE3_PROVIDER_MONTHLY_BUDGET_USD           --monthly-budget-usd
    PHASE3_RIN_INPUT_COST_PER_MILLION_TOKENS_USD --input-price-per-million
    PHASE3_RIN_OUTPUT_COST_PER_MILLION_TOKENS_USD --output-price-per-million
    PHASE3_RIN_MAX_INPUT_TOKENS                  --max-input-tokens
    PHASE3_RIN_MAX_OUTPUT_TOKENS                 --max-output-tokens

Cases:
  session        the 11th question from one browser session is refused
  daily          the question after the daily cap is refused
  monthly_budget the 100% budget alert sets static mode and Rin stops

Each refusal must be the fixture fallback, and no refused question may reach
the model. The unreviewed result goes to build/phase3/stage3/quota-fallbacks.json.
"""

from __future__ import annotations

import argparse
import json
import math
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phase3.kill_switch import disable_live_features  # noqa: E402
from phase3.quotas import SESSION_QUESTION_LIMIT, consume_quota  # noqa: E402
from phase3.redaction import redact_snapshot  # noqa: E402
from phase3.rin_service import rin_response  # noqa: E402

OUTPUT = ROOT / "build/phase3/stage3/quota-fallbacks.json"
TOPIC = "arn:aws:sns:us-east-1:000000000000:phase3-budget-kill"
MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def daily_cap(budget: float, input_price: float, output_price: float, max_in: int, max_out: int) -> int:
    """Mirror of local.rin_daily_cap in infra/phase3/control-plane/stage3.tf."""
    request_cost = (max_in * input_price + max_out * output_price) / 1_000_000
    if request_cost <= 0:
        return 0
    return min(1000, max(0, math.floor((budget * 0.8 / 30) / request_cost)))


def _report(now: datetime) -> dict[str, Any]:
    completed = now.isoformat()
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
        "evidence": {"block_public_acls": False},
        "remediation": "Enable all four S3 Block Public Access settings.",
        "references": [{"type": "compliance", "framework": "CIS AWS Foundations", "id": "2.1.4"}],
        "lifecycle_state": "open",
        "detected_at": completed,
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
                "run_id": "quota-evaluation",
                "status": "FAIL",
                "gate_status": "NOT_CONFIGURED",
                "started_at": completed,
                "completed_at": completed,
                "regions": ["us-east-1"],
                "scanner_versions": {"account-access-auditor": "1.0.0"},
            },
            "findings": [finding],
        },
        "drift": [],
    }


class _Store:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def get_latest(self):
        return self.snapshot, None

    def list_runs(self, limit):
        del limit
        return []


def evaluate(cap: int) -> dict[str, Any]:
    import boto3
    from moto import mock_aws

    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        tables = {}
        for name in ("quota", "feature"):
            tables[name] = dynamodb.create_table(
                TableName=name,
                KeySchema=[
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                    {"AttributeName": "sk", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )
        tables["feature"].put_item(
            Item={"pk": "PLATFORM", "sk": "CONFIG", "rin_enabled": True, "static_mode": False}
        )
        snapshot = redact_snapshot(_report(datetime.now(UTC)), secrets.token_bytes(32))
        finding_id = snapshot["findings"][0]["id"]
        model_calls = []

        def provider(request, api_key=None):
            del api_key
            model_calls.append(1)
            fingerprint = json.loads(request["input"])["findings"][0]["fingerprint"]
            return {
                "schema_version": "1.0.0",
                "analyses": [
                    {
                        "fingerprint": fingerprint,
                        "explanation": "Enable all four Block Public Access settings.",
                        "uncertainty": "The scan does not show current exposure.",
                        "citations": ["REMEDIATION"],
                        "proposal": None,
                    }
                ],
            }

        def enabled_now():
            item = tables["feature"].get_item(Key={"pk": "PLATFORM", "sk": "CONFIG"}, ConsistentRead=True)[
                "Item"
            ]
            return item.get("rin_enabled") is True and item.get("static_mode") is not True

        def ask(session_token):
            event = {
                "httpMethod": "POST",
                "path": "/api/rin",
                "body": json.dumps(
                    {
                        "question": "How do I fix this?",
                        "finding_id": finding_id,
                        "session_token": session_token,
                    }
                ),
            }
            response = rin_response(
                event,
                store=_Store(snapshot),
                enabled=True,
                model=MODEL,
                api_key=None,
                max_output_tokens=600,
                quota_consumer=lambda token: consume_quota(tables["quota"], token, cap),
                enabled_check=enabled_now,
                provider=provider,
                guardrail=lambda **_kwargs: {"action": "NONE"},
                guardrail_identifier="arn:aws:bedrock:us-east-1:000000000000:guardrail/quota",
                guardrail_version="1",
                requires_api_key=False,
            )
            return response["statusCode"], json.loads(response["body"])

        def fixture(body, reason):
            return body.get("reason_code") == reason and "fixture fallback" in body.get("message", "")

        cases = {}

        # Session cap: SESSION_QUESTION_LIMIT answers, then a refusal.
        token = secrets.token_urlsafe(32)
        answered = [ask(token)[1].get("status") == "COMPLETE" for _ in range(SESSION_QUESTION_LIMIT)]
        calls_before = len(model_calls)
        status, body = ask(token)
        cases["session"] = all(answered) and status == 429 and fixture(body, "SESSION_LIMIT")
        cases["session"] = cases["session"] and len(model_calls) == calls_before

        # Daily cap: fresh sessions until the global count reaches the cap.
        tables["quota"].delete_item(Key={"pk": "GLOBAL", "sk": f"DAY#{datetime.now(UTC).date().isoformat()}"})
        answered_today = 0
        for _ in range(math.ceil(cap / SESSION_QUESTION_LIMIT)):
            session_token = secrets.token_urlsafe(32)
            for _ in range(min(SESSION_QUESTION_LIMIT, cap - answered_today)):
                answered_today += ask(session_token)[1].get("status") == "COMPLETE"
        calls_before = len(model_calls)
        status, body = ask(secrets.token_urlsafe(32))
        cases["daily"] = answered_today == cap and status == 429 and fixture(body, "DAILY_LIMIT")
        cases["daily"] = cases["daily"] and len(model_calls) == calls_before

        # Monthly budget: the 100% alert flips static mode; Rin stops before the model.
        tables["quota"].delete_item(Key={"pk": "GLOBAL", "sk": f"DAY#{datetime.now(UTC).date().isoformat()}"})
        disable_live_features(
            {
                "Records": [
                    {
                        "EventSource": "aws:sns",
                        "Sns": {"Type": "Notification", "TopicArn": TOPIC, "Message": "100%"},
                    }
                ]
            },
            table=tables["feature"],
            expected_topic_arn=TOPIC,
        )
        calls_before = len(model_calls)
        status, body = ask(secrets.token_urlsafe(32))
        cases["monthly_budget"] = (
            status == 200 and fixture(body, "RIN_DISABLED") and len(model_calls) == calls_before
        )
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--monthly-budget-usd", type=float, required=True)
    parser.add_argument("--input-price-per-million", type=float, required=True)
    parser.add_argument("--output-price-per-million", type=float, required=True)
    parser.add_argument("--max-input-tokens", type=int, required=True)
    parser.add_argument("--max-output-tokens", type=int, required=True)
    args = parser.parse_args(argv)
    cap = daily_cap(
        args.monthly_budget_usd,
        args.input_price_per_million,
        args.output_price_per_million,
        args.max_input_tokens,
        args.max_output_tokens,
    )
    if cap < 1:
        print(
            "error: these values give a daily cap of 0; raise the budget or lower the token limits",
            file=sys.stderr,
        )
        return 1
    print(f"Daily cap (same formula as Terraform): {cap} questions")
    cases = evaluate(cap)
    for name, passed in cases.items():
        print(f"{'ok  ' if passed else 'FAIL'} {name}")
    if not all(cases.values()):
        print("\nA cap did not fall back to fixtures; nothing was written.")
        return 1
    document = {
        "schema_version": 1,
        "per_session_limit": SESSION_QUESTION_LIMIT,
        "daily_invocation_limit": cap,
        "monthly_budget_usd": args.monthly_budget_usd,
        "cases": {name: {"limit_reached": True, "response_mode": "fixture"} for name in cases},
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nAll caps fell back to fixtures. Wrote {OUTPUT.relative_to(ROOT)} (unreviewed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
