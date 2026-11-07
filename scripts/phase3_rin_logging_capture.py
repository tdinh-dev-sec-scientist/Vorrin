#!/usr/bin/env python3
"""Capture where Rin's prompts could be logged, for the Stage 3 logging review.

    python3 scripts/phase3_rin_logging_capture.py --profile vorrin-admin --provider bedrock

Reads the account's Amazon Bedrock model invocation logging configuration
(and, when prompts are delivered to CloudWatch Logs or S3, how long they are
kept) and writes the two Stage 3 source exports:

    docs/evidence/stage3/bedrock-logging-settings.json
    docs/evidence/stage3/external-provider-logging-settings.json

With ``--provider bedrock`` Rin calls no external model provider, so the
external export records that no provider receives prompts. Rin's own Lambda
never logs question or answer text.

The exports are refused (exit 1, nothing written) when Bedrock delivers
prompt text somewhere without a known retention of at most 30 days, the
review limit the Stage 3 gate enforces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/stage3"
MAX_PROMPT_RETENTION_DAYS = 30
NO_EXTERNAL_PROVIDER = "none (Rin uses Amazon Bedrock in the control-plane account)"


class LoggingCaptureError(RuntimeError):
    pass


def _log_group_retention(logs, name: str) -> int | None:
    groups = [
        group
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
        for group in page.get("logGroups", [])
        if group.get("logGroupName") == name
    ]
    if len(groups) != 1:
        return None
    retention = groups[0].get("retentionInDays")
    return retention if isinstance(retention, int) else None


def _bucket_retention(s3, bucket: str, prefix: str) -> int | None:
    """Shortest enabled expiration that applies to every object under prefix."""
    try:
        rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules", [])
    except Exception:
        return None
    days = []
    for rule in rules:
        if rule.get("Status") != "Enabled":
            continue
        rule_prefix = (rule.get("Filter") or {}).get("Prefix", rule.get("Prefix", ""))
        if "Filter" in rule and set(rule["Filter"]) - {"Prefix"}:
            continue  # tag or size filters do not cover every object
        if not prefix.startswith(rule_prefix or ""):
            continue
        expiration = (rule.get("Expiration") or {}).get("Days")
        if isinstance(expiration, int) and expiration > 0:
            days.append(expiration)
    return min(days) if days else None


def bedrock_settings(bedrock, logs, s3) -> dict[str, Any]:
    config = bedrock.get_model_invocation_logging_configuration().get("loggingConfig")
    if not config:
        return {
            "schema_version": 1,
            "enabled": False,
            "includes_prompt_content": False,
            "retention_days": None,
        }
    destinations = []
    if (config.get("cloudWatchConfig") or {}).get("logGroupName"):
        destinations.append(("logs", config["cloudWatchConfig"]["logGroupName"], ""))
        large = (config["cloudWatchConfig"].get("largeDataDeliveryS3Config") or {}).get("bucketName")
        if large:
            destinations.append(
                ("s3", large, config["cloudWatchConfig"]["largeDataDeliveryS3Config"].get("keyPrefix", ""))
            )
    if (config.get("s3Config") or {}).get("bucketName"):
        destinations.append(("s3", config["s3Config"]["bucketName"], config["s3Config"].get("keyPrefix", "")))
    includes_text = config.get("textDataDeliveryEnabled") is True
    retentions = [
        _log_group_retention(logs, name) if kind == "logs" else _bucket_retention(s3, name, prefix)
        for kind, name, prefix in destinations
    ]
    retention = None if not retentions or None in retentions else max(retentions)
    return {
        "schema_version": 1,
        "enabled": bool(destinations),
        "includes_prompt_content": includes_text and bool(destinations),
        "retention_days": retention,
    }


def external_settings(provider: str) -> dict[str, Any]:
    if provider != "bedrock":
        raise LoggingCaptureError("only --provider bedrock can be captured automatically")
    return {
        "schema_version": 1,
        "provider": NO_EXTERNAL_PROVIDER,
        "enabled": False,
        "includes_prompt_content": False,
        "retention_days": None,
    }


def acceptable(settings: dict[str, Any]) -> bool:
    if not settings["includes_prompt_content"]:
        return True
    retention = settings["retention_days"]
    return settings["enabled"] and retention is not None and retention <= MAX_PROMPT_RETENTION_DAYS


def write_json(path: Path, value: dict[str, Any]) -> str:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def capture(bedrock, logs, s3, provider: str) -> int:
    bedrock_doc = bedrock_settings(bedrock, logs, s3)
    external_doc = external_settings(provider)
    print("Bedrock model invocation logging:")
    print(f"  enabled                 {bedrock_doc['enabled']}")
    print(f"  includes prompt content {bedrock_doc['includes_prompt_content']}")
    print(f"  retention days          {bedrock_doc['retention_days']}")
    print(f"External provider: {external_doc['provider']}")
    if not acceptable(bedrock_doc):
        print(
            f"\nBedrock stores prompt text without a retention of at most {MAX_PROMPT_RETENTION_DAYS} days; "
            "nothing was written. Set a retention or turn off text delivery, then capture again."
        )
        return 1
    bedrock_sha = write_json(EVIDENCE / "bedrock-logging-settings.json", bedrock_doc)
    external_sha = write_json(EVIDENCE / "external-provider-logging-settings.json", external_doc)
    print(f"\nWrote stage3/bedrock-logging-settings.json            sha256 {bedrock_sha}")
    print(f"Wrote stage3/external-provider-logging-settings.json  sha256 {external_sha}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--provider", required=True, choices=["bedrock"])
    args = parser.parse_args(argv)

    import boto3

    session = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    try:
        return capture(session.client("bedrock"), session.client("logs"), session.client("s3"), args.provider)
    except LoggingCaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
