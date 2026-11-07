"""The Stage 3 logging capture script, against fake AWS clients."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from phase3 import stage_gates

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "logging_capture", ROOT / "scripts/phase3_rin_logging_capture.py"
)
capture = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(capture)


class Bedrock:
    def __init__(self, config):
        self.config = config

    def get_model_invocation_logging_configuration(self):
        return {"loggingConfig": self.config} if self.config is not None else {}


class Paginator:
    def __init__(self, groups):
        self.groups = groups

    def paginate(self, **kwargs):
        return [
            {
                "logGroups": [
                    g for g in self.groups if g["logGroupName"].startswith(kwargs["logGroupNamePrefix"])
                ]
            }
        ]


class Logs:
    def __init__(self, groups=()):
        self.groups = list(groups)

    def get_paginator(self, name):
        assert name == "describe_log_groups"
        return Paginator(self.groups)


class S3:
    def __init__(self, rules=None, error=False):
        self.rules = rules or []
        self.error = error

    def get_bucket_lifecycle_configuration(self, Bucket):
        if self.error:
            raise RuntimeError("NoSuchLifecycleConfiguration")
        return {"Rules": self.rules}


def test_disabled_logging_is_recorded_and_accepted(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(capture, "EVIDENCE", tmp_path)
    assert capture.capture(Bedrock(None), Logs(), S3(), "bedrock") == 0

    bedrock = json.loads((tmp_path / "bedrock-logging-settings.json").read_text())
    external = json.loads((tmp_path / "external-provider-logging-settings.json").read_text())
    assert bedrock == {
        "schema_version": 1,
        "enabled": False,
        "includes_prompt_content": False,
        "retention_days": None,
    }
    assert external["provider"] == capture.NO_EXTERNAL_PROVIDER and external["enabled"] is False
    review_bedrock = {k: bedrock[k] for k in ("enabled", "includes_prompt_content", "retention_days")}
    review_external = dict(review_bedrock, provider=external["provider"])
    assert stage_gates._valid_logging_capture(bedrock, review_bedrock, require_provider=False)
    assert stage_gates._valid_logging_capture(external, review_external, require_provider=True)
    assert "Wrote stage3/bedrock-logging-settings.json" in capsys.readouterr().out


def test_cloudwatch_prompt_logging_with_short_retention_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "EVIDENCE", tmp_path)
    config = {"cloudWatchConfig": {"logGroupName": "bedrock"}, "textDataDeliveryEnabled": True}
    logs = Logs([{"logGroupName": "bedrock", "retentionInDays": 14}, {"logGroupName": "bedrock-other"}])
    assert capture.capture(Bedrock(config), logs, S3(), "bedrock") == 0
    written = json.loads((tmp_path / "bedrock-logging-settings.json").read_text())
    assert written == {
        "schema_version": 1,
        "enabled": True,
        "includes_prompt_content": True,
        "retention_days": 14,
    }


@pytest.mark.parametrize(
    ("config", "logs", "s3"),
    [
        ({"cloudWatchConfig": {"logGroupName": "bedrock"}, "textDataDeliveryEnabled": True}, Logs([{"logGroupName": "bedrock"}]), S3()),
        ({"cloudWatchConfig": {"logGroupName": "bedrock"}, "textDataDeliveryEnabled": True}, Logs([{"logGroupName": "bedrock", "retentionInDays": 90}]), S3()),
        ({"cloudWatchConfig": {"logGroupName": "missing"}, "textDataDeliveryEnabled": True}, Logs(), S3()),
        ({"s3Config": {"bucketName": "b", "keyPrefix": "logs/"}, "textDataDeliveryEnabled": True}, Logs(), S3(error=True)),
        ({"s3Config": {"bucketName": "b"}, "textDataDeliveryEnabled": True}, Logs(), S3([{"Status": "Disabled", "Filter": {}, "Expiration": {"Days": 7}}])),
        ({"s3Config": {"bucketName": "b"}, "textDataDeliveryEnabled": True}, Logs(), S3([{"Status": "Enabled", "Filter": {"Tag": {"Key": "a", "Value": "b"}}, "Expiration": {"Days": 7}}])),
        ({"s3Config": {"bucketName": "b", "keyPrefix": "x/"}, "textDataDeliveryEnabled": True}, Logs(), S3([{"Status": "Enabled", "Filter": {"Prefix": "y/"}, "Expiration": {"Days": 7}}])),
    ],
)  # fmt: skip
def test_prompt_logging_without_a_known_short_retention_writes_nothing(
    tmp_path, monkeypatch, config, logs, s3
):
    monkeypatch.setattr(capture, "EVIDENCE", tmp_path / "stage3")
    assert capture.capture(Bedrock(config), logs, s3, "bedrock") == 1
    assert not (tmp_path / "stage3").exists()


def test_s3_lifecycle_and_large_payload_bucket_count_toward_retention(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "EVIDENCE", tmp_path)
    config = {
        "cloudWatchConfig": {
            "logGroupName": "bedrock",
            "largeDataDeliveryS3Config": {"bucketName": "large", "keyPrefix": "big/"},
        },
        "s3Config": {"bucketName": "b", "keyPrefix": "logs/"},
        "textDataDeliveryEnabled": True,
    }
    rules = [
        {"Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 20}},
        {"Status": "Enabled", "Filter": {"Prefix": "logs/"}, "Expiration": {"Days": 10}},
    ]
    logs = Logs([{"logGroupName": "bedrock", "retentionInDays": 7}])
    assert capture.capture(Bedrock(config), logs, S3(rules), "bedrock") == 0
    written = json.loads((tmp_path / "bedrock-logging-settings.json").read_text())
    assert written["retention_days"] == 20  # the longest destination decides


def test_metadata_only_logging_is_not_prompt_content(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "EVIDENCE", tmp_path)
    config = {"cloudWatchConfig": {"logGroupName": "bedrock"}, "textDataDeliveryEnabled": False}
    assert capture.capture(Bedrock(config), Logs([{"logGroupName": "bedrock"}]), S3(), "bedrock") == 0
    written = json.loads((tmp_path / "bedrock-logging-settings.json").read_text())
    assert written == {
        "schema_version": 1,
        "enabled": True,
        "includes_prompt_content": False,
        "retention_days": None,
    }


def test_only_the_bedrock_provider_is_captured_automatically():
    with pytest.raises(capture.LoggingCaptureError):
        capture.external_settings("openai")
