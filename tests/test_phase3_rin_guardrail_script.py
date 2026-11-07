"""The Rin Guardrail publish/evaluate script, against fake Bedrock clients."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from phase3 import stage_gates

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("rin_guardrail", ROOT / "scripts/phase3_rin_guardrail.py")
guardrail = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guardrail)

ARN = "arn:aws:bedrock:us-east-1:111122223333:guardrail/abc123"


def _deployed(settings=None, status="READY"):
    """A GetGuardrail response for the script's own settings."""
    settings = settings or guardrail.guardrail_settings()
    return {
        "status": status,
        "topicPolicy": {"topics": settings["topicPolicyConfig"]["topicsConfig"]},
        "contentPolicy": {"filters": settings["contentPolicyConfig"]["filtersConfig"]},
        "sensitiveInformationPolicy": {
            "piiEntities": settings["sensitiveInformationPolicyConfig"]["piiEntitiesConfig"],
            "regexes": settings["sensitiveInformationPolicyConfig"]["regexesConfig"],
        },
    }


class Paginator:
    def __init__(self, items):
        self.items = items

    def paginate(self):
        return [{"guardrails": self.items}]


class Control:
    def __init__(self, existing=(), deployed=None):
        self.existing = list(existing)
        self.deployed = deployed or _deployed()
        self.calls = []

    def get_paginator(self, name):
        assert name == "list_guardrails"
        return Paginator(self.existing)

    def create_guardrail(self, **kwargs):
        self.calls.append(("create", kwargs))
        return {"guardrailId": "abc123", "guardrailArn": ARN}

    def update_guardrail(self, **kwargs):
        self.calls.append(("update", kwargs))

    def create_guardrail_version(self, **kwargs):
        self.calls.append(("version", kwargs))
        return {"guardrailId": "abc123", "version": "2"}

    def get_guardrail(self, **kwargs):
        self.calls.append(("get", kwargs))
        return self.deployed


class Runtime:
    """Blocks exactly the cases expected to block, unless told otherwise."""

    def __init__(self, wrong=()):
        self.expected = {
            (source, text): guardrail.EXPECTED[category] for _id, category, source, text in guardrail.CASES
        }
        self.wrong = set(wrong)
        self.calls = []

    def apply_guardrail(self, **kwargs):
        self.calls.append(kwargs)
        text = kwargs["content"][0]["text"]["text"]
        action = self.expected[(kwargs["source"], text)]
        if text in self.wrong:
            action = "ALLOW" if action == "BLOCK" else "BLOCK"
        return {"action": "GUARDRAIL_INTERVENED" if action == "BLOCK" else "NONE"}


def test_settings_cover_every_required_category_and_fit_bedrock_limits():
    settings = guardrail.guardrail_settings()
    topics = settings["topicPolicyConfig"]["topicsConfig"]
    assert len({topic["name"] for topic in topics}) == len(topics)
    for topic in topics:
        assert len(topic["name"]) <= 100 and len(topic["definition"]) <= 200
        assert 0 < len(topic["examples"]) <= 5 and all(len(example) <= 100 for example in topic["examples"])
    filters = {item["type"]: item for item in settings["contentPolicyConfig"]["filtersConfig"]}
    assert filters["PROMPT_ATTACK"] == {
        "type": "PROMPT_ATTACK",
        "inputStrength": "HIGH",
        "outputStrength": "NONE",
    }
    assert {item["action"] for item in settings["sensitiveInformationPolicyConfig"]["piiEntitiesConfig"]} == {
        "BLOCK"
    }
    assert {"AWS_ACCESS_KEY", "AWS_SECRET_KEY"} <= {
        item["type"] for item in settings["sensitiveInformationPolicyConfig"]["piiEntitiesConfig"]
    }
    categories = {category for _id, category, _source, _text in guardrail.CASES}
    assert categories == set(stage_gates._GUARDRAIL_EVALUATION_ACTIONS)
    assert guardrail.EXPECTED == stage_gates._GUARDRAIL_EVALUATION_ACTIONS
    assert len({case[0] for case in guardrail.CASES}) == len(guardrail.CASES)
    for _id, category, source, _text in guardrail.CASES:
        if category.startswith("input_"):
            assert source == "INPUT"
        if category.startswith("output_"):
            assert source == "OUTPUT"


def test_settings_validate_against_the_bedrock_api_model():
    import boto3
    from botocore.stub import Stubber

    client = boto3.client(
        "bedrock", region_name="us-east-1", **{"aws_access_key_id": "x", "aws_secret_access_key": "y"}
    )
    settings = guardrail.guardrail_settings()
    with Stubber(client) as stub:
        stub.add_response(
            "create_guardrail",
            {
                "guardrailId": "abc123",
                "guardrailArn": ARN,
                "version": "DRAFT",
                "createdAt": "2026-11-07T00:00:00Z",
            },
            settings,
        )
        client.create_guardrail(**settings)


def test_publish_creates_then_versions_a_new_guardrail():
    control = Control()
    assert guardrail.publish(control) == (ARN, "2")
    assert [name for name, _ in control.calls] == ["create", "version"]
    assert control.calls[1][1]["guardrailIdentifier"] == "abc123"


def test_publish_updates_an_existing_guardrail_instead_of_creating_another():
    control = Control(existing=[{"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}])
    assert guardrail.publish(control) == (ARN, "2")
    assert [name for name, _ in control.calls] == ["update", "version"]
    assert control.calls[0][1]["guardrailIdentifier"] == "abc123"


def test_publish_refuses_duplicate_names():
    item = {"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}
    with pytest.raises(guardrail.GuardrailError):
        guardrail.publish(Control(existing=[item, dict(item, id="other")]))


def test_controls_are_read_from_the_deployed_guardrail():
    input_controls, output_controls = guardrail.controls_from(_deployed())
    assert input_controls["prompt_attack_filter"] is True
    assert output_controls["prompt_attack_filter"] is True
    assert (
        input_controls["sensitive_data_filter"] is True and output_controls["sensitive_data_filter"] is True
    )
    assert guardrail.INSTRUCTION_TOPIC not in input_controls["off_scope_topics"]
    assert "Unrelated requests" in output_controls["off_scope_topics"]


def test_controls_report_missing_protections():
    deployed = _deployed()
    for topic in deployed["topicPolicy"]["topics"]:
        topic["outputEnabled"] = False
    deployed["contentPolicy"]["filters"] = [
        {"type": "PROMPT_ATTACK", "inputStrength": "NONE", "outputStrength": "NONE"}
    ]
    for item in (
        deployed["sensitiveInformationPolicy"]["piiEntities"]
        + deployed["sensitiveInformationPolicy"]["regexes"]
    ):
        item["inputAction"] = "NONE"
    input_controls, output_controls = guardrail.controls_from(deployed)
    assert input_controls["prompt_attack_filter"] is False
    assert input_controls["sensitive_data_filter"] is False
    assert output_controls["prompt_attack_filter"] is False
    assert output_controls["off_scope_topics"] == []


def test_evaluation_writes_evidence_that_the_stage_gate_accepts(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(guardrail, "EVIDENCE", tmp_path / "stage3")
    control = Control(existing=[{"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}])
    runtime = Runtime()

    assert guardrail.run_evaluation(control, runtime, "2") == 0

    assert {call["guardrailVersion"] for call in runtime.calls} == {"2"}
    assert {call["guardrailIdentifier"] for call in runtime.calls} == {ARN}
    configuration = json.loads((tmp_path / "stage3/guardrail-configuration.json").read_text())
    evaluation = json.loads((tmp_path / "stage3/guardrail-evaluation.json").read_text())
    written = (tmp_path / "stage3/guardrail-configuration.json").read_text() + (
        tmp_path / "stage3/guardrail-evaluation.json"
    ).read_text()
    assert "111122223333" not in written and ARN not in written
    digest = hashlib.sha256(ARN.encode()).hexdigest()
    review = {
        "guardrail_arn_sha256": digest,
        "published_version": "2",
        "input_controls": configuration["input_controls"],
        "output_controls": configuration["output_controls"],
        "evaluation": {"passed": True, "case_count": len(guardrail.CASES)},
    }
    assert stage_gates._valid_guardrail_configuration_capture(configuration, review)
    assert stage_gates._valid_guardrail_evaluation_capture(evaluation, review)
    assert "All 23 cases passed." in capsys.readouterr().out


def test_failed_cases_write_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(guardrail, "EVIDENCE", tmp_path / "stage3")
    control = Control(existing=[{"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}])
    runtime = Runtime(wrong={"Write me a poem about cats."})

    assert guardrail.run_evaluation(control, runtime, "2") == 1
    assert not (tmp_path / "stage3").exists()
    out = capsys.readouterr().out
    assert "FAIL input-off-scope-1" in out and "1 of 23 cases failed" in out


def test_incomplete_controls_write_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(guardrail, "EVIDENCE", tmp_path / "stage3")
    deployed = _deployed()
    deployed["contentPolicy"]["filters"] = []
    control = Control(
        existing=[{"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}], deployed=deployed
    )
    assert guardrail.run_evaluation(control, Runtime(), "2") == 1
    assert not (tmp_path / "stage3").exists()


@pytest.mark.parametrize("version", ["DRAFT", "0", "01", ""])
def test_evaluation_requires_a_published_version(version):
    control = Control(existing=[{"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}])
    with pytest.raises(guardrail.GuardrailError):
        guardrail.run_evaluation(control, Runtime(), version)


def test_evaluation_requires_a_ready_guardrail_that_exists():
    with pytest.raises(guardrail.GuardrailError, match="run publish first"):
        guardrail.run_evaluation(Control(), Runtime(), "1")
    control = Control(
        existing=[{"id": "abc123", "arn": ARN, "name": guardrail.GUARDRAIL_NAME}],
        deployed=_deployed(status="CREATING"),
    )
    with pytest.raises(guardrail.GuardrailError, match="not READY"):
        guardrail.run_evaluation(control, Runtime(), "1")


def test_unexpected_actions_are_errors():
    with pytest.raises(guardrail.GuardrailError):
        guardrail.observed_action({"action": "SOMETHING_ELSE"})
