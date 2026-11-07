"""Rin's Bedrock provider: structured output, fail-closed parsing, and exact IAM."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

import phase3.rin_service as rin_service
from auditor.ai_analyst import AIAnalystError
from tests.test_phase3_rin import Store, _event, _provider_result, _rin_response, _snapshot

ROOT = Path(__file__).resolve().parents[1]
MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
NOW = datetime(2026, 11, 3, 11, 5, tzinfo=UTC)


class Converse:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


def _tool_response(output, *, stop="tool_use", name="security_analysis"):
    return {
        "stopReason": stop,
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"toolUse": {"toolUseId": "t1", "name": name, "input": output}}],
            }
        },
    }


def _request():
    return {
        "model": MODEL,
        "instructions": "rules",
        "input": '{"findings":[]}',
        "max_output_tokens": 600,
    }


def test_converse_forces_one_schema_tool_with_null_proposals_and_returns_its_input():
    output = _provider_result("a111111111111111")
    client = Converse(_tool_response(output))

    assert rin_service._bedrock_converse(client, _request()) == output
    call = client.calls[0]
    assert call["modelId"] == MODEL
    assert call["system"] == [{"text": "rules"}]
    assert call["messages"] == [{"role": "user", "content": [{"text": '{"findings":[]}'}]}]
    assert call["inferenceConfig"] == {"maxTokens": 600, "temperature": 0}
    assert call["toolConfig"]["toolChoice"] == {"tool": {"name": "security_analysis"}}
    schema = call["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]
    assert schema["properties"]["analyses"]["items"]["properties"]["proposal"] == {"type": "null"}
    # The shared analyst schema is not mutated.
    assert rin_service.OUTPUT_SCHEMA["properties"]["analyses"]["items"]["properties"]["proposal"] != {
        "type": "null"
    }


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (_tool_response({}, stop="max_tokens"), "ProviderIncomplete"),
        (_tool_response({}, stop="end_turn"), "ProviderIncomplete"),
        (_tool_response({}, stop="guardrail_intervened"), "ProviderRefusal"),
        (_tool_response({}, stop="content_filtered"), "ProviderRefusal"),
        (_tool_response({}, name="other_tool"), "ProviderInvalidResponse"),
        (_tool_response("not an object"), "ProviderInvalidResponse"),
        ({"stopReason": "tool_use", "output": {"message": {"content": []}}}, "ProviderInvalidResponse"),
        ({"stopReason": "tool_use", "output": "bad"}, "ProviderInvalidResponse"),
        (
            {
                "stopReason": "tool_use",
                "output": {
                    "message": {
                        "content": [
                            {"toolUse": {"name": "security_analysis", "input": {}}},
                            {"toolUse": {"name": "security_analysis", "input": {}}},
                        ]
                    }
                },
            },
            "ProviderInvalidResponse",
        ),
        (_tool_response({"x": "y" * (65 * 1024)}), "ProviderResponseTooLarge"),
        (_tool_response({"x": float("nan")}), "InvalidOutputSchema"),
        ("not a dict", "ProviderInvalidResponse"),
    ],
)
def test_converse_rejects_unusable_responses(response, code):
    with pytest.raises(AIAnalystError) as caught:
        rin_service._bedrock_converse(Converse(response), _request())
    assert caught.value.code == code


def test_converse_maps_service_errors_and_unapproved_models_to_provider_unavailable():
    with pytest.raises(AIAnalystError) as caught:
        rin_service._bedrock_converse(Converse(error=RuntimeError("AccessDenied")), _request())
    assert caught.value.code == "ProviderUnavailable"
    for model in (
        "anthropic.claude-haiku-4-5-20251001-v1:0",
        "global.anthropic.claude-haiku-4-5",
        "us.meta.llama3",
    ):
        client = Converse(_tool_response({}))
        with pytest.raises(AIAnalystError) as caught:
            rin_service._bedrock_converse(client, {**_request(), "model": model})
        assert caught.value.code == "ProviderUnavailable"
        assert client.calls == []


def test_bedrock_rin_answers_without_a_provider_secret_and_keeps_every_check():
    snapshot = _snapshot()
    finding_id = snapshot["findings"][0]["id"]
    client = Converse()

    def provider(request, api_key):
        assert api_key is None
        fingerprint = json.loads(request["input"])["findings"][0]["fingerprint"]
        client.response = _tool_response(_provider_result(fingerprint))
        return rin_service._bedrock_converse(client, request)

    sources = []
    response = _rin_response(
        _event("Why is this risky?", finding_id),
        store=Store(snapshot),
        enabled=True,
        model=MODEL,
        api_key=lambda: pytest.fail("Bedrock must not read the external provider secret"),
        max_output_tokens=600,
        quota_consumer=lambda _identity: {"allowed": True, "reason": "OK"},
        provider=provider,
        guardrail=lambda *, source, text: sources.append(source) or {"action": "NONE"},
        requires_api_key=False,
        now=NOW,
    )

    body = json.loads(response["body"])
    assert body["status"] == "COMPLETE"
    assert sources == ["INPUT", "OUTPUT"]
    assert "123456789012" not in client.calls[0]["messages"][0]["content"][0]["text"]


def test_bedrock_rin_without_a_provider_falls_back():
    snapshot = _snapshot()
    response = _rin_response(
        _event("Why?", snapshot["findings"][0]["id"]),
        store=Store(snapshot),
        enabled=True,
        model=MODEL,
        api_key=None,
        max_output_tokens=600,
        quota_consumer=lambda _identity: {"allowed": True, "reason": "OK"},
        provider=None,
        requires_api_key=False,
        now=NOW,
    )
    assert json.loads(response["body"])["reason_code"] == "PROVIDER_NOT_CONFIGURED"


def test_bedrock_rin_rejects_a_leaking_model_answer():
    snapshot = _snapshot()

    def provider(request, api_key):
        del api_key
        result = _provider_result(json.loads(request["input"])["findings"][0]["fingerprint"])
        result["analyses"][0]["explanation"] = "The account is 123456789012."
        return result

    response = _rin_response(
        _event("Which account?", snapshot["findings"][0]["id"]),
        store=Store(snapshot),
        enabled=True,
        model=MODEL,
        api_key=None,
        max_output_tokens=600,
        quota_consumer=lambda _identity: {"allowed": True, "reason": "OK"},
        provider=provider,
        requires_api_key=False,
        now=NOW,
    )
    body = json.loads(response["body"])
    assert body["status"] == "REJECTED"
    assert "123456789012" not in response["body"]


def test_bedrock_model_policy_is_exact_and_conditional():
    policy = json.loads((ROOT / "infra/phase3/policies/rin-bedrock-model.json").read_text(encoding="utf-8"))
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")
    variables = (ROOT / "infra/phase3/control-plane/variables.tf").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    actions = {s["Action"] for s in policy["Statement"]}
    assert actions == {"bedrock:InvokeModel"}
    profile, model = policy["Statement"]
    assert profile["Resource"] == "${inference_profile_arn}"
    assert model["Resource"] == "arn:aws:bedrock:us-*::foundation-model/${foundation_model_id}"
    assert model["Condition"] == {"StringEquals": {"bedrock:InferenceProfileArn": "${inference_profile_arn}"}}
    assert "*" not in profile["Resource"]
    assert re.search(
        r'count\s*=\s*var\.enable_stage3\s*&&\s*var\.rin_enabled\s*&&\s*var\.rin_provider\s*==\s*"bedrock"',
        stage3,
    )
    assert "inference-profile/${var.rin_model}" in stage3
    assert 'trimprefix(var.rin_model, "us.")' in stage3
    assert "PHASE3_RIN_PROVIDER" in stage3
    assert 'contains(["openai", "bedrock"], var.rin_provider)' in variables
    assert "TF_VAR_rin_provider" in workflow


def test_bedrock_model_regex_matches_terraform_validation():
    variables = (ROOT / "infra/phase3/control-plane/variables.tf").read_text(encoding="utf-8")
    hcl = re.search(r'can\(regex\("(\^us[^"]+)", var\.rin_model\)\)', variables).group(1)
    terraform_pattern = re.compile(hcl.replace("\\\\", "\\"))
    for model in (MODEL, "us.amazon.nova-lite-v1:0", "us.anthropic.claude-haiku-5-5"):
        assert terraform_pattern.fullmatch(model)
        assert rin_service._BEDROCK_MODEL.fullmatch(model)
    for model in (
        "global.anthropic.claude-haiku-5-5",
        "anthropic.claude-haiku-5-5",
        "us.meta.llama3",
        "us.anthropic.*",
    ):
        assert not terraform_pattern.fullmatch(model)
        assert not rin_service._BEDROCK_MODEL.fullmatch(model)


def test_workload_boundary_caps_model_invocation_to_us_profiles():
    boundary = json.loads(
        (ROOT / "infra/phase3/policies/control-plane-workload-boundary.json").read_text(encoding="utf-8")
    )
    statement = next(s for s in boundary["Statement"] if s.get("Sid") == "InvokeOnlyUsInferenceProfileModels")
    assert statement["Action"] == "bedrock:InvokeModel"
    assert statement["Resource"] == [
        "arn:aws:bedrock:${region}:${account_id}:inference-profile/us.*",
        "arn:aws:bedrock:us-*::foundation-model/*",
    ]


def test_bedrock_schema_restricts_fingerprint_and_citations_to_the_supplied_finding():
    request_input = json.dumps(
        {
            "findings": [
                {
                    "fingerprint": "a111111111111111",
                    "citation_catalog": {"REMEDIATION": "x", "DESCRIPTION": "y"},
                }
            ]
        }
    )
    schema = rin_service._rin_output_schema(request_input)
    item = schema["properties"]["analyses"]["items"]["properties"]
    assert item["fingerprint"] == {"type": "string", "enum": ["a111111111111111"]}
    assert item["citations"]["items"] == {"type": "string", "enum": ["DESCRIPTION", "REMEDIATION"]}
    assert item["citations"]["minItems"] == 1 and item["citations"]["uniqueItems"] is True
    assert schema["properties"]["analyses"]["maxItems"] == 1
    assert schema["properties"]["schema_version"]["enum"] == ["1.0.0"]
    client = Converse(_tool_response(_provider_result("a111111111111111")))
    rin_service._bedrock_converse(client, {**_request(), "input": request_input})
    sent = client.calls[0]["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]
    assert sent["properties"]["analyses"]["items"]["properties"]["citations"]["items"]["enum"] == [
        "DESCRIPTION",
        "REMEDIATION",
    ]


@pytest.mark.parametrize(
    "request_input", ["not json", "{}", '{"findings": []}', '{"findings": [{"fingerprint": 1}]}']
)
def test_bedrock_schema_falls_back_to_the_generic_schema_for_unexpected_input(request_input):
    item = rin_service._rin_output_schema(request_input)["properties"]["analyses"]["items"]["properties"]
    assert item["fingerprint"] == {"type": "string"}
    assert item["proposal"] == {"type": "null"}
