#!/usr/bin/env python3
"""Synchronize README, Phase 3 status docs, and console knowledge from the canonical manifest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import quote

STAGES = ("stage1", "stage2", "stage3", "stage4")
STAGE_TITLES = {
    "stage1": "Demo account and scans",
    "stage2": "Redaction, publication, and API",
    "stage3": "Website and Rin",
    "stage4": "Load, cost controls, and operational resilience",
}
STATUS_FIELDS = {"status", "verification_scope", "summary", "verification_evidence"}
ALLOWED = {
    "stage1": {("passed", "offline_fixtures_and_moto"), ("passed", "private_aws_verification")},
    "stage2": {("passed", "offline_fixtures_and_moto"), ("passed", "private_aws_verification")},
    "stage3": {("unverified", "pending_external_confirmation"), ("passed", "private_aws_verification")},
    "stage4": {("pending", "load_and_operational_resilience"), ("passed", "private_aws_verification")},
}


def _load_manifest(root: Path) -> dict:
    path = root / "docs/evidence/phase3-stage-acceptance.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 4
        or set(value) != {"schema_version", "canonical_status", "deployment_gates"}
    ):
        raise ValueError("canonical Phase 3 status manifest has an unsupported schema")
    status = value["canonical_status"]
    if not isinstance(status, dict) or set(status) != set(STAGES):
        raise ValueError("canonical Phase 3 status must define stages 1–4")
    for stage in STAGES:
        record = status[stage]
        if not isinstance(record, dict) or set(record) != STATUS_FIELDS:
            raise ValueError(f"{stage} canonical status has an invalid shape")
        if (record["status"], record["verification_scope"]) not in ALLOWED[stage]:
            raise ValueError(f"{stage} canonical status or verification scope is invalid")
        if not isinstance(record["summary"], str) or not record["summary"].strip():
            raise ValueError(f"{stage} canonical summary is missing")
        evidence = record["verification_evidence"]
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            raise ValueError(f"{stage} verification evidence must be a string list")
        if record["status"] == "passed" and not evidence:
            raise ValueError(f"passed {stage} requires verification evidence")
        if record["status"] != "passed" and evidence:
            raise ValueError(f"pending {stage} cannot claim verification evidence")
    if not isinstance(value["deployment_gates"], dict) or set(value["deployment_gates"]) != set(STAGES):
        raise ValueError("deployment gate records must define stages 1–4")
    for stage in STAGES:
        gate = value["deployment_gates"][stage]
        if not isinstance(gate, dict) or gate.get("status") not in {"pending", "passed"}:
            raise ValueError(f"{stage} deployment gate status is invalid")
        private_pass = (
            status[stage]["status"] == "passed"
            and status[stage]["verification_scope"] == "private_aws_verification"
        )
        if (gate["status"] == "passed") != private_pass:
            raise ValueError(f"{stage} canonical status conflicts with its deployment gate")
        index = STAGES.index(stage)
        if private_pass and any(
            not (
                status[previous]["status"] == "passed"
                and status[previous]["verification_scope"] == "private_aws_verification"
            )
            for previous in STAGES[:index]
        ):
            raise ValueError(f"{stage} cannot pass before private verification of its predecessors")
    return value


def _label(stage: str, record: dict) -> str:
    status, scope = record["status"], record["verification_scope"]
    if status == "passed" and scope == "offline_fixtures_and_moto":
        return "PASSED (Offline Fixtures & Moto Benchmarks)"
    if status == "passed" and scope == "private_aws_verification":
        return "PASSED (Private AWS Verification)"
    if status == "unverified":
        return "UNVERIFIED / PENDING EXTERNAL CONFIRMATION"
    if stage == "stage4":
        return "PENDING (Load & Operational Resilience Benchmarks)"
    return "PENDING"


def _status_data(manifest: dict) -> dict:
    records = manifest["canonical_status"]
    stages = {stage: {**records[stage], "label": _label(stage, records[stage])} for stage in STAGES}
    summary = "; ".join(
        f"Stage {index}: {stages[stage]['label']}" for index, stage in enumerate(STAGES, start=1)
    )
    return {
        "privateAwsStage3Verified": (
            stages["stage3"]["status"] == "passed"
            and stages["stage3"]["verification_scope"] == "private_aws_verification"
        ),
        "stages": stages,
        "summary": summary,
    }


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _write_if_changed(root: Path, relative: str, content: str) -> bool:
    path = root / relative
    current = path.read_text(encoding="utf-8")
    if current == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def _replace_marked_block(text: str, begin: str, end: str, body: str, *, anchor: str | None = None) -> str:
    block = f"{begin}\n{body.rstrip()}\n{end}"
    if begin in text:
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        return pattern.sub(lambda _match: block, text, count=1)
    if anchor is None or anchor not in text:
        raise ValueError(f"cannot place generated block: {begin}")
    index = text.index(anchor) + len(anchor)
    return text[:index] + "\n" + block + text[index:]


def _render_badge(data: dict) -> str:
    badge_color = "brightgreen" if data["privateAwsStage3Verified"] else "yellow"
    alt = data["stages"]["stage3"]["label"]
    badge_label = quote(alt, safe="")
    return f"![Phase 3 status: {alt}](https://img.shields.io/badge/Phase%203-{badge_label}-{badge_color})"


def _render_readme_status(data: dict) -> str:
    rows = []
    for index, stage in enumerate(STAGES, start=1):
        record = data["stages"][stage]
        rows.append(f"| {index} | {STAGE_TITLES[stage]} | {record['label']} | {record['summary']} |")
    verified = data["privateAwsStage3Verified"]
    deployment_note = (
        "The manifest records private AWS verification for Stage 3."
        if verified
        else (
            "No private AWS verification is recorded for Stage 3. "
            "Offline passes for Stages 1–2 do not establish that AWS resources were deployed."
        )
    )
    return f"""<!-- BEGIN GENERATED PHASE 3 STATUS -->
## Phase 3 deployment status

The stage summaries below are generated from the
[canonical status manifest](docs/evidence/phase3-stage-acceptance.json).

| Stage | Scope | Canonical status | Verification note |
| --- | --- | --- | --- |
{chr(10).join(rows)}

{deployment_note} The public GitHub Pages site remains a static Moto/fixture
replay and does not connect to AWS or an AI provider. Terraform deployment
acceptance is tracked separately in the same manifest and requires private
AWS evidence.

<!-- END GENERATED PHASE 3 STATUS -->"""


def _update_readme(root: Path, data: dict) -> str:
    readme = _read(root, "README.md")
    badge_begin, badge_end = (
        "<!-- BEGIN GENERATED PHASE 3 BADGE -->",
        "<!-- END GENERATED PHASE 3 BADGE -->",
    )
    badge_body = _render_badge(data)
    if badge_begin in readme:
        readme = _replace_marked_block(readme, badge_begin, badge_end, badge_body)
    else:
        anchor_match = re.search(r"(?m)^\[!\[IaC guardrails\].*$", readme)
        if not anchor_match:
            raise ValueError("README.md has no IaC badge insertion point")
        end = anchor_match.end()
        badge = f"\n{badge_begin}\n{badge_body}\n{badge_end}"
        readme = readme[:end] + badge + readme[end:]

    section = _render_readme_status(data)
    marked = re.compile(
        r"(?ms)<!-- BEGIN GENERATED PHASE 3 STATUS -->.*?"
        r"<!-- END GENERATED PHASE 3 STATUS -->[ \t]*(?:\r?\n)*"
    )
    if marked.search(readme):
        readme = marked.sub(lambda _match: section + "\n\n", readme, count=1)
    else:
        pattern = re.compile(r"(?ms)^## Live deployment status\n.*?(?=^## Security and scope\n)")
        if pattern.search(readme):
            readme = pattern.sub(lambda _match: section + "\n\n", readme, count=1)
        else:
            marker = "## Security and scope\n"
            if marker not in readme:
                raise ValueError("README.md has no Phase 3 status section or insertion point")
            readme = readme.replace(marker, section + "\n\n" + marker, 1)

    readme = readme.replace(
        "- The Phase 3 live deployment defaults to invite-only access: Cognito sign-in\n"
        "  with mandatory MFA and PKCE, an authorizer on every API method, and per-user\n"
        "  Rin quotas. See [private access](docs/private-access.md).",
        "- The Phase 3 deployment design defaults to invite-only access: Cognito sign-in\n"
        "  with mandatory MFA and PKCE, an authorizer on every API method, and per-user\n"
        "  Rin quotas. Live AWS access is not independently verified. See\n"
        "  [private access](docs/private-access.md).",
    )
    return readme


def _render_status_doc(manifest: dict, data: dict) -> str:
    rows = []
    for index, stage in enumerate(STAGES, start=1):
        record = data["stages"][stage]
        rows.append(f"| Stage {index} — {STAGE_TITLES[stage]} | {record['label']} | {record['summary']} |")
    gate_states = [manifest["deployment_gates"][stage]["status"] for stage in STAGES]
    if all(state == "pending" for state in gate_states):
        gate_note = (
            "Every Terraform deployment gate is pending. Offline fixture and Moto passes do not "
            "authorize a live deployment."
        )
    else:
        gate_note = (
            "Terraform deployment gates are recorded separately from repository test status. "
            "Each passed gate must bind reviewed private AWS evidence by SHA-256."
        )
    stage3 = data["stages"]["stage3"]
    stage4 = data["stages"]["stage4"]
    return f"""# Phase 3 status

The canonical source is
[docs/evidence/phase3-stage-acceptance.json](evidence/phase3-stage-acceptance.json).
This page is generated by python scripts/sync_status.py; do not edit its
status table by hand.

## Canonical stage status

| Stage | Status | Scope |
| --- | --- | --- |
{chr(10).join(rows)}

{gate_note}

## Deployment and evidence boundary

The public GitHub Pages site is a static Moto/fixture replay. It does not
connect to AWS, accept credentials, or run scans against visitors' accounts.
The repository does not independently confirm a private AWS Phase 3 deployment
or live Rin access.

{stage3["summary"]}

Artifacts under docs/evidence/stage3/ are retained as candidate review
material. They are not private AWS acceptance evidence until an external
review confirms their source and the deployment gate binds their hashes.
Offline and Moto test results remain repository verification; they do not
prove deployed control-plane configuration.

## Stage 4 work remaining

{stage4["summary"]} The Terraform design includes a $5 monthly AWS budget and
$4.50 actual/forecast notifications, but the budget cutoff, kill-switch
recovery, actual monthly cost, load test, and operational resilience remain
unrehearsed until supported by reviewed evidence.

No AWS apply or live rehearsal is recorded by this repository update. See
[the operations runbook](operations-runbook.md) and
[the bootstrap guide](phase3-bootstrap.md) before any future deployment.
"""


def _set_knowledge_text(source: str, entry_id: str, expression: str) -> str:
    start = source.index(f'id: "{entry_id}",')
    text_start = source.index("      text: ", start)
    line_end = source.index("\n", text_start)
    return source[:text_start] + "      text: " + expression + "," + source[line_end:]


def _update_knowledge(root: Path, data: dict) -> str:
    path = "scripts/console/knowledge.js"
    source = _read(root, path)
    begin, end = "// BEGIN GENERATED PHASE 3 STATUS", "// END GENERATED PHASE 3 STATUS"
    status_object = json.dumps(data, ensure_ascii=False, indent=2)
    body = f"  const PHASE3_STATUS = Object.freeze({status_object});"
    if begin in source:
        source = _replace_marked_block(source, begin, end, body)
    else:
        anchor = "  const KNOWLEDGE_VERSION = "
        index = source.index(anchor)
        block = f"{begin}\n{body}\n{end}\n\n"
        source = source[:index] + block + source[index:]

    entries = {
        "phase3-status": [
            "The public GitHub Pages site is a static Moto/fixture replay. ",
            "PHASE3_STATUS.summary",
            ". Live AWS deployment and live Rin access are not independently verified.",
        ],
        "access-control": [
            "The Phase 3 deployment design uses invite-only Cognito access with mandatory MFA, "
            "PKCE, and per-user Rin quotas. Canonical Stage 3 status: ",
            "PHASE3_STATUS.stages.stage3.label",
            "; live account access is not independently verified. The public fixture page "
            "remains available without signing in.",
        ],
        "read-only-boundary": [
            "In the Phase 3 design, the scan worker reads target AWS resources only. The public "
            "API reads sanitized scan data and its feature flag, and writes only to its own "
            "CloudWatch log group. Rin reads sanitized scan data, its feature flag, and its "
            "provider secret; Rin's role writes only to its own CloudWatch log group and invokes "
            "a separate quota function, which writes per-session and daily counters to its own "
            "DynamoDB table. The public API and Rin cannot change target AWS resources or scan "
            "results. The Phase 3 stacks remain disabled until private deployment acceptance is "
            "recorded; owner-managed organization and control-plane role policies are not "
            "independently captured here."
        ],
        "rin-privacy": [
            "Canonical Stage 3 status: ",
            "PHASE3_STATUS.stages.stage3.label",
            ". The repository does not verify live Rin enablement. The Phase 3 design can "
            "explain one redacted finding, has no target-account scanning tools, and cannot "
            "change scan results. The public GitHub Pages demo uses local fixture answers only; "
            "no model is connected to that site. In a deployed service, a Bedrock Guardrail is "
            "intended to check bounded redacted input and validate the answer before it reaches "
            "a visitor. A block, invalid response, or service error selects the fixture fallback. "
            "Guardrail errors use that fallback too.",
        ],
        "architecture-flow": [
            "The Phase 3 design uses a scanner that reads a dedicated target account through a "
            "read-only role and records private snapshots; a publisher redacts and validates "
            "snapshots before the API and website read sanitized data. Canonical status: ",
            "PHASE3_STATUS.summary",
            ". The public GitHub Pages site is a static fixture replay; private AWS deployment "
            "is not independently verified.",
        ],
        "budget-status": [
            "The recorded AWS estimate is $2.93 per month and Terraform fixes the AWS budget at "
            "$5.00. Terraform configures $4.50 actual/forecast SNS notifications to invoke a "
            "Lambda breaker intended to disable scheduled scans, stop in-flight Step Functions "
            "and Fargate scan work, disable live Rin, and select static mode. ",
            "PHASE3_STATUS.stages.stage4.label",
            ". AWS Budgets data can lag, so the breaker is best-effort rather than a hard invoice "
            "cap. No live cutoff rehearsal or actual-cost evidence is recorded. Rin's provider "
            "budget is separate.",
        ],
        "platform-overview": [
            "Vorrin is a read-only AWS cloud-security guardrails platform. Phase 2 checks AWS "
            "account posture and infrastructure policy, gates changes, and records drift. ",
            "PHASE3_STATUS.summary",
            ". The public GitHub Pages site is a static Moto/fixture replay.",
        ],
    }
    for entry_id, parts in entries.items():
        expression = " + ".join(
            part if part.startswith("PHASE3_STATUS.") else json.dumps(part, ensure_ascii=False)
            for part in parts
        )
        source = _set_knowledge_text(source, entry_id, expression)

    source = source.replace(
        "README.md · Live deployment status",
        "README.md · Phase 3 deployment status",
    )
    source = source.replace(
        "return { KNOWLEDGE_VERSION, answerPlatformQuestion };",
        "return { KNOWLEDGE_VERSION, PHASE3_STATUS, answerPlatformQuestion };",
    )
    return source


def _render_stage3_evidence(data: dict) -> str:
    stage = data["stages"]["stage3"]
    return f"""# Stage 3 candidate evidence

**Canonical status: {stage["label"]}.**

The files in this directory are retained as candidate review artifacts. They
are not independent confirmation of a private AWS deployment or live Rin
enablement. The deployment gate in
../phase3-stage-acceptance.json does not bind them as accepted evidence.

To change this status, obtain external confirmation of the deployment and
review the relevant evidence before updating the canonical manifest and
deployment gate.
"""


def sync(root: Path) -> list[str]:
    manifest = _load_manifest(root)
    data = _status_data(manifest)
    outputs = {
        "README.md": _update_readme(root, data),
        "docs/phase3-status.md": _render_status_doc(manifest, data),
        "scripts/console/knowledge.js": _update_knowledge(root, data),
        "docs/evidence/stage3/README.md": _render_stage3_evidence(data),
    }
    changed = []
    for relative, content in outputs.items():
        if _write_if_changed(root, relative, content):
            changed.append(relative)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        changed = sync(args.root.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if changed:
        print("Updated canonical Phase 3 status in: " + ", ".join(changed))
    else:
        print("Phase 3 status documents already match the canonical manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
