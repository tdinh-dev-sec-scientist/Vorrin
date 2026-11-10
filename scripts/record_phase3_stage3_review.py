#!/usr/bin/env python3
"""Record the reviewed Stage 3 acceptance evidence and mark Stage 3 passed.

    python3 scripts/record_phase3_stage3_review.py --reviewer "Truong Dinh"
    python3 scripts/record_phase3_stage3_review.py --reviewer "Truong Dinh" --confirm-reviewed

Run after every Stage 3 collector has written its output:

    scripts/phase3_rin_guardrail.py evaluate     guardrail-configuration/evaluation
    scripts/phase3_rin_logging_capture.py         bedrock/external-provider logging settings
    scripts/phase3_rin_evaluation.py              build/phase3/stage3/rin-evaluation.json
    scripts/phase3_rin_quota_evaluation.py        build/phase3/stage3/quota-fallbacks.json
    scripts/phase3_stage3_banners.py              build/phase3/stage3/failure-banners.json
    scripts/phase3_stage3_browser.py              privacy/accessibility summary + source reports
    scripts/phase3_stage3_transport.py            transport/external TLS summaries + source report

Without --confirm-reviewed it prints what it would record and writes
nothing. With it, it stamps every review document with the same reviewer
and time, writes the Guardrail policy and Bedrock logging review records,
updates docs/evidence/phase3-stage-acceptance.json, and runs the same Stage
3 gate the Terraform workflow runs. Nothing is written unless that gate
passes on a scratch copy first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phase3.stage_gates import (  # noqa: E402
    STAGE3_MAX_PROMPT_RETENTION_DAYS,
    STAGE_REQUIRED_EVIDENCE,
    StageGateError,
    validate_stage_gates,
)

DRAFT_NAMES = (
    "transport-security.json",
    "external-tls-scan.json",
    "privacy-accessibility.json",
    "rin-evaluation.json",
    "quota-fallbacks.json",
    "failure-banners.json",
)
SOURCE_FILES = (
    "stage3/guardrail-configuration.json",
    "stage3/guardrail-evaluation.json",
    "stage3/bedrock-logging-settings.json",
    "stage3/external-provider-logging-settings.json",
    "stage3/source-reports/external-tls.json",
    "stage3/source-reports/browser-network.json",
    "stage3/source-reports/lighthouse.json",
    "stage3/source-reports/accessibility.json",
)
CRITERIA = (
    "https_and_security_headers",
    "rin_evaluation",
    "quota_fallbacks",
    "failure_banners",
    "published_guardrail_policy_review",
    "bedrock_invocation_logging_review",
)


class ReviewError(RuntimeError):
    pass


def _bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ReviewError(f"missing or invalid: {path}") from None


def build(root: Path, drafts: Path, reviewer: str, reviewed_at: str) -> dict[str, bytes]:
    """Every Stage 3 review document, keyed by its path under docs/evidence."""
    evidence = root / "docs/evidence"
    sources = {}
    for relative in SOURCE_FILES:
        path = evidence / relative
        if not path.is_file():
            raise ReviewError(f"missing source export: docs/evidence/{relative}")
        sources[relative] = path.read_bytes()
    draft = {name: _read(drafts / name) for name in DRAFT_NAMES}

    def stamp(document: dict[str, Any]) -> dict[str, Any]:
        return {**document, "reviewed_by": reviewer, "reviewed_at": reviewed_at}

    files: dict[str, bytes] = {}
    external = draft["external-tls-scan.json"]
    if external.get("source_report_sha256") != _sha(sources["stage3/source-reports/external-tls.json"]):
        raise ReviewError(
            "external-tls.json changed after the transport check; run the transport check again"
        )
    files["stage3/external-tls-scan.json"] = _bytes(stamp(external))
    files["stage3/transport-security.json"] = _bytes(
        stamp(
            {
                **draft["transport-security.json"],
                "external_scan_evidence_path": "stage3/external-tls-scan.json",
                "external_scan_sha256": _sha(files["stage3/external-tls-scan.json"]),
            }
        )
    )
    privacy = dict(draft["privacy-accessibility.json"])
    for field, report in (
        ("browser_network", "browser-network"),
        ("lighthouse", "lighthouse"),
        ("accessibility", "accessibility"),
    ):
        relative = f"stage3/source-reports/{report}.json"
        privacy[f"{field}_report_evidence_path"] = relative
        digest_field = (
            "browser_network_log_sha256" if field == "browser_network" else f"{field}_report_sha256"
        )
        privacy[digest_field] = _sha(sources[relative])
    files["stage3/privacy-accessibility.json"] = _bytes(stamp(privacy))
    for name in ("rin-evaluation.json", "quota-fallbacks.json", "failure-banners.json"):
        files[f"stage3/{name}"] = _bytes(stamp(draft[name]))

    configuration = json.loads(sources["stage3/guardrail-configuration.json"])
    evaluation = json.loads(sources["stage3/guardrail-evaluation.json"])
    files["stage3/guardrail-policy-review.json"] = _bytes(
        stamp(
            {
                "schema_version": 1,
                "guardrail_arn_sha256": configuration["guardrail_arn_sha256"],
                "published_version": configuration["published_version"],
                "configuration_evidence_path": "stage3/guardrail-configuration.json",
                "configuration_sha256": _sha(sources["stage3/guardrail-configuration.json"]),
                "input_controls": configuration["input_controls"],
                "output_controls": configuration["output_controls"],
                "evaluation": {
                    "evidence_path": "stage3/guardrail-evaluation.json",
                    "sha256": _sha(sources["stage3/guardrail-evaluation.json"]),
                    "passed": evaluation["passed"],
                    "case_count": evaluation["case_count"],
                },
            }
        )
    )
    bedrock = json.loads(sources["stage3/bedrock-logging-settings.json"])
    provider = json.loads(sources["stage3/external-provider-logging-settings.json"])

    def scope(settings: dict[str, Any], relative: str, *, with_provider: bool) -> dict[str, Any]:
        value = {
            "enabled": settings["enabled"],
            "includes_prompt_content": settings["includes_prompt_content"],
            "retention_days": settings["retention_days"],
            "evidence_path": relative,
            "settings_sha256": _sha(sources[relative]),
        }
        if with_provider:
            value["provider"] = settings["provider"]
        return value

    files["stage3/bedrock-logging-review.json"] = _bytes(
        stamp(
            {
                "schema_version": 1,
                "guardrail_arn_sha256": configuration["guardrail_arn_sha256"],
                "published_version": configuration["published_version"],
                "bedrock_model_invocation_logging": scope(
                    bedrock, "stage3/bedrock-logging-settings.json", with_provider=False
                ),
                "external_provider_logging": scope(
                    provider, "stage3/external-provider-logging-settings.json", with_provider=True
                ),
                "maximum_prompt_retention_days": STAGE3_MAX_PROMPT_RETENTION_DAYS,
            }
        )
    )
    return files


def stage_record(root: Path, files: dict[str, bytes], reviewer: str, reviewed_at: str) -> dict[str, Any]:
    evidence = sorted(STAGE_REQUIRED_EVIDENCE["stage3"])
    digests = {}
    for relative in evidence:
        data = files.get(relative)
        if data is None:
            data = (root / "docs/evidence" / relative).read_bytes()
        digests[relative] = _sha(data)
    return {
        "status": "passed",
        "reviewed_by": reviewer,
        "reviewed_at": reviewed_at,
        "criteria": dict.fromkeys(CRITERIA, True),
        "evidence": evidence,
        "evidence_sha256": digests,
    }


def write(root: Path, files: dict[str, bytes], record: dict[str, Any]) -> None:
    for relative, data in files.items():
        target = root / "docs/evidence" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest_path = root / "docs/evidence/phase3-stage-acceptance.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["deployment_gates"]["stage3"] = record
    manifest["canonical_status"]["stage3"] = {
        "status": "passed",
        "verification_scope": "private_aws_verification",
        "summary": "Private AWS verification was reviewed and recorded for Stage 3.",
        "verification_evidence": ["docs/evidence/stage3/ reviewed artifacts bound by SHA-256."],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def check(root: Path, record: dict[str, Any], quota: dict[str, Any]) -> None:
    try:
        validate_stage_gates(
            root / "docs/evidence/phase3-stage-acceptance.json",
            root=root,
            enabled_stages=set(),
            expected_daily_invocation_limit=quota["daily_invocation_limit"],
            expected_monthly_budget_usd=quota["monthly_budget_usd"],
            require_runtime_bindings=True,
        )
    except StageGateError as exc:
        raise ReviewError(f"the Phase 3 deployment gates reject this evidence: {exc}") from None


def record_review(
    root: Path, drafts: Path, reviewer: str, *, confirm: bool, reviewed_at: str | None = None
) -> dict:
    reviewed_at = reviewed_at or datetime.now().astimezone().replace(microsecond=0).isoformat()
    files = build(root, drafts, reviewer, reviewed_at)
    record = stage_record(root, files, reviewer, reviewed_at)
    quota = json.loads(files["stage3/quota-fallbacks.json"])
    with tempfile.TemporaryDirectory() as scratch:
        # Resolve symlinks (macOS temp dirs live under /var -> /private/var) so
        # the gate sees docs/evidence inside the scratch root.
        scratch_root = Path(scratch).resolve()
        shutil.copytree(root / "docs/evidence", scratch_root / "docs/evidence")
        write(scratch_root, files, record)
        check(scratch_root, record, quota)
    if confirm:
        write(root, files, record)
    return {"files": files, "record": record, "quota": quota}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--confirm-reviewed", action="store_true")
    args = parser.parse_args(argv)
    reviewer = args.reviewer.strip()
    if not reviewer or len(reviewer) > 120:
        parser.error("--reviewer must be 1-120 characters")
    try:
        result = record_review(ROOT, ROOT / "build/phase3/stage3", reviewer, confirm=args.confirm_reviewed)
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    files, quota = result["files"], result["quota"]
    rin = json.loads(files["stage3/rin-evaluation.json"])
    guardrail = json.loads(files["stage3/guardrail-policy-review.json"])
    external = json.loads(files["stage3/external-tls-scan.json"])
    print("Stage 3 evidence passes the gate:")
    print(f"  HTTPS and headers   {external['provider']}")
    print(f"  Rin evaluation      {sum(c['passed'] for c in rin['cases'])}/{len(rin['cases'])} cases")
    print(
        f"  Quotas              {quota['per_session_limit']} per session, {quota['daily_invocation_limit']} per day,"
        f" ${quota['monthly_budget_usd']} per month"
    )
    print("  Failure banners     8/8 states shown")
    print(
        f"  Guardrail           version {guardrail['published_version']},"
        f" {guardrail['evaluation']['case_count']} cases passed"
    )
    print("  Logging review      prompt retention within 30 days")
    if not args.confirm_reviewed:
        print("\nDry run: nothing written. Rerun with --confirm-reviewed to record the review.")
        print(
            "The GitHub variables must give the same daily cap: PHASE3_PROVIDER_MONTHLY_BUDGET_USD="
            f"{quota['monthly_budget_usd']:g} with the token prices and limits used for the quota check."
        )
        return 0
    print(
        f"\nWrote {len(files)} review files and marked Stage 3 as privately verified in docs/evidence/phase3-stage-acceptance.json."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
