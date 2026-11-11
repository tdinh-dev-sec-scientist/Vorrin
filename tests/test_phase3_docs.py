import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_phase3_status_separates_offline_verification_from_deployment_acceptance():
    status = (ROOT / "docs/phase3-status.md").read_text(encoding="utf-8")
    normalized_status = " ".join(status.split())
    manifest = json.loads((ROOT / "docs/evidence/phase3-stage-acceptance.json").read_text(encoding="utf-8"))

    assert "PASSED (Offline Fixtures & Moto Benchmarks)" in normalized_status
    assert "UNVERIFIED / PENDING EXTERNAL CONFIRMATION" in normalized_status
    assert "PENDING (Load & Operational Resilience Benchmarks)" in normalized_status
    assert manifest["canonical_status"]["stage1"]["status"] == "passed"
    assert manifest["canonical_status"]["stage2"]["status"] == "passed"
    assert manifest["canonical_status"]["stage3"]["status"] == "unverified"
    assert manifest["canonical_status"]["stage4"]["status"] == "pending"
    assert "Every Terraform deployment gate is pending" in normalized_status
    assert "do not authorize a live deployment" in normalized_status
    assert "does not connect to AWS" in normalized_status


def test_phase3_status_makes_the_external_verification_boundary_explicit():
    status = " ".join((ROOT / "docs/phase3-status.md").read_text(encoding="utf-8").split())

    assert "does not connect to AWS, accept credentials" in status
    assert "not independent proof of an AWS deployment" in status
    assert "external review confirms their source" in status
    assert "deployment gate binds their hashes" in status


def test_role_scope_manifest_records_are_pending_or_complete_untampered_reviews():
    from datetime import datetime

    from phase3.role_evidence import ROLE_EVIDENCE_FILES, ROLE_SOURCE_FILES

    manifest = json.loads((ROOT / "docs/evidence/phase3-role-scope.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 3
    assert set(manifest["roles"]) == {"org", "control-plane"}
    for stack, phases in manifest["roles"].items():
        assert set(phases) == {"plan", "apply"}
        for phase, record in phases.items():
            if record["status"] == "pending":
                assert record["role_arn_sha256"] is None
                assert record["evidence"] == []
                assert record["evidence_sha256"] == {}
                assert record["source_evidence_sha256"] == {}
                continue
            # A reviewed record names every redacted projection, and each
            # checked-in projection still has the digest the reviewer recorded.
            assert record["status"] == "reviewed", (stack, phase)
            assert re.fullmatch(r"[a-f0-9]{64}", record["role_arn_sha256"])
            assert record["reviewed_by"].strip()
            assert datetime.fromisoformat(record["reviewed_at"]).tzinfo is not None
            assert record["evidence"] == sorted(ROLE_EVIDENCE_FILES[stack][phase])
            assert set(record["evidence_sha256"]) == set(record["evidence"])
            for relative, digest in record["evidence_sha256"].items():
                content = (ROOT / "docs/evidence" / relative).read_bytes()
                assert hashlib.sha256(content).hexdigest() == digest, relative
            assert set(record["source_evidence_sha256"]) == ROLE_SOURCE_FILES[stack][phase]
            assert all(
                re.fullmatch(r"[a-f0-9]{64}", value) for value in record["source_evidence_sha256"].values()
            )


def test_role_capture_guide_uses_non_root_read_only_capture_and_keeps_manifest_pending():
    guide = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")
    normalized_guide = " ".join(guide.split())

    assert "scripts/capture_phase3_role_evidence.py" in guide
    assert "scripts/verify_phase3_role_capture.py" in guide
    assert "SHA-256 fingerprint of the exact role ARN" in guide
    assert "exact deterministic redaction" in normalized_guide
    assert "named non-root profile" in guide
    assert "iam:GetRole" in guide
    assert "iam:GetPolicyVersion" in guide
    assert "never changes the manifest's review status" in normalized_guide
    assert "resource and policy names" in normalized_guide
    assert "public GitHub OIDC claims" in normalized_guide
    assert "Exact policy names and values stay in owner-only source files" in normalized_guide


def test_stage_acceptance_guide_lists_required_evidence_and_digest_review():
    guide = " ".join((ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8").split())

    for artifact in (
        "stage1/scheduled-scan-results.json",
        "stage1/drift-review.json",
        "stage1/read-only-role-review.json",
        "stage2/redaction-test-results.json",
        "stage2/publisher-failure.json",
        "stage2/public-api-methods.json",
        "stage3/transport-security.json",
        "stage3/external-tls-scan.json",
        "stage3/privacy-accessibility.json",
        "stage3/rin-evaluation.json",
        "stage3/quota-fallbacks.json",
        "stage3/failure-banners.json",
        "stage3/transport-security.json",
        "stage3/rin-evaluation.json",
        "stage3/quota-fallbacks.json",
        "stage3/failure-banners.json",
        "stage4/budget-cutoff.json",
        "stage4/kill-switch-recovery.json",
        "stage4/load-resilience.json",
        "stage4/actual-monthly-cost.json",
        "stage4/launch-evidence.json",
    ):
        assert artifact in guide
    assert "evidence_sha256" in guide
    assert "not a test fixture or placeholder" in guide
    assert "changing a file after review blocks the stage" in guide
    assert "Generic `checked: true` files do not satisfy these schemas" in guide
    assert "match the configured ARN and version exactly" in guide
    assert "actual AWS and provider costs against their separate budgets" in guide
    assert "browser-network and accessibility report digests" in guide
    assert "Generic `checked: true` files do not satisfy these schemas" in guide
    assert "match the configured ARN and version exactly" in guide


def test_readme_demo_video_is_linked_and_labelled_as_non_live():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Try the console" in readme
    assert "not a live AWS account" in readme
    assert "](docs/media/vorrin-demo.mp4)" in readme
    assert "docs/images/demo-poster.jpg" in readme
    assert (ROOT / "docs/media/vorrin-demo.mp4").stat().st_size > 0


def test_stage_three_remains_unverified_until_private_aws_acceptance():
    from phase3.stage_gates import validate_stage_gates

    manifest_path = ROOT / "docs/evidence/phase3-stage-acceptance.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    canonical = manifest["canonical_status"]["stage3"]
    gate = manifest["deployment_gates"]["stage3"]

    assert manifest["schema_version"] == 4
    assert canonical["status"] == "unverified"
    assert canonical["verification_scope"] == "pending_external_confirmation"
    assert canonical["verification_evidence"] == []
    assert gate["status"] == "pending"
    assert not any(gate["criteria"].values())
    assert gate["evidence"] == []
    validate_stage_gates(manifest_path, root=ROOT, enabled_stages=set())


def test_stage_three_review_requires_digest_bound_captures_and_short_prompt_retention():
    from phase3.stage_gates import STAGE_REQUIRED_EVIDENCE

    bootstrap = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")
    manifest = json.loads((ROOT / "docs/evidence/phase3-stage-acceptance.json").read_text(encoding="utf-8"))
    stage3_evidence = STAGE_REQUIRED_EVIDENCE["stage3"]

    for artifact in (
        "stage3/guardrail-configuration.json",
        "stage3/guardrail-evaluation.json",
        "stage3/bedrock-logging-settings.json",
        "stage3/external-provider-logging-settings.json",
    ):
        assert artifact in bootstrap
        assert artifact in stage3_evidence
    assert manifest["canonical_status"]["stage3"]["status"] == "unverified"
    assert manifest["deployment_gates"]["stage3"]["evidence"] == []
    assert "matching SHA-256" in bootstrap
    assert "capped at 30" in bootstrap
    assert "expected/observed action" in bootstrap
    assert "Review summaries must" in bootstrap


def test_phase3_cost_record_never_invents_owner_values_or_actual_spend():
    costs = (ROOT / "docs/costs.md").read_text(encoding="utf-8")

    assert "AWS Pricing Calculator" in costs
    assert "Not recorded" in costs
    assert "AWS actual spend" in costs
    assert "provider" in costs.lower()
    assert "disabled by default" in costs
    assert "two Bedrock Guardrail evaluations" in costs


def test_phase3_runbook_and_threat_model_cover_the_publication_boundary_and_kill_switch():
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")
    threat = (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")

    assert "Phase 3 live operations" in runbook
    assert "static mode" in runbook.lower()
    assert "not a hard spend limit" in runbook.lower()
    assert "public-results" in threat
    assert "publisher" in threat.lower()
    assert "Rin" in threat
    assert "Bedrock Guardrail" in threat
    assert "bedrock:ApplyGuardrail" in threat
    assert "output Guardrail" in runbook


def test_phase3_runbook_matches_fargate_and_remote_state_design():
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")

    assert "local state backend by default" not in runbook
    assert "infra/phase3/demo-account" in runbook
    assert "Phase 3 Terraform" in runbook
    assert "must require a reviewer" in runbook.lower()
    assert "PHASE3_TF_STATE_BUCKET" in runbook


def test_phase3_oidc_bootstrap_guide_limits_initial_terraform_identity():
    guide = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")

    assert "Phase3DemoBootstrapPlan" in guide
    assert "Phase3DemoBootstrapApply" in guide
    assert "OrganizationAccountAccessRole" in guide
    assert "phase3-demo-bootstrap-plan" in guide
    assert "phase3-demo-bootstrap-apply" in guide
    assert "demo-bootstrap-plan.json" in guide
    assert "demo-bootstrap-apply.json" in guide
    assert "refs/heads/main" in guide
    assert "Rin Bedrock Guardrail" in guide
    assert "bedrock:ApplyGuardrail" in guide
    assert "source=INPUT" in guide and "source=OUTPUT" in guide
