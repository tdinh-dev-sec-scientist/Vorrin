(function installPhase3PlatformKnowledge(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.Phase3PlatformKnowledge = api;
})(typeof globalThis === "undefined" ? this : globalThis, function createPhase3PlatformKnowledge() {
  "use strict";

// BEGIN GENERATED PHASE 3 STATUS
  const PHASE3_STATUS = Object.freeze({
  "privateAwsStage3Verified": false,
  "stages": {
    "stage1": {
      "status": "passed",
      "verification_scope": "offline_fixtures_and_moto",
      "summary": "Offline fixtures and Moto-backed Phase 3 benchmark tests pass. This verifies repository behavior only, not a deployed AWS account.",
      "verification_evidence": [
        "CI Python 3.11 and 3.12 pytest runs using offline fixtures and Moto."
      ],
      "label": "PASSED (Offline Fixtures & Moto Benchmarks)"
    },
    "stage2": {
      "status": "passed",
      "verification_scope": "offline_fixtures_and_moto",
      "summary": "Offline redaction, publication, and API behavior checks pass with fixtures and Moto. This does not confirm a live AWS publication path.",
      "verification_evidence": [
        "CI Python 3.11 and 3.12 pytest runs using offline fixtures and Moto."
      ],
      "label": "PASSED (Offline Fixtures & Moto Benchmarks)"
    },
    "stage3": {
      "status": "unverified",
      "verification_scope": "pending_external_confirmation",
      "summary": "Checked-in owner-provided artifacts are not independent proof of an AWS deployment or live Rin enablement; external confirmation is pending.",
      "verification_evidence": [],
      "label": "UNVERIFIED / PENDING EXTERNAL CONFIRMATION"
    },
    "stage4": {
      "status": "pending",
      "verification_scope": "load_and_operational_resilience",
      "summary": "Load and operational resilience benchmarks, budget-cutoff and recovery rehearsal, and actual-cost evidence remain outstanding.",
      "verification_evidence": [],
      "label": "PENDING (Load & Operational Resilience Benchmarks)"
    }
  },
  "summary": "Stage 1: PASSED (Offline Fixtures & Moto Benchmarks); Stage 2: PASSED (Offline Fixtures & Moto Benchmarks); Stage 3: UNVERIFIED / PENDING EXTERNAL CONFIRMATION; Stage 4: PENDING (Load & Operational Resilience Benchmarks)"
});
// END GENERATED PHASE 3 STATUS

  const KNOWLEDGE_VERSION = "1.3.0";
  const entries = [
    {
      id: "phase3-status",
      match: /\bphase\s*3\b.*\b(live|deploy|status|complete|done|website|ready)\b|\b(is|has)\b.*\b(live|deployed|launched)\b.*\b(website|phase\s*3|demo)\b/i,
      text: "The public GitHub Pages site is a static Moto/fixture replay. " + PHASE3_STATUS.summary + ". Live AWS deployment and live Rin access are not independently verified.",
      citations: ["docs/evidence/phase3-stage-acceptance.json", "docs/phase3-status.md · Stage status"],
    },
    {
      id: "access-control",
      match: /\b(sign[- ]?in|log[- ]?in|invite[ds]?|invite[- ]only|access control|private access|mfa)\b|\bwho can\b.*\b(use|access|see|sign)\b/i,
      text: "The Phase 3 deployment design uses invite-only Cognito access with mandatory MFA, PKCE, and per-user Rin quotas. Canonical Stage 3 status: " + PHASE3_STATUS.stages.stage3.label + "; live account access is not independently verified. The public fixture page remains available without signing in.",
      citations: ["docs/private-access.md", "docs/phase3-access-mode-amendment.md"],
    },
    {
      id: "read-only-boundary",
      match: /\b(read[- ]only|read only)\b|\b(?:aws|target account|scan results)\b.*\b(write access|write to|modify|change)\b|\b(?:does|can)\s+(?:rin|the scan worker|the public api)\b.*\b(write|modify|change)\b|\b(?:what|which)\b.*\bpermissions?\b.*\b(rin|public api|scan worker)\b/i,
      text: "In the Phase 3 design, the scan worker reads target AWS resources only. The public API reads sanitized scan data and its feature flag, and writes only to its own CloudWatch log group. Rin reads sanitized scan data, its feature flag, and its provider secret; Rin's role writes only to its own CloudWatch log group and invokes a separate quota function, which writes per-session and daily counters to its own DynamoDB table. The public API and Rin cannot change target AWS resources or scan results. The Phase 3 stacks remain disabled until private deployment acceptance is recorded; owner-managed organization and control-plane role policies are not independently captured here.",
      citations: ["docs/least-privilege.md · The chain", "docs/phase3-status.md · Confirmed assumptions and permission boundary", "infra/phase3/policies/rin-readonly.json · Service boundary", "infra/phase3/control-plane/stage3.tf · Rin runtime and log policy", ".github/workflows/phase3-terraform.yml · Protected apply"],
    },
    {
      id: "rin-privacy",
      match: /\b(rin|assistant|chatbot|ai analyst|model)\b.*\b(provider|privacy|data|enabled|access|aws|permission|permissions|tool|tools|answer|answers|send|external|store|capabilities|guardrail|moderation|prompt)\b|\bwhat is rin\b(?!['’]s?\b)/i,
      text: "Canonical Stage 3 status: " + PHASE3_STATUS.stages.stage3.label + ". The repository does not verify live Rin enablement. The Phase 3 design can explain one redacted finding, has no target-account scanning tools, and cannot change scan results. The public GitHub Pages demo uses local fixture answers only; no model is connected to that site. In a deployed service, a Bedrock Guardrail is intended to check bounded redacted input and validate the answer before it reaches a visitor. A block, invalid response, or service error selects the fixture fallback. Guardrail errors use that fallback too.",
      citations: ["docs/ai-analyst.md · Evidence-bound output", "docs/phase3-bootstrap.md · Rin Bedrock Guardrail", "docs/phase3-status.md · Stage 3"],
    },
    {
      id: "service-scope",
      match: /\b(which|what|supported|scanned)\b.*\b(aws )?services\b|\b(iam|s3|cloudtrail)\b.*\b(check|scan|support)\b/i,
      text: "The AWS posture checks cover IAM, S3, and CloudTrail. Incomplete collection stays UNKNOWN or ERROR; it is not treated as a clean result.",
      citations: ["docs/least-privilege.md", "docs/contracts.md · Run status and exit codes"],
    },
    {
      id: "architecture-flow",
      match: /\b(architecture|data flow)\b|\bhow does\b.*\b(public demo|phase\s*3 website|publication path)\b.*\b(work|flow|move)\b|\bwhere.*\b(public|private) data\b/i,
      text: "The Phase 3 design uses a scanner that reads a dedicated target account through a read-only role and records private snapshots; a publisher redacts and validates snapshots before the API and website read sanitized data. Canonical status: " + PHASE3_STATUS.summary + ". The public GitHub Pages site is a static fixture replay; private AWS deployment is not independently verified.",
      citations: ["docs/phase3-status.md · Stage status", "docs/phase3-bootstrap.md"],
    },
    {
      id: "iac-inputs",
      match: /\b(iac|infrastructure as code|terraform|helm|kubernetes|checkov|conftest)\b/i,
      text: "Local IaC scanning supports Terraform HCL, IAM policy JSON, Kubernetes YAML or JSON, and rendered Helm YAML. It does not render raw Helm templates or accept Terraform JSON (.tf.json). Scans run locally without AWS credentials.",
      citations: ["docs/iac-scanning.md · Local IaC and policy scanning"],
    },
    {
      id: "rule-catalog",
      match: /\b(what|which|list|show)\b.*\brule ids?\b.*\b(catalog|covered|included|available|cover)\b|\brule catalog\b.*\b(ids?|list|include|cover)\b/i,
      text: "The AWS posture rule catalog contains 14 controls: IAM-001 through IAM-006, S3-001 through S3-004, and CT-001 through CT-004.",
      citations: ["docs/implementation-status.md", "docs/cis-mapping.md · Mapped rules"],
    },
    {
      id: "cis-coverage",
      match: /\b(cis|security control|control mapping)\b.*\b(mapped|mapping|coverage|how many)\b|\b(what|which|how many)\b.*\b(cis|control mapping)\b/i,
      text: "The documented CIS AWS Foundations v3.0.0 mapping covers 11 of 14 auditor rules. Two related rules are marked partial and one is unmapped; those are not counted as direct mappings.",
      citations: ["docs/cis-mapping.md · Counting rule"],
    },
    {
      id: "drift-semantics",
      match: /\b(drift|history)\b|\bincomplete scan\b|\bunknown result\b/i,
      text: "Drift is tracked across scan history. If a service or region was not fully read, the result stays UNKNOWN; missing findings in incomplete coverage are not marked resolved and do not replace the last complete baseline.",
      citations: ["docs/fleet-scanning.md · View history", "docs/contracts.md · Run status and exit codes"],
    },
    {
      id: "budget-status",
      match: /\b(cost|budget|monthly cap|provider rates)\b.*\b(approved|estimate|recorded|cap|enforcement|controls?)\b|\b(what|which|is there)\b.*\b(cost|budget|monthly cap|provider rates)\b/i,
      text: "The recorded AWS estimate is $2.93 per month and Terraform fixes the AWS budget at $5.00. Terraform configures $4.50 actual/forecast SNS notifications to invoke a Lambda breaker intended to disable scheduled scans, stop in-flight Step Functions and Fargate scan work, disable live Rin, and select static mode. " + PHASE3_STATUS.stages.stage4.label + ". AWS Budgets data can lag, so the breaker is best-effort rather than a hard invoice cap. No live cutoff rehearsal or actual-cost evidence is recorded. Rin's provider budget is separate.",
      citations: ["docs/evidence/aws-cost-estimate.md", "docs/evidence/phase3-stage-acceptance.json", "docs/phase3-status.md · Remaining Stage 4 evidence"],
    },
    {
      id: "platform-overview",
      match: /\b(what|describe|explain)\b.*\b(platform|project|vorrin|guardrails)\b|\b(platform|project)\b.*\b(do|include|purpose|scope)\b/i,
      text: "Vorrin is a read-only AWS cloud-security guardrails platform. Phase 2 checks AWS account posture and infrastructure policy, gates changes, and records drift. " + PHASE3_STATUS.summary + ". The public GitHub Pages site is a static Moto/fixture replay.",
      citations: ["README.md · Phase 3 deployment status", "docs/evidence/phase3-stage-acceptance.json", "docs/phase3-status.md · Stage status"],
    },
  ];

  function answerPlatformQuestion(question) {
    if (typeof question !== "string" || question.length > 500) return null;
    const normalized = question.trim();
    if (!normalized) return null;
    if (/\b(finding|remediation|resource|this issue|this misconfiguration)\b/i.test(normalized)) {
      return null;
    }
    const entry = entries.find((item) => item.match.test(normalized));
    if (!entry) return null;
    return {
      id: entry.id,
      version: KNOWLEDGE_VERSION,
      text: entry.text,
      citations: [...entry.citations],
    };
  }

  return { KNOWLEDGE_VERSION, PHASE3_STATUS, answerPlatformQuestion };
});
