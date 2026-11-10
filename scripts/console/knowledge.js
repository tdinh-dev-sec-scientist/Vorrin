(function installPhase3PlatformKnowledge(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.Phase3PlatformKnowledge = api;
})(typeof globalThis === "undefined" ? this : globalThis, function createPhase3PlatformKnowledge() {
  "use strict";

  const KNOWLEDGE_VERSION = "1.2.0";
  const entries = [
    {
      id: "phase3-status",
      match: /\bphase\s*3\b.*\b(live|deploy|status|complete|done|website|ready)\b|\b(is|has)\b.*\b(live|deployed|launched)\b.*\b(website|phase\s*3|demo)\b/i,
      text: "The public GitHub Pages site is a static Moto/fixture replay, not the separate Phase 3 live console. The checked-in acceptance manifest records Stages 1, 2, and 3 as passed through 2026-11-08; Stage 4 remains pending. Live Rin is invite-only according to the repository evidence.",
      citations: ["docs/evidence/phase3-stage-acceptance.json", "docs/phase3-status.md · Stage status"],
    },
    {
      id: "access-control",
      match: /\b(sign[- ]?in|log[- ]?in|invite[ds]?|invite[- ]only|access control|private access|mfa)\b|\bwho can\b.*\b(use|access|see|sign)\b/i,
      text: "The separate Phase 3 live console is invite-only. The owner creates each account; there is no self sign-up. Users sign in through Cognito with mandatory MFA, and every API and Rin request needs a valid ID token, which the API re-checks. Rin's quota is counted per signed-in user. The public fixture page stays visible without signing in.",
      citations: ["docs/private-access.md", "docs/phase3-access-mode-amendment.md"],
    },
    {
      id: "read-only-boundary",
      match: /\b(read[- ]only|read only)\b|\b(?:aws|target account|scan results)\b.*\b(write access|write to|modify|change)\b|\b(?:does|can)\s+(?:rin|the scan worker|the public api)\b.*\b(write|modify|change)\b|\b(?:what|which)\b.*\bpermissions?\b.*\b(rin|public api|scan worker)\b/i,
      text: "In the live design, the scan worker reads target AWS resources only. The public API reads sanitized scan data and its feature flag, and writes only to its own CloudWatch log group. Rin reads sanitized scan data, its feature flag, and its provider secret; Rin's role writes only to its own CloudWatch log group and invokes a separate quota function, which writes per-session and daily counters to its own DynamoDB table. The public API and Rin cannot change target AWS resources or scan results. Stage 1 demo-account Terraform uses a separate apply approval to create or fix demo resources; later Phase 3 stacks remain disabled until their predecessor acceptance is recorded. The repository includes a Stage 1 read-only-role review; owner-managed organization and control-plane role policies are not captured here.",
      citations: ["docs/least-privilege.md · The chain", "docs/phase3-status.md · Confirmed assumptions and permission boundary", "infra/phase3/policies/rin-readonly.json · Service boundary", "infra/phase3/control-plane/stage3.tf · Rin runtime and log policy", ".github/workflows/phase3-terraform.yml · Protected apply"],
    },
    {
      id: "rin-privacy",
      match: /\b(rin|assistant|chatbot|ai analyst|model)\b.*\b(provider|privacy|data|enabled|access|aws|permission|permissions|tool|tools|answer|answers|send|external|store|capabilities|guardrail|moderation|prompt)\b|\bwhat is rin\b(?!['’]s?\b)/i,
      text: "Rin is enabled for invited users according to the Stage 3 acceptance record. It can explain one redacted finding, has no target-account scanning tools, and cannot change scan results. The public GitHub Pages demo uses local fixture answers only; no model is connected to that site. In the separate live service, an owner-managed Bedrock Guardrail checks the bounded redacted input before the external model and validates the answer before it reaches the visitor. A block, invalid response, or service error selects the fixture fallback. Guardrail errors use that fallback too.",
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
      text: "According to the repository's Stage 1–3 acceptance record, the separate live flow uses a scanner that reads the dedicated target account through its read-only role and records a private snapshot; a publisher redacts and validates that snapshot into an isolated public store; the API and website read only the sanitized copy. The public GitHub Pages site remains a static fixture replay, while the live console is invite-only.",
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
      text: "The recorded AWS estimate is $2.93 per month and the documented owner cap is $10. Stage 4 remains pending its budget cutoff, kill-switch recovery, and actual-cost evidence. A budget alert is not a hard spend cap; confirm an owner cap at or below $5 before enabling additional billable work. Rin's model-provider budget is separate.",
      citations: ["docs/evidence/aws-cost-estimate.md", "docs/evidence/phase3-stage-acceptance.json", "docs/phase3-status.md · Remaining Stage 4 evidence"],
    },
    {
      id: "platform-overview",
      match: /\b(what|describe|explain)\b.*\b(platform|project|vorrin|guardrails)\b|\b(platform|project)\b.*\b(do|include|purpose|scope)\b/i,
      text: "Vorrin is a read-only AWS cloud-security guardrails platform. Phase 2 checks AWS account posture and infrastructure policy, gates changes, and records drift. The repository records Phase 3 Stages 1–3 as passed for a separate invite-only live console; Stage 4 remains pending. The public GitHub Pages site is a static Moto/fixture replay.",
      citations: ["README.md · Live deployment status", "docs/evidence/phase3-stage-acceptance.json", "docs/phase3-status.md · Stage status"],
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

  return { KNOWLEDGE_VERSION, answerPlatformQuestion };
});
