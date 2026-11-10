# Phase 3 status

**The checked-in acceptance manifest records Stages 1–3 as passed and Stage 4 as pending.**
The manifest is the source of truth for repository status and binds the
owner-reviewed evidence files by SHA-256. The public GitHub Pages site remains
a static Moto/fixture replay; it is not the separate invite-only Phase 3
console. This page reports repository evidence and does not independently
query AWS.

Terraform 1.9.8 `fmt -check -recursive infra/phase3` passed, and
`terraform validate` passed in the `org`, `demo-bootstrap`, `demo-account`,
and `control-plane` roots. Each root was initialized with `-backend=false` and
`-lockfile=readonly`; no AWS credentials were used. These local checks do not
count as live acceptance.

The owner selected invite-only access on 2026-11-05; see
[private access](private-access.md) and the
[access-mode amendment](phase3-access-mode-amendment.md), which records how
the Stage 4 traffic-control evidence differs by mode.

The README now gives visitors a short console walkthrough and links each view
to its source report and JSON evidence. The demo video
(`docs/media/vorrin-demo.mp4`) shows simulated and Moto-emulated data, not
a live AWS account.

## Stage status

| Stage | Local implementation | Live acceptance |
| --- | --- | --- |
| Stage 1 — Demo account and scans | OU/SCP, guarded low-cost demo resources, read-only ECS Fargate scanner, scheduler, private snapshots, and drift history are implemented. | **Passed 2026-11-07** per the acceptance manifest: two scheduled scans, reviewed drift, and read-only-role evidence. |
| Stage 2 — Redaction, publication, and API | Versioned public schema, allowlist redaction, private-to-public publisher, last-good behavior, and GET/HEAD API are implemented and locally tested. | **Passed 2026-11-07** per the acceptance manifest: redaction, publisher-failure atomicity, and public API method evidence. |
| Stage 3 — Website and Rin | Sanitized bundle, same-origin API client, failure banners, fixture fallback, external-provider Rin path, input/output Bedrock Guardrail checks, session/daily quotas, CloudFront/TLS Terraform, and invite-only access (Cognito sign-in with MFA and PKCE, an authorizer on every API method, per-user quotas; WAF in public mode) are implemented. | **Passed 2026-11-08** per the acceptance manifest and linked evidence: HTTPS and headers, Rin evaluation, quota fallbacks, failure banners, Guardrail version 3 (26/26), and Bedrock logging review. Live Rin enabled for invited users on 2026-11-08 (Claude Haiku 4.5 on Amazon Bedrock, Guardrail version 3, $5/month provider budget, 19 questions/day); the budget kill switch, alerts, and monthly AWS budget are deployed. |
| Stage 4 — Harden, document, and launch | AWS budget alerts, a separate daily-limit alert, atomic static-mode kill switch, and operational documentation are implemented. | **Pending.** Budget-cutoff, kill-switch recovery, actual monthly cost, launch, external-security, and load/resilience evidence remain outstanding. |

Later-stage code was prepared before earlier live gates passed; this sequencing
deviation is documented. The checked-in manifest records Stages 1 and 2 passed
on 2026-11-07 and Stage 3 passed on 2026-11-08, with Stage 4 pending. The
manifest binds reviewed evidence files by SHA-256; the listed Stage 1–3 files
are checked into docs/evidence. These are repository owner-reviewed records;
this page does not independently query the AWS account or verify external
control-plane settings. The configured audit-readonly profile can obtain an
identity but AWS denies iam:ListRoles; the default profile resolves to account
root and was not used for policy capture. Effective organization and
control-plane role policies remain owner-managed and unverified here.

The version-3 stage gate requires named evidence artifacts and a SHA-256 digest
for every reviewed file. A file changed after review blocks the gate. Stage 3
also validates that its review summaries match the captured Guardrail and
logging records. The manifest records Stage 3 passed; Stage 4 remains pending
until its own budget, recovery, cost, and launch evidence is reviewed.

## Confirmed assumptions and permission boundary

The public snapshot shape is versioned as 2.0.0 because evidence summaries and
affected-service status are required fields. The repository contains no 1.0.0
public snapshot, and the Stage 2 acceptance manifest records publisher and API
evidence. This repository does not provide credentials or direct access to the
live public-results store; before a future schema migration, independently
verify current and prior objects and the latest pointer.

- **A1 is false:** Phase 2 has local drift history and a fixture-backed static
  site, not an S3 snapshot store or DynamoDB index. Phase 3 implements those
  missing components.
- **Rin status:** The acceptance manifest records Stage 3 passed on 2026-11-08.
  Its evidence describes invite-only live Rin using Claude Haiku 4.5 on Amazon
  Bedrock with a published Guardrail and a separate provider budget. The public
  GitHub Pages assistant remains fixture-only; no model is connected there.
- The scan worker assumes only the named target read-only role. The public API
  reads sanitized scan results and its feature flag, and writes its own logs.
  Rin reads sanitized scan results, its feature flag and provider secret,
  invokes the separate quota function, writes its own logs, and applies only
  the approved Bedrock Guardrail when enabled. Neither can change target
  resources or scan results. The private snapshot writer, publisher, quota
  writer, and kill switch have separate runtime roles.
  The Organizations and control-plane Terraform role policies are owner-created
  prerequisites and have not been independently verified; see the bootstrap
  guide before using them.
- Terraform defaults for stage flags, the six-hour schedule, and live Rin stay
  disabled for new environments. The accepted deployment recorded in the
  manifest has its own configured values. See [the cost record](costs.md) and
  [the operations runbook](operations-runbook.md) before any live plan.

## Remaining Stage 4 evidence and deployment caveats

1. Stage 4 remains pending until budget cutoff, kill-switch recovery, actual
   monthly AWS cost, launch, external security scan, and load/resilience
   evidence are reviewed.
2. The recorded cost estimate is $2.93/month, while the documented owner cap
   is $10/month. This estimate and alerting configuration do not establish a
   hard $5/month ceiling; confirm a cap at or below $5 before enabling
   additional billable work.
3. AWS Organizations and control-plane role policies, the selected Terraform
   state bucket/table, and their effective permissions are owner-managed
   prerequisites. Their deployed configuration is not independently captured
   by this repository status page.
4. For future provisioning, use the bootstrap guide and keep account-specific
   values out of tracked files.

The accepted Stage 3 evidence uses a custom domain. The CloudFront default
domain remains the fallback for future environments without one.
