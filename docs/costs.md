# Phase 3 cost record

This file records the AWS estimate and operational budget controls for the
Phase 3 deployment. Actual AWS and external-provider charges still need a
monthly Cost Explorer or provider billing export.

## Recorded estimate and cap

| Record | Value |
| --- | --- |
| AWS Pricing Calculator monthly estimate | **$2.93** (rounded to $3) |
| Calculator evidence | [AWS cost estimate](evidence/aws-cost-estimate.md) |
| Monthly AWS budget ceiling in Terraform | **$5.00** |
| Operational circuit-breaker threshold | **$4.50 actual or forecasted AWS spend** |
| AWS region and usage assumptions | us-east-1; 130 scheduled/manual Fargate scans and light console traffic |
| External provider and approved model | Claude Haiku 4.5 through Amazon Bedrock; provider budget is separate |
| Monthly budget alert recipient | Owner-managed GitHub variable; the address is not stored here |

The control-plane stages stay disabled until their predecessor evidence and
owner-managed settings are supplied. Live Rin also requires its separate
provider budget, model, token rates, and a published Bedrock Guardrail.

## Cost controls in code

- AWS Budgets sets a $5.00 monthly budget. It sends email alerts at 50%, 80%,
  and 100% of the budget.
- When actual or forecasted AWS spend reaches or exceeds $4.50, AWS Budgets
  publishes to the isolated SNS topic. The Lambda breaker sets Rin to static
  mode, disables the six-hour scan schedule, stops running Step Functions
  executions, and stops Fargate tasks in the Phase 3 scan cluster.
- AWS Budgets data is delayed, and forecast alerts need about five weeks of
  usage history. The $5.00 budget and $4.50 breaker are operating controls, not
  a guaranteed billing limit; costs already incurred or reported late can
  exceed the threshold before the Lambda runs.
- Rin enforces a ten-question browser-session limit and an atomic global daily
  provider-call cap. Its cap is derived from the owner-entered provider monthly
  budget and current per-token rates, reserving 20% of that budget and capping
  at 1,000 calls per day. A blocked request emits only an aggregate metric; it
  does not log a session token or question text.
- Each live Rin request also makes two Bedrock Guardrail evaluations: one for
  the bounded redacted input before the external model call and one for the
  validated response before it reaches the visitor. Both evaluations are
  included in the AWS estimate.
- WAF limits API traffic to 100 requests per IP per five minutes. Provider
  input bytes and output tokens are bounded before a call. The live API, Rin,
  and scanners cannot create, update, or delete target-account resources.
- Scheduled scans are disabled by default and are limited to the dedicated
  demo account. The Organizations S3 policy enforces all four public-access
  block settings throughout the demo OU.

## Actual costs after launch

| Month (UTC) | AWS actual spend | External provider actual spend | Evidence |
| --- | --- | --- | --- |
| Not recorded | **Not captured** | **Not captured** | Add owner-reviewed AWS Cost Explorer and provider billing exports. |

Update this table monthly with the period, currency, account scope, and report
reference. Do not substitute Moto request counts or a calculator estimate for
actual spend.
