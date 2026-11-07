# Stage 3 evidence (in progress)

Stage 3 has **not passed**, and live Rin stays disabled. This folder holds the
source exports captured so far. The Stage 3 review records (with reviewer and
review time) are written only when every criterion has evidence.

## Captured on 2026-11-07

| Export | Captured with | Result |
| --- | --- | --- |
| `guardrail-configuration.json` | `scripts/phase3_rin_guardrail.py evaluate` | Published Guardrail version 3, read back from AWS: prompt-attack, denied-topic, and sensitive-data controls on input and output |
| `guardrail-evaluation.json` | `scripts/phase3_rin_guardrail.py evaluate` | 26 of 26 adversarial and must-allow cases passed |
| `bedrock-logging-settings.json` | `scripts/phase3_rin_logging_capture.py` | Bedrock model invocation logging is off; no prompt text is stored |
| `external-provider-logging-settings.json` | `scripts/phase3_rin_logging_capture.py` | No external provider: Rin uses Amazon Bedrock in the control-plane account |

The Guardrail is identified by the SHA-256 of its ARN, so no account ID is
checked in.

Also run on 2026-11-07, with results kept under `build/phase3/stage3/` until
the Stage 3 review:

- `scripts/phase3_rin_evaluation.py`: Rin's request handler with Claude Haiku
  4.5 on Amazon Bedrock (US inference profile) and Guardrail version 3. 11 of
  11 cases passed: citation grounding, response schema, prompt injection,
  hostile finding text, secret leakage, unsupported questions, and
  provider-error fallback.
- `scripts/phase3_rin_quota_evaluation.py`: the real quota writer and budget
  kill switch against Moto. Session (10 questions), daily (19 questions at a
  $5 monthly budget), and monthly-budget caps all returned the fixture
  fallback without reaching the model.

## Open blocker: TLS on the default CloudFront domain

The console is served at its `*.cloudfront.net` address. CloudFront accepts
TLS 1.0 and 1.1 there (checked 2026-11-07 with `curl --tlsv1.0 --tls-max 1.0`),
and a minimum protocol version can only be set with a custom domain and an
ACM certificate. The Terraform already supports this (`domain_name`,
`certificate_arn`, `TLSv1.2_2021`). Until a custom domain is configured, the
`https_and_security_headers` criterion cannot pass, so Stage 3 and live Rin
remain blocked by design.
