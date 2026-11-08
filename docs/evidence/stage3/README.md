# Stage 3 evidence

**Stage 3 passed on 2026-11-08** (reviewed by Truong Dinh). The record is in
`../phase3-stage-acceptance.json`; every file below is bound to it by SHA-256,
and the same gate runs in Terraform before Stage 4 or live Rin can be enabled.

| Criterion | Evidence | Result |
| --- | --- | --- |
| HTTPS and security headers | `transport-security.json`, `external-tls-scan.json`, `source-reports/external-tls.json` | Custom domain with an ACM certificate and `TLSv1.2_2021`: HTTP redirects to HTTPS, TLS 1.0 and 1.1 refused, five required headers present, Mozilla HTTP Observatory grade in the A range |
| Browser privacy and accessibility | `privacy-accessibility.json`, `source-reports/browser-network.json`, `accessibility.json`, `lighthouse.json` | No third-party requests on the dashboard, finding, and Rin pages; axe-core 4.14.0 found no violations; Lighthouse accessibility 100 |
| Rin evaluation | `rin-evaluation.json` | 11 of 11 cases with Claude Haiku 4.5 on Amazon Bedrock and the published Guardrail |
| Quota fallbacks | `quota-fallbacks.json` | Session (10), daily (19), and monthly-budget ($5) caps all return the fixture fallback |
| Failure banners | `failure-banners.json` | All eight failure states are shown in the browser |
| Guardrail policy review | `guardrail-policy-review.json`, `guardrail-configuration.json`, `guardrail-evaluation.json` | Published version 3; 26 of 26 adversarial and must-allow cases |
| Bedrock logging review | `bedrock-logging-review.json`, `bedrock-logging-settings.json`, `external-provider-logging-settings.json` | Model invocation logging off; no external provider receives prompts |

The Guardrail is identified by the SHA-256 of its ARN, so no account ID is
checked in. The default CloudFront domain still accepts TLS 1.0 and 1.1, which
is why the console moved to a custom domain before this review.
