# Audit findings tracker

Findings from a full shakedown/audit of the running app (2026-07-10), not yet
triaged into fix PRs. Each file documents one finding: what was observed, why it
matters, priority, and detailed instructions for the implementer. **These docs
describe problems only — no code has changed.** Fixing any of them is a separate,
future PR that should reference the relevant file here.

Once a finding is fixed, delete its file from this directory and fold a one-line
mention into `CHANGELOG.md` under the release that shipped the fix (see
[Documentation sync](../../../AGENTS.md#documentation-sync)) — don't let a fixed
finding linger here alongside shipped history.

## Open findings

| # | Finding | Area | Priority |
|---|---------|------|----------|
| [0002](0002-missing-hsts-csp-hardening.md) | Missing HSTS header; CSP missing `base-uri`/`object-src` | Security | Medium-High |
| [0004](0004-viewer-token-minting.md) | Viewers can mint their own (read-only) API tokens | Security | Medium |
| [0005](0005-webhook-ssrf-guard-parity.md) | Webhook dispatcher may lack the agent-endpoint SSRF guard | Security | Medium-High |
| [0006](0006-export-transient-503.md) | Transient 503 on repeated `/subnets/export.csv` requests | Reliability | Medium |
| [0007](0007-audit-log-metadata-empty.md) | Audit log metadata mostly empty; `scan.discovery.recorded` mislabels a count as `status` | Observability | Low-Medium |
| [0008](0008-405-plaintext-response.md) | 405 Method Not Allowed returns plain text instead of the JSON error envelope | API consistency | Low |
| [0009](0009-readme-js-wording-and-social-preview.md) | README JS-framework wording could mislead; GitHub social-preview image still unset | Docs | Low |

## Priority key

- **High** — realistic exploit path with low attacker effort; fix soon.
- **Medium-High** — real risk but needs a specific precondition (admin role, specific deployment choice).
- **Medium** — worth fixing, not urgent; often a defense-in-depth or config-default question.
- **Low-Medium** — no security impact, but materially hurts operability (e.g. forensics).
- **Low** — cosmetic, consistency, or minor polish.
