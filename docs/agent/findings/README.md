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

## Priority key

- **High** — realistic exploit path with low attacker effort; fix soon.
- **Medium-High** — real risk but needs a specific precondition (admin role, specific deployment choice).
- **Medium** — worth fixing, not urgent; often a defense-in-depth or config-default question.
- **Low-Medium** — no security impact, but materially hurts operability (e.g. forensics).
- **Low** — cosmetic, consistency, or minor polish.
