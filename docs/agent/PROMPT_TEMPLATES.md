# Prompt Templates

Reusable prompts for driving agent work on LightIPAM. Copy one, fill the blanks, and
paste it in. Every template forces the same spine — **problem, constraints, non-goals,
acceptance criteria, validation, docs to update** — so the agent starts with enough to
work safely and stops at a verifiable finish line.

Every template inherits the invariants in [`AGENTS.md`](../../AGENTS.md); they are
restated only where a task is especially likely to trip on them.

---

## Bugfix

```text
Fix a bug in LightIPAM.

Problem: <observed behavior> vs <expected behavior>. Repro: <steps / failing input>.
Suspected area: <file/package or "unknown">.

Constraints:
- Smallest safe change; no drive-by refactors. Match surrounding style.
- Keep the app unprivileged and the UI server-rendered (no inline JS/CSS).

Non-goals: <what NOT to change>.

Acceptance criteria:
- A regression test reproduces the bug, then passes with the fix.
- No unrelated behavior changes; existing tests still pass.

Validation: docs/agent/VALIDATION.md Tier 0 (+ Tier 2 if runtime-observable).
Docs to update: only if user-visible behavior changes.

Use the lightipam-bugfix skill.
```

---

## Scanner / networking change

```text
Change LightIPAM scanner/discovery behavior.

Problem: <what discovery/scan behavior to add or fix>.
Affected surface: <nmap | SNMP | NetBIOS/mDNS | DNS | DHCP | LLDP/CDP | scheduling |
diagnostics | mTLS | egress pin/route | allowlist>.

Hard constraints (do not violate):
- The app stays unprivileged; all active discovery stays in scanner-agent. nmap/NET_RAW
  only on the agent.
- Both allowlist checks stay valid: app-side ValidateJobForAgent, agent-side ValidateAgentScope.
- Failures must be explainable to operators; never succeed with a misleading empty result.
- Agent-only secrets (SNMP community, egress pin, DHCP path, allowlist) stay on the agent.

Non-goals: <e.g. no IPv6, no new scan type, no app-side probing>.

Acceptance criteria: <observable behavior> with hermetic unit tests (injected
socket/session/reader — no live network).

Validation: VALIDATION.md Tier 0 + Tier 1 (scanner image) + Tier 2 scanner smoke.
Docs to update: docs/SCANNER_*, README limitations, and an ADR if behavior/decision changes.

Use the lightipam-scanner-change skill.
```

---

## Docs sync

```text
Reconcile LightIPAM documentation after a status change.

Trigger: <feature X shipped | plan Y changed | ADR Z merged>.

Task: make these agree — AGENTS.md, CLAUDE.md, docs/agent/PROJECT_STATE.md, README.md,
CHANGELOG.md, docs/ROADMAP.md, the relevant ADR, and docs/SCANNER_*/SECURITY.md.

Constraints: no file says "planned" while another says "shipped"; keep agent docs
compact; do not duplicate release history into agent files (point to CHANGELOG).

Acceptance criteria: a single consistent state; PROJECT_STATE reflects reality.
Validation: none required (docs only) unless examples/commands changed.

Use the lightipam-doc-sync skill.
```

---

## PR review

```text
Review a LightIPAM PR (review only — do not edit unless asked).

Target: <PR number / branch / diff>.

Task: work docs/agent/CODE_REVIEW.md top to bottom. Summarize the PR, list changed
surfaces, and check every invariant (app-unprivileged, scanner boundary, sparse
storage, CSP/no-inline-JS, migrations additive, tests, docs consistency, dependencies).

Output: findings grouped by severity — blocking, should-fix, nit, follow-up issue —
each with file:line and a concrete failure scenario where relevant.

Use the lightipam-review skill.
```

---

## Release prep

```text
Prepare a LightIPAM release.

Target version: vX.Y.Z (SemVer; major only for a breaking /api/v1, scanner-protocol,
or destructive-migration change).

Task:
- Update CHANGELOG.md (move Unreleased → the version + date; Keep a Changelog format).
- Bump version references: package.json, README image tags/pull examples.
- Confirm docs/agent/PROJECT_STATE.md and docs/ROADMAP.md reflect what shipped.
- Validate builds (VALIDATION.md Tier 0 + Tier 1); confirm app/scanner image naming.

Constraints: no product code changes unless explicitly requested. The release workflow
publishes on the pushed v* tag — do not publish images by hand.

Acceptance criteria: a clean release PR; the tag push builds and publishes cleanly.

Use the lightipam-release-prep skill.
```
