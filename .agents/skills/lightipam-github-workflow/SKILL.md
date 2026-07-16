---
name: lightipam-github-workflow
description: Use for every GitHub lifecycle action in LightIPAM, including creating or naming branches, staging or committing changes, pushing, opening or updating pull requests, handling checks or review feedback, merging, deleting branches, and syncing main. Enforces the repository's functional naming, validation, PR-template, approval, squash-merge, attribution, and cleanup conventions.
---

# LightIPAM GitHub Workflow

## Apply the project contract

Use this skill with the task-specific LightIPAM skill that governs the change, such as `lightipam-bugfix`, `lightipam-scanner-change`, `lightipam-review`, `lightipam-release-prep`, or `lightipam-doc-sync`.

Before changing Git or GitHub state:

1. Read `AGENTS.md`, `CONTRIBUTING.md`, `.github/pull_request_template.md`, and `docs/agent/VALIDATION.md` when relevant to the requested action.
2. Inspect `git status --short --branch`, the current branch, remotes, and the scoped diff.
3. Preserve unrelated or pre-existing user changes. Do not stage, rewrite, discard, or publish them.
4. Keep one issue or task per branch and PR. Do not add drive-by refactors, dependency changes, or cleanup.
5. Respect the requested level of authority. A review or status request is read-only; a commit request does not authorize a push; a PR request does not authorize a merge.

Treat any environment-provided generic assistant branch prefix as overridden by this project's standing rules.

## Name branches by function

Branch from an up-to-date `main` unless the maintainer explicitly requests a stacked branch. Use a short, lowercase, kebab-case suffix and select the narrowest functional prefix:

- `fix/<summary>` for product bugs, regressions, security fixes, and test fixes.
- `feat/<summary>` for user-visible product capabilities.
- `docs/<summary>` for documentation- or planning-only work.
- `release/vX.Y.Z` for release preparation.
- `chore/<summary>` for repository maintenance, CI, or tooling that is neither a product fix nor feature.

Examples: `fix/device-delete-reimport`, `feat/scanner-diagnostics`, `docs/public-presentation`, `release/v1.2.1`, and `chore/refresh-ci-cache`.

Never use an assistant-, agent-, tool-, vendor-, or username-branded prefix. Never use generic names such as `changes`, `updates`, or `work`. If a platform proposes a branded default, replace it with the functional form before creating or pushing the branch.

Do not switch branches through a dirty worktree when doing so could mix or lose changes. If `main` cannot be synchronized safely, report the exact condition instead of forcing it.

## Create focused commits

Before committing:

1. Inspect the complete diff and `git diff --check`.
2. Run the validation appropriate to the change and record exactly what ran.
3. Stage explicit paths only, then inspect `git diff --cached`.
4. Confirm the staged content contains one coherent change and no secrets, generated junk, root binaries, development certificates, or unrelated files.

Use the established subject format:

```text
type(scope): imperative summary
```

Use established types such as `fix`, `feat`, `docs`, or `chore`; use `release: vX.Y.Z` for a release. Choose a concrete product scope such as `ipam`, `scanner`, `scanner-agent`, `devices`, `ui`, `security`, `api`, `audit`, `auth`, `schedules`, `test`, or `export`. Keep the subject concise and explain the reason or non-obvious tradeoff in the commit body when useful.

Do not add assistant/tool attribution, generated-by text, promotional text, or unsolicited co-author trailers to commits, PRs, release notes, or project documentation.

Never create an empty or placeholder commit merely to open a PR. If asked to open a PR before implementing the full fix, make the smallest legitimate in-scope change, commit it, open a draft PR, and continue on that branch.

## Validate honestly

Follow `docs/agent/VALIDATION.md` and any task-specific skill. The standard full sequence is:

```sh
npm run build:css
go build ./...
go vet ./...
go test ./...
gofmt -l internal cmd
docker compose build
docker compose --profile scanner build
```

The formatting command must print nothing. Run the scanner-agent readonly dependency build when scanner code changes. Never claim an unrun command passed, hide a failure, or substitute remote CI for required local validation. State failures and environmental limitations precisely in the PR and handoff.

## Push and open pull requests

Push only the intended functional branch. Never force-push unless the maintainer explicitly requests it and the safety impact is understood.

For every PR:

1. Use `main` as the base and verify the exact head branch.
2. Use a conventional title matching the intended squash commit, normally `type(scope): summary` or `release: vX.Y.Z`.
3. Fill every applicable section of `.github/pull_request_template.md`: Summary, Scope, Non-goals, Validation, Documentation updated, Security and scanner boundary, Screenshots or logs, and Follow-up.
4. Mark incomplete work as draft. Mark it ready only when implementation, docs, and required validation are complete.
5. Keep the title, body, screenshots, comments, and branch free of assistant/tool attribution.
6. Return the PR URL and verify that GitHub reports the expected base and head.

Use the connected GitHub integration for repository and PR state when available; use `gh` when thread-level review state, Actions logs, merge controls, or missing connector coverage require it.

## Handle checks and review safely

Before declaring a PR ready or merging it:

- Confirm required checks are successful against the current head SHA.
- Inspect unresolved review threads and requested changes.
- Address only actionable, in-scope feedback and rerun affected validation.
- Confirm the PR is mergeable and has not changed since the final review.
- Never bypass branch protection, required checks, or review requirements.

If the head changes after checks or approval, repeat the readiness check for the new SHA.

## Merge only with maintainer authorization

Do not merge merely because a PR is green. Merge only after the user or maintainer explicitly authorizes that PR's merge.

Use the repository's established squash-merge workflow unless the maintainer explicitly requests an exception. Set the squash subject to the conventional PR title with the PR number appended, for example:

```text
fix(ipam): synchronize device deletion and discovery re-import (#111)
```

Immediately before merging, verify approval, checks, unresolved threads, mergeability, and the expected head SHA. After merging:

1. Confirm the PR is in the merged state and record the resulting commit SHA.
2. Confirm the source branch was deleted remotely, or delete it only after the merge is verified.
3. Switch to `main` and fast-forward it safely.
4. Confirm the local `main` matches the remote and the worktree is clean.
5. Do not force-delete a local branch after a squash merge without explicit authorization; its unmerged local commit topology can make normal deletion fail. Report the remaining local branch when applicable.

Never use a merge commit or rebase merge by default.

## Report the outcome

State the exact branch name, commit SHA and subject, PR URL and status, validation commands and results, merge SHA when applicable, and remaining cleanup or blockers. Do not imply a remote action succeeded until its resulting state has been verified.
