# Branch Protection (recommended)

Documentation only. These are the recommended GitHub settings for `main`; a
maintainer applies them in **Settings → Branches → Branch protection rules** (or via
`gh api`). Nothing here is configured from code — an agent must not try to change
repository settings.

## Recommended rule for `main`

- **Require a pull request before merging.** No direct pushes to `main`.
- **Require status checks to pass before merging**, and require branches to be up to
  date first. Select the checks from `.github/workflows/ci.yml` (the Go build/test/vet/
  gofmt job and the app + scanner Docker build jobs).
- **Require conversation resolution before merging** — all review threads resolved.
- **Require at least one approving review**, and (optionally) **require review from a
  code owner / maintainer**. Agents do not approve or merge their own PRs.
- **Block force pushes** to `main`.
- **Block deletions** of `main`.
- Optionally **require linear history** (matches the squash-merge workflow) and
  **require signed commits**.

## Why

- CI as a required check keeps the invariants in `docs/agent/CODE_REVIEW.md`
  mechanically enforced (build, tests, formatting, and that both images still build).
- Requiring a PR + review + resolved conversations matches the working agreement in
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md): branch from `main`, open a PR, wait for
  the maintainer to merge (PRs are squash-merged).
- Publishing images stays gated behind pushing a `v*` tag (`release.yml`), so branch
  protection on `main` never blocks or triggers a release.

## Applying via gh (maintainer, optional)

```sh
# Example only — adjust the required check names to match the CI job names.
gh api -X PUT repos/devSealWare/LightIPAM/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f "required_pull_request_reviews[required_approving_review_count]=1" \
  -F "required_status_checks[strict]=true" \
  -F "enforce_admins=false" \
  -F "restrictions=null"
```
