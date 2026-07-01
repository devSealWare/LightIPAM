<!--
Thanks for contributing to LightIPAM. Keep PRs focused and reviewable — one task per
branch, no drive-by refactors. See CONTRIBUTING.md and AGENTS.md for the working
agreement, and docs/agent/CODE_REVIEW.md for what review will check.
-->

## Summary

<!-- What this changes and why. Link the issue/ADR. -->

## Scope

<!-- The surfaces this PR touches (packages/files/areas). -->

## Non-goals

<!-- What this deliberately does NOT change, to keep scope honest. -->

## Validation

<!-- Tick what you actually ran (docs/agent/VALIDATION.md). Don't tick what you didn't. -->

- [ ] `npm run build:css`
- [ ] `go build ./... && go vet ./...`
- [ ] `go test ./...`
- [ ] `gofmt -l internal cmd` is clean
- [ ] `docker compose build` (and `docker compose --profile scanner build` if the agent changed)

## Docs updated

<!-- Which docs changed (README, docs/SCANNER_*, ADR, CHANGELOG, docs/agent/PROJECT_STATE.md),
     or "none — no behavior/status change". -->

## Security / scanner boundary checklist

- [ ] The web app remains unprivileged.
- [ ] No raw sockets, nmap, packet capture, or network capability were added to the app.
- [ ] Scanner-agent privilege boundaries are unchanged or explicitly justified.
- [ ] App-side and agent-side scan allowlist checks remain intact where relevant.
- [ ] Strict CSP preserved — no inline JS/CSS; generated CSS came from the Tailwind source.
- [ ] No unrelated refactors or dependency additions.

## Screenshots / logs

<!-- For UI changes, before/after. For scanner changes, relevant scan output. -->

## Follow-up issues

<!-- Anything worth doing that is out of scope for this PR. -->
