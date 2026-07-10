# 0004 — Viewers can mint their own (read-only) API tokens

- **Priority:** Medium
- **Area:** Security
- **Status:** Open — not yet fixed

## Summary

`authorize` exempts every `/account/*` path for any signed-in user regardless of
role (`internal/app/authz.go:34`), which includes `POST /account/tokens`
(`internal/app/app.go:238`, handled by `accountTokenCreate` in
`internal/app/account_tokens.go:18`). A read-only **viewer** can therefore mint a
machine API token for themselves.

This is **not** a privilege escalation — `accountTokenCreate` issues a token tied
to the creating user's own role (viewer stays viewer), so the minted token can
only do what the viewer could already do in the UI. But it's worth a conscious
decision: some operators may want token creation restricted to admins as a
matter of policy (e.g. limiting the number of long-lived credentials that can
touch `/api/v1`), and today there's no way to enforce that.

## Affected code

- `internal/app/authz.go:34` — the `/account/` path exemption in the authorize
  middleware.
- `internal/app/app.go:238-239` — `POST /account/tokens`, `POST
  /account/tokens/{id}/delete` route registrations.
- `internal/app/account_tokens.go:18` — `accountTokenCreate`.

## Fix instructions

This needs a maintainer decision first — it's a policy question, not a bug with
one right answer:

1. **If viewers should keep self-service token creation** (arguably fine, since
   it inherits their existing permissions): document this explicitly in
   `docs/SECURITY.md` under "Product Security Features" / RBAC, so it reads as a
   conscious choice rather than an oversight. No code change.
2. **If token creation should be admin-only:** add a role check in
   `accountTokenCreate` (and surface it in the account UI — hide/disable the
   "Create token" form for viewers, not just block the POST) gated on
   `session.User.Role`. Keep token **deletion** self-service either way (a user
   revoking their own token is not a privilege concern). Add a test asserting a
   viewer gets `403` (or the equivalent UI message) from `POST /account/tokens`
   while an admin succeeds — extend `internal/app/authz_test.go` or
   `account_tokens_test.go` if one exists.
3. Either way, update `docs/agent/CODE_REVIEW.md` / `docs/SECURITY.md` RBAC
   notes so the `/account/*` blanket exemption in `authz.go` is documented as
   intentional and its scope (self-service account management, not admin
   actions) is explicit for future reviewers.
