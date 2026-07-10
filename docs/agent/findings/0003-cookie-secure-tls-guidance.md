# 0003 — Cookie `Secure` flag is config-dependent; quick-start leads to plaintext HTTP

- **Priority:** Medium
- **Area:** Security / Docs
- **Status:** Open — not yet fixed

## Summary

Session, CSRF, and OIDC-state cookies only get the `Secure` attribute when
`CookieSecure` is set true (`internal/config/config.go:97`, default `"false"`).
The audited instance served on `http://192.168.0.9:8080` — plaintext HTTP — so
session cookies traversed cleartext. This is partly a deployment choice, but the
README's quick-start ("Open http://localhost:8080") gives no warning that it is
leading the operator into an unencrypted session, and there's no prominent
guidance on putting a TLS-terminating reverse proxy in front for anything beyond
local/loopback use.

## Affected code / docs

- `internal/config/config.go:18,97` — `CookieSecure bool`, default `false`.
- `internal/app/app.go:1364,1395,1407`, `internal/app/mfa.go:42,82`,
  `internal/app/oidc.go:107,239` — every `Secure: a.cfg.CookieSecure` cookie
  write site (session, CSRF, MFA, OIDC state).
- `README.md` quick-start section (the `http://localhost:8080` instruction).
- `docs/SECURITY.md` — already states the app should sit "behind a reverse proxy
  for TLS" conceptually but doesn't call out the cookie/`COOKIE_SECURE` implication.

## Fix instructions

This is primarily a **documentation** fix; the `CookieSecure` config knob itself
is reasonable to keep config-dependent (a bare loopback dev instance legitimately
has no TLS). What's missing is operator guidance, not new code:

1. In `README.md`, right after the quick-start `docker compose up` /
   `http://localhost:8080` instructions, add a clearly-flagged note: sessions are
   sent in cleartext unless you (a) set `COOKIE_SECURE=true` and (b) terminate
   TLS in front of the app (reverse proxy — nginx/Caddy/Traefik example, or the
   OIDC path if applicable). State this **before** the reader deploys off
   localhost, not buried in `docs/SECURITY.md` alone.
2. In `docs/SECURITY.md`, add a short "Deploying beyond localhost" subsection
   under "Container Boundaries" or "Product Security Features" spelling out: set
   `COOKIE_SECURE=true` + put a TLS-terminating proxy in front + (optionally)
   defer to [0002](0002-missing-hsts-csp-hardening.md)'s HSTS work once TLS is
   confirmed.
3. Decide (with the maintainer) whether `COOKIE_SECURE` should default to `true`
   with an explicit opt-out for loopback/dev use, versus keeping the current
   opt-in default with better docs. This is a product decision, not something to
   change silently — flag it, don't just flip the default.
4. No code change is required to close this finding if the maintainer decides
   docs-only is sufficient; if the default changes, that's a separate, small
   follow-up PR (update `internal/config/config.go:97` + a config test +
   CHANGELOG entry, since it changes shipped default behavior).
