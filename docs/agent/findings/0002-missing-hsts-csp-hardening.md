# 0002 — Missing HSTS header; CSP missing `base-uri`/`object-src`

- **Priority:** Medium-High
- **Area:** Security
- **Status:** Open — not yet fixed

## Summary

`securityHeaders` sets `Content-Security-Policy`, `Referrer-Policy`,
`X-Content-Type-Options`, and `X-Frame-Options`, but never emits
`Strict-Transport-Security` (HSTS) — not even conditionally when TLS is
terminated. The CSP also omits `base-uri 'self'` and `object-src 'none'`, both
cheap defense-in-depth additions for a strict, no-inline-JS app.

## Affected code

- `internal/app/app.go:1806-1813` — `securityHeaders(next http.Handler)`, the
  middleware wrapping the whole mux (`internal/app/app.go:246`).

Current CSP:
```
default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'
```

## Fix instructions

1. **HSTS:** the app itself doesn't know whether it's behind TLS termination
   (it's often deployed behind a reverse proxy per `docs/SECURITY.md`). Two
   options, pick based on maintainer input:
   - Emit `Strict-Transport-Security: max-age=31536000; includeSubDomains` only
     when the request arrived over TLS as the proxy reports it (check
     `r.TLS != nil` or a trusted `X-Forwarded-Proto: https`, consistent with how
     `docs/SECURITY.md` already expects a trusted reverse-proxy setup) — do
     **not** trust `X-Forwarded-Proto` unconditionally, since it's spoofable
     unless the proxy strips/overwrites it.
   - Or gate it behind an existing/new config flag (mirroring `CookieSecure` in
     `internal/config/config.go:18`) so operators opt in once TLS is confirmed
     terminated correctly. This avoids sending HSTS to a plaintext-HTTP dev
     deployment, which would be actively wrong.
   - Cross-reference [0003](0003-cookie-secure-tls-guidance.md) — both findings
     touch the same "is this deployment on TLS" question and should probably be
     fixed together.
2. **CSP hardening:** add `base-uri 'self'; object-src 'none'` to the policy
   string at `internal/app/app.go:1808`. Both are safe no-ops for this app (no
   `<base>` tag, no plugins/Flash/Java), so this should not require any
   template changes.
3. Add/update a test asserting the new header values (check for an existing
   headers test near `internal/app/app_test.go` or similar covering
   `securityHeaders`).
4. Update `docs/SECURITY.md` "Product Security Features" list if HSTS becomes a
   documented guarantee (conditional on TLS termination).
