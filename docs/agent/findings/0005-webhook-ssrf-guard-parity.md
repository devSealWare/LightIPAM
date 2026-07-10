# 0005 — Webhook dispatcher may lack the agent-endpoint SSRF guard

- **Priority:** Medium-High
- **Area:** Security
- **Status:** Open — needs verification, then a fix if confirmed

## Summary

Two admin-only surfaces make server-initiated outbound HTTP requests to
admin-supplied URLs: the scanner-agent endpoint (`ValidateAgentEndpoint`,
`internal/scanner/endpoint.go`) and the webhook "Payload URL"
(`internal/webhook/webhook.go`). The agent path already rejects loopback,
link-local, and unspecified literal IPs before connecting (fixed under PR #82,
"resolve CodeQL alerts... agent-endpoint SSRF"). **The webhook dispatcher does
not appear to have an equivalent guard** — `send()` builds the request directly
from `wh.URL` with no validation visible in `internal/webhook/webhook.go`.

If confirmed, a compromised or careless admin (or an admin account created via
[0004](0004-viewer-token-minting.md)'s policy gap, if that one stays permissive)
could register a webhook pointed at `http://169.254.169.254/...` (cloud instance
metadata) or an internal-only service, and LightIPAM would dutifully POST an
HMAC-signed payload there on every matching audit event — an SSRF oracle with a
predictable trigger.

## Affected code

- `internal/webhook/webhook.go:149-263` — `Dispatcher`, `send()` (builds and
  executes the outbound `http.NewRequestWithContext` / `d.client.Do(req)` at
  lines ~232-249). No URL-scheme/IP check visible in this range.
- Compare against the existing guard: `internal/scanner/endpoint.go` —
  `ValidateAgentEndpoint`, which rejects non-`https`, empty host, and literal
  loopback/link-local/unspecified IPs before the agent dispatcher ever connects.
- Wherever a webhook's `URL` is set/validated on create/update (likely
  `internal/app/api.go` or an admin-settings handler — locate the
  webhook-create/update handler and confirm whether it calls any URL validator
  today).

## Fix instructions

1. **First, verify** whether there's already a guard elsewhere in the webhook
   create/update path (e.g. a validator called before `store.CreateWebhook`) that
   this review missed — grep for any existing URL validation before assuming
   none exists.
2. If none exists, extract the IP-literal check from
   `scanner.ValidateAgentEndpoint` into a small shared helper (e.g.
   `internal/netguard` or similar — check whether a shared package makes sense,
   given both `internal/scanner` and `internal/webhook` need it, or duplicate the
   ~10-line pure function if a new shared package is overkill; either is
   reasonable, but don't create a heavy new abstraction for two call sites).
3. Apply the same rules used for agent endpoints: require `https://` (webhooks
   carry an HMAC-signed payload but plaintext HTTP still leaks its content and
   is a downgrade vector), require a host, reject literal
   loopback/link-local/unspecified IPs. Do **not** attempt DNS-based SSRF
   protection (resolving and re-checking on every delivery) — match the existing
   agent guard's scope and stated tradeoff (literal-IP rejection only, no live
   DNS dependency) unless the maintainer wants to go further.
4. Apply the validator both at webhook create/update time (reject early, like
   the agent endpoint) and confirm `TestDeliver`
   (`internal/webhook/webhook.go:274`) goes through the same validated path.
5. Add a unit test mirroring the agent-endpoint SSRF tests
   (`internal/scanner/endpoint_test.go` if present) for the webhook validator:
   reject `http://169.254.169.254/...`, `https://127.0.0.1/...`, accept a normal
   `https://example.internal/hook`.
6. Update `docs/SECURITY.md` "Agent Trust" or a new "Webhook egress" note once
   fixed, so the two SSRF guards are documented as a matched pair.
