# ADR 0022: Change Webhooks

## Status

Accepted.

## Context

Light IPAM records every mutation in an immutable audit log, but that log is only
visible inside the app. Operators want changes pushed *out* — to a chat channel, a
SIEM, a ticketing system, or an automation runner — when something notable happens: a
new conflict is discovered, a scheduled scan fails, a subnet is edited. This is the
third slice of **Phase 6 (Advanced Automation)** and the roadmap's "change webhooks"
item, and it follows the slice (a)/(b) template: pure, unit-tested decision functions,
the runtime settings pattern, full server-side rendering, and no new privilege.

The web app stays unprivileged. Webhooks are an app-side feature: they hold no agent
secrets and add no socket or capability. The only secret involved is the per-webhook
HMAC signing key, which is sealed at rest with the app encryption key
(`internal/secret`), exactly like the OIDC client secret and the managed-CA key.

## Decision

An admin registers outbound **webhook** endpoints on a new **Notifications** settings
tab. When a matching change is audited, the app POSTs a JSON payload to each enabled,
subscribed endpoint; if the webhook has a signing secret, the request carries an
`X-LightIPAM-Signature: sha256=<hmac>` of the body.

### The audit log is the change feed

Rather than instrument every handler, the dispatcher hangs off a single chokepoint:
`store.CreateAuditLog`. Every IPAM edit and every scan-lifecycle event already funnels
through it (from the app handlers *and* the orchestrator), so one hook captures the
whole change surface. `Store` gained an optional `AuditHook` invoked after each
successful insert; it is registered on both store instances (the app's and the
orchestrator's) at startup. The hook is guarded by a mutex because the scheduler
goroutine can write audit entries before the hook is registered.

`internal/webhook.categoryForAction` (pure, unit-tested) maps an audit action to one of
four subscribable **categories** — `ipam` (subnet/address/device/MAC changes),
`discovery` (scan findings recorded/imported/conflicting), `scan` (job + schedule +
agent lifecycle), and `security` (settings/users/sessions, plus failed-login and
lockout events). Read-only actions (CSV exports) and routine/successful auth events are
deliberately **not** delivered, keeping the change and security-alert feeds meaningful.
A webhook subscribes to a subset of categories; an empty set means "all".

### Asynchronous, bounded, observable delivery

`webhook.Dispatcher.Deliver` runs in its own goroutine with a fresh context, so it
never blocks the request that produced the audit entry and survives the request's
cancellation. A cached atomic gate (`Active()`, refreshed at startup and on every
webhook CRUD) makes the hook a no-op when no webhook is enabled, so the common case
adds nothing to the hot path. Each attempt is recorded in `webhook_deliveries` (HTTP
status or transport error), pruned to the last 20 per webhook so the table stays
bounded; the Notifications tab shows the recent log. The HTTP client has a 10s timeout;
a non-2xx response or transport error is a recorded failure (no automatic retry in this
slice — the delivery log makes failures visible, and a "Send test" button lets an admin
re-check an endpoint on demand).

### Payload and signature

The body is the marshaled `Event` (`event`, `category`, `subject_type`, `subject_id`,
`actor_user_id`, the audit `metadata` as a nested object, `instance`, `timestamp`).
Headers carry `X-LightIPAM-Event`, `X-LightIPAM-Category`, `X-LightIPAM-Timestamp`, and
— when signed — `X-LightIPAM-Signature: sha256=<hex HMAC-SHA256 of the raw body>`. The
receiver verifies authenticity by recomputing the HMAC with the shared secret. The
signing helper is unit-tested against the canonical HMAC-SHA256 vector, and an
httptest-backed test asserts the real POST, headers, signature, and body.

### Schema (migration 19)

Two tables: `webhooks` (`id`, `name`, `url`, `secret_sealed`, `events text[]`,
`enabled`, timestamps) and `webhook_deliveries` (`webhook_id`, `event_type`, `status`,
`status_code`, `error`, `created_at`, indexed by webhook + time). The signing secret is
stored **sealed**; the form never echoes it, and an update with a blank secret field
keeps the stored value (the OIDC-secret precedent).

### Settings tab

A new admin-only **Notifications** tab (`GET/POST /settings/notifications`, with
per-webhook update/test/delete routes) lists webhooks with an inline edit form, an
event-category picker (shared `webhook_events` template partial), a "Send test" button,
and the recent delivery log. A pure `parseWebhookForm` validator (name required, URL
must be `http(s)://` with a host, categories validated, secret returned separately for
sealing) is unit-tested. Create/update/delete/test are audited
(`settings.notifications.*`). This is app configuration, so it lives in the panel — no
agent secret crosses the boundary.

## Consequences

- Changes flow out of Light IPAM to any HTTP endpoint, signed and observable, with the
  operator choosing which categories matter. The audit-log chokepoint means new audited
  actions are covered automatically, with `categoryForAction` deciding their category.
- One small, mutex-guarded hook on the store; no per-handler instrumentation. The
  active-webhook gate keeps the change feed free when no webhook is configured.
- The signing secret is sealed at rest; no agent capability or secret is exposed. The
  web app stays unprivileged.
- No automatic retry and an at-most-once, best-effort delivery model (with a visible
  log and manual test) is the accepted trade-off for this slice; a durable retry queue
  could be added later behind the same dispatcher without changing the event model.
- Establishes the outbound-integration pattern for the remaining Phase 6 slices; the
  next slice is NetBox-compatible import/export (ADR 0023), then a Terraform
  provider/CLI.
