# ADR 0024: Machine API and CLI

## Status

Accepted.

## Context

Phase 6's final slice is a programmatic client so Light IPAM can be driven by
automation (CI, scripts, infrastructure-as-code) rather than only the browser UI. The
roadmap framed it as "Terraform provider **or** CLI". Both need something Light IPAM did
not have: a **machine-authenticated read/write API**. Today the app is a session-cookie
+ CSRF web app — there is no non-browser credential and no JSON endpoints.

After confirming with the user, the chosen form is a **CLI** (not a Terraform provider):
it is lightweight, ships in-repo with the app, adds no large dependency (the Terraform
plugin framework would), and matches the project's stdlib-first ethos. The chosen
auth is **per-user bearer API tokens**.

The constraints hold: the web app stays unprivileged, no agent secret is exposed, and
the existing admin/viewer authorization must apply to the API too.

## Decision

Two parts: an API-token-authenticated JSON API under `/api/v1`, and a `lightipam-cli`
binary that consumes it.

### API tokens (migration 20)

`api_tokens` (id, user_id, name, token_hash, last_used_at, created_at) stores a SHA-256
**hash** of each token — never the plaintext. A token is a high-entropy random string
(`lipam_<random>`), so a fast cryptographic hash (`auth.HashToken`), not a slow password
KDF, is the correct at-rest form: non-reversible and supporting an indexed equality
lookup. The plaintext is shown **once** at creation. Tokens are self-service on the
**Account** page (any signed-in user mints/revokes their own); a token inherits its
owner's role, so a viewer's token is read-only. `AuthenticateAPIToken` resolves a
presented hash to the owning user and refreshes `last_used_at` in one statement.

### JSON API (`/api/v1`)

A small CRUD surface over the IPAM core — subnets, addresses (nested under a subnet for
list/create, flat by id for get/update/delete), and devices — plus `whoami`. Each
handler is wrapped by `apiHandler(write bool, fn)`, which:

- authenticates the `Authorization: Bearer <token>` header (401 on failure), and
- for writes, requires a write-capable (admin) role (403 for a viewer),

then calls the handler with the resolved user. The API is **cookie-free, so it is exempt
from CSRF** (there is no ambient credential to forge); the cookie-based `authorize`
middleware passes API requests through (it only blocks writes when a *session* lacks the
role), and the per-handler check is the real gate. Requests/responses are JSON;
`decodeJSON` bounds the body and rejects unknown fields so a client typo is reported.
Mutations **reuse the existing store methods and validation** (overlap blocking,
containment, the address-state enum) and are **audited** with the token's user as actor
— which means API changes also fan out to change webhooks (ADR 0022), for free. Read is
open to any valid token; only admins can write.

### `lightipam-cli`

A single stdlib-only binary (`cmd/lightipam-cli`). Config from flags or environment
(`LIGHTIPAM_URL`, `LIGHTIPAM_TOKEN`, `LIGHTIPAM_INSECURE`); global flags precede the
command. Verbs: `whoami` and `list`/`get`/`create`/`update`/`delete` for subnets,
addresses, and devices. `create`/`update` build a JSON body from `--field` flags,
including only the flags actually set (so `update` is a partial change) and emitting
integer fields (`--vlan`) as JSON numbers. A non-2xx surfaces the API's JSON `error`
message and a non-zero exit. The flag/body building (`parseFields`) is pure and
unit-tested; the request validators (`subnetReq.toInput`, `addressReq.toInput`) and the
token hash are unit-tested; the full chain (token → CRUD → 401/204) was exercised
end-to-end against the running app. See `docs/API.md`.

## Consequences

- Light IPAM is now scriptable: an operator mints a token on the Account page and uses
  `lightipam-cli` (or any HTTP client) to manage subnets, addresses, and devices. The
  same admin/viewer roles, validation, audit log, and change webhooks apply to API
  traffic as to the UI.
- Migration 20 adds one table; the API reuses existing store methods, so the new
  read/write surface is thin. No new heavyweight dependency, no client JS, no change to
  the unprivileged posture.
- Tokens are sealed-by-hash and shown once; revocation is immediate (delete the row).
  There is no token expiry in this slice (revoke to invalidate) and no rate limiting on
  the API beyond the role gate — both are reasonable later increments.
- A Terraform **provider** can be added later as a separate module against this same
  stable API without touching the app; the CLI doubles as the reference client. This
  completes the Phase 6 slices (policy checks, scan windows, webhooks, NetBox
  import/export, and now the machine API + CLI).
