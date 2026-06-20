# ADR 0018: Phase 5 Completion — Roles, MFA, SSO, Secrets, Backup, and a Managed CA

## Status

Accepted.

## Context

ADR 0017 delivered the first Phase 5 slice (login throttling/lockout, idle+absolute
session timeouts, a runtime-editable Settings page, and a readiness probe) and
explicitly deferred the rest of Phase 5. This ADR covers the remaining slices that
take Light IPAM to the Phase 5 **exit criteria**: *an operator can stand up Light
IPAM with SSO + MFA, agents that rotate their own certificates, secrets that are
never stored in plaintext, and a tested backup/restore path.* Roles (admin vs.
read-only) are included as the foundational access-control item.

The project constraints are unchanged: the **web app stays unprivileged** (no scanner
capability, raw sockets, or nmap move into it), the strict same-origin CSP is
untouched (no inline JS), store methods live in `internal/store`, handlers in
`internal/app`, settings persist in `app_settings` with env boot defaults, and every
mutation is audited. Pure decision logic is unit-tested in the established style.

## Decision

### Encrypted secrets at rest (`internal/secret`)

A small AES-256-GCM sealer (`secret.Sealer`) seals/opens short secrets as a versioned
URL-safe token. The key is `APP_ENCRYPTION_KEY` (base64, 32 bytes) when set, otherwise
derived from `APP_SECRET` via SHA-256 (`secret.DeriveKey`) so single-secret
deployments still store secrets encrypted. Used for the TOTP secret, the OIDC client
secret, and the managed-CA private key. Nothing sensitive is written or rendered in
plaintext.

### Roles: admin vs. read-only operator (migration 14)

`users.role` (`admin` | `viewer`) is the authoritative authorization field; `is_admin`
is kept in sync for legacy queries. A central `authorize` middleware lets read-only
methods through and rejects any unsafe-method request from a viewer (403), except the
auth allowlist (`/login`, `/logout`, `/bootstrap`) and self-service `/account/*`. The
whole Settings area is admin-only (`requireAdmin`, hidden from the viewer nav). A new
**Users & Roles** settings tab creates users, changes roles, resets passwords, and
deletes accounts, with last-admin and self-delete guards. `canWrite` and the path
predicates are pure + tested.

### MFA — TOTP with recovery codes (migration 15)

RFC 6238 TOTP implemented on the standard library (HMAC-SHA1), verified against the
RFC test vector, with ±1 window skew and constant-time comparison. `user_totp` stores
the per-user secret **sealed**; `user_recovery_codes` stores SHA-256 hashes of
single-use recovery codes. Login becomes two-step when MFA is enabled: after the
password verifies, a short-lived **sealed** pending-MFA cookie carries the user id and
the user is sent to `/login/mfa`; only a valid TOTP (or recovery) code establishes the
session. A self-service `/account` area (available to every role) handles enrollment
(QR via `go-qrcode` + manual key), one-time recovery-code display, disable-with-code,
password change, and the user's own active-session review.

### OIDC SSO — authorization-code + PKCE (migration 16)

Optional SSO via `go-oidc` + `oauth2`: state, PKCE verifier, and nonce live in a sealed
short-lived cookie; the ID token and nonce are verified. `users.oidc_subject` binds an
IdP identity to a local user; login resolves by subject, then by username (linking the
subject), then optionally auto-provisions a **read-only viewer**. The admin
**Authentication** settings tab edits issuer/client-id/base-url/username-claim/
auto-provision; the **client secret is sealed** and never re-displayed. SSO users have
no usable password and authenticate entirely through the IdP (which owns their MFA).
Form parsing and claim→username mapping are pure + tested.

### Backup & restore (`internal/backup`)

On-demand `pg_dump -Fc` snapshots written to `BACKUP_DIR`. The filename encodes the
time and the **schema-migration version** and is the traversal guard for
download/delete (a strict regex). The admin **Backup & Restore** tab creates, lists,
downloads, and deletes backups. The app image bundles `postgresql16-client` and compose
mounts a persisted `backups` volume — `pg_dump` is an ordinary DB client, so the app
keeps **zero Linux capabilities**. Restore is documented and scripted
(`docs/BACKUP_RESTORE.md`, `deploy/restore.sh`); embedded migrations roll an older dump
forward on boot. Name build/parse + the traversal guard are pure + tested.

### Managed agent-certificate CA (migration 17)

The app owns a CA (`pki.CA`) whose private key is **sealed at rest** (`app_ca`),
generated on first boot, replacing the hand-run dev CA (`cmd/scanner-certs`) as the
issuing authority. It signs short-lived mTLS leaves and supports **stable-key
rotation** of leaves (re-issued certs keep chaining to the same root). The admin
**Agent certificates** tab shows the CA fingerprint/expiry, issues downloadable agent
and app cert bundles (zip) with configurable CN/SANs/TTL, downloads the CA cert, and
rotates the CA (with an explicit blast-radius warning). The scanner agent gains a
**hot-reloading certificate** (`agent.CertReloader` + a file watcher) so a rotated cert
is applied without a restart. Issuance/rotation/renewal helpers are pure + tested
(leaves verified against the CA).

Revocation relies on **short TTLs** (the roadmap's accepted alternative to a CRL):
re-issue before expiry, and a compromised CA is replaced via CA rotation.

## Consequences

- The Phase 5 exit criteria are met: SSO + MFA, agents that pick up rotated certs
  without a restart, secrets sealed at rest, and a tested backup/restore path, on top
  of admin/viewer roles.
- Three well-scoped dependencies are added — `go-oidc`/`oauth2` (SSO), `go-qrcode` (MFA
  enrollment) — all pure-Go and unprivileged.
- The Settings panel grew the **Users & Roles**, **Authentication**, **Agent
  certificates**, and **Backup & Restore** tabs alongside the existing **Security** tab.
- **Online agent enrollment** (an agent pulling/renewing its own cert from the app over
  a bootstrap channel) is intentionally out of scope: the managed CA issues certs and
  the agent hot-reloads them, but the operator (or a sidecar/cron) deploys the issued
  files. This is the natural next increment and does not block the exit criteria.
- The dev CA generator (`cmd/scanner-certs`) still works for local bootstrap; the
  managed CA is the production issuing authority.

See also: `docs/SETTINGS.md`, `docs/BACKUP_RESTORE.md`, `docs/DISASTER_RECOVERY.md`,
`docs/KEY_ROTATION.md`, and ADR 0017.
