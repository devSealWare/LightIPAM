# ADR 0017: Authentication and Session Hardening

## Status

Accepted.

## Context

Phases 1–4 (+4.5) delivered the IPAM and discovery feature set on top of a minimal
local-auth foundation: a single bootstrapped admin, Argon2id password hashing,
server-side sessions with a CSRF token, and a 12-hour absolute session expiry. That
foundation is sound but thin against an attacker who can reach the login page. Three
gaps stand out, and they are the first slice of **Phase 5 (Production Hardening)**:

- **No brute-force protection.** `loginSubmit` verified credentials on every request
  with no rate limit or lockout, so an attacker could try passwords as fast as the
  Argon2 cost allowed.
- **A username-enumeration timing oracle.** When the username did not exist, the
  handler returned immediately; when it existed but the password was wrong, it paid
  the Argon2 verification cost. The response-time difference revealed which usernames
  are real.
- **Coarse sessions.** Only an absolute timeout existed — no idle timeout, no record
  of where a session came from, and no way for an operator to see or revoke active
  sessions if a laptop was lost or a token leaked.

This ADR covers only authentication and session hardening. MFA (TOTP), OIDC SSO, and
roles beyond the single admin are separate Phase 5 slices and are intentionally **out
of scope** here. The project constraints are unchanged: the web app stays
unprivileged (no scanner capability moves into it), the strict same-origin CSP is
untouched (no new inline JS — this work adds no client JS at all), store methods live
in `internal/store`, handlers in `internal/app`, and every mutation is audited.

## Decision

### Login throttling + account lockout

- **Migration 12 adds `login_attempts`**, one row per failed local login keyed by
  both the attempted `username` and the client `ip`, with `created_at`. Indexed on
  `(username, created_at)` and `(ip, created_at)`.
- **`evaluateLockout` is a pure, unit-tested function** (`internal/app/lockout.go`,
  mirroring `parseBulkRequest` / `parseScanResult`). It takes the recent-failure
  counts for the username and IP, the policy, and the current time, and returns
  whether the login is locked and for how long. A login locks when **either** the
  username or the IP reaches `LoginMaxAttempts` failures within `LoginWindow`, and
  stays locked until `LoginLockout` has elapsed since the most recent failure; the
  more restrictive of the two keys wins. Evaluating the two keys separately means a
  brute force against one account and a flood from one source are each caught without
  diluting the other. Once the cooldown passes the lock clears even before the
  failures age out of the window.
- **The store query counts both keys in one round trip** (`RecentLoginFailures`,
  using `count(*) FILTER (WHERE …)`), the handler records a failure on every wrong
  attempt (`RecordLoginFailure`), and a **successful login clears that username's
  failures** (`ClearLoginFailures`).
- **Generic message, no enumeration.** A locked attempt returns HTTP 429 with "Too
  many failed attempts. Please try again later." — it never reveals whether the
  username exists or how many attempts remain.
- **Timing-oracle fix.** When the username is not found, the handler now runs
  `auth.VerifyDecoy(password)`, an Argon2 verification against a fixed decoy hash
  (computed once at startup from a random secret with the standard parameters, so it
  never matches input), discarding the result. The not-found path now performs the
  same Argon2 work as the wrong-password path, so response time no longer
  distinguishes them.
- **Thresholds are configurable** in `internal/config` with safe defaults:
  `LOGIN_MAX_ATTEMPTS` (5), `LOGIN_ATTEMPT_WINDOW` (15m), `LOGIN_LOCKOUT` (15m). The
  window is kept ≥ the lockout so the lock is fully enforced before counted failures
  age out.

### Session hardening

- **Idle timeout in addition to absolute.** Migration 12 adds `sessions.last_seen_at`
  (plus `client_ip` and `user_agent`). `GetSession` now refreshes `last_seen_at` and
  enforces both bounds in **one atomic statement** (a CTE that `UPDATE … RETURNING`s
  only when `expires_at > now()` and `last_seen_at > idleCutoff`, then joins the
  user), so each request slides the idle window forward. Both timeouts are
  configurable: `SESSION_ABSOLUTE_TIMEOUT` (12h, unchanged default) and
  `SESSION_IDLE_TIMEOUT` (30m). A non-positive idle value disables the idle check.
- **Origin capture.** Session creation records the client IP and User-Agent. The IP
  is the real TCP peer (`RemoteAddr`), deliberately **not** a spoofable
  `X-Forwarded-For` header — the same value keys the login throttle, so trusting a
  client header would let an attacker rotate it to evade the IP lock. A deployment
  behind a trusted reverse proxy should terminate it so `RemoteAddr` reflects the
  client.
- **Settings page → Security tab** (`GET /settings/security`, a "Settings" sidebar
  link under System; `GET /settings` redirects to it) lists the user's active
  sessions — signed-in time, last seen, IP, User-Agent, and a "This device" marker —
  and offers **"Log out everywhere"** (`POST /settings/security/logout-all`),
  CSRF-protected (session token) and audited. The page is built as a **tab layout**
  (one tab today, room for more) so future settings live alongside it.

### Runtime-editable policy

- The auth/session knobs above are **no longer env-only**. The Security tab exposes a
  form to edit max attempts, attempt window, lockout duration, idle timeout, absolute
  timeout, **and** the "log out everywhere" behavior. Values persist in a key/value
  `app_settings` table (migration 13) and are validated by a pure, unit-tested
  `parseSecuritySettingsForm`; an update is audited (`settings.security.updated`).
- **Env values become boot defaults, not the ceiling.** On startup the app overlays
  any stored settings onto the config defaults and caches the result
  (`SecuritySettings`, guarded by an `RWMutex`); the login throttle, idle cutoff, and
  session-creation timeout read the cached value, and a save refreshes it so changes
  apply immediately. A missing/invalid stored key falls back to its default, so the
  table can never produce an unsafe policy.
- **"Log out everywhere" is configurable** (`LogoutEverywhereKeepsCurrent`, default
  off): off revokes every session including the current one and redirects to login;
  on revokes only the user's *other* sessions (`DeleteOtherUserSessions`) and keeps
  the current device signed in.

### Deeper readiness

- **`GET /healthz` stays the liveness probe** (static OK). **`GET /readyz` is added**
  as the readiness probe: it `pool.Ping`s the database and reports the applied
  migration version (`{"status":"ready","database":"up","migration":12}`), returning
  **503** when the database is unreachable. The app compose service gains a
  `healthcheck` that hits `/readyz`, so orchestration only routes traffic once the app
  can serve it.

### Audit

- New audited events via the existing `CreateAuditLog` path: **`auth.login.failed`**
  (with the client IP, and the user id when the username exists), **`auth.login.locked`**
  (IP + retry-after), and **`session.revoked_all`** (count revoked). A small
  `auditMeta` helper JSON-encodes the structured metadata. The existing `auth.login`
  / `auth.logout` events are unchanged.

## Consequences

- Online password guessing is bounded: after a handful of failures an attacker (by
  username or by source IP) is locked out, and the response no longer leaks which
  usernames exist.
- A leaked or forgotten session is recoverable — it now expires on idle, and an
  operator can see and revoke sessions from the Settings → Security tab.
- An admin can tune lockout/timeout policy and the "log out everywhere" behavior from
  the UI without redeploying; env still seeds the boot defaults. The cache is
  per-instance (fine for the single-instance compose deployment; a save in one
  instance would not refresh another instance's cache until restart — documented).
- The Security tab is the **seed of a broader Settings panel** — the `app_settings`
  store, the cached-typed-settings pattern, and the pure form validator are meant to be
  reused by future tabs (General, Users & Roles, Authentication, Scanning, Discovery,
  Agents, Backup, Notifications). The full plan and the agent-secret boundary it must
  respect are in `docs/SETTINGS.md` and `docs/ROADMAP.md`.
- Orchestration gets a true readiness signal that distinguishes "process up" from
  "can serve requests," including the schema version it is serving.
- No new heavyweight dependency, no client JavaScript, the CSP is unchanged, and the
  web app remains unprivileged. Throttle/timeout values are env-tunable with secure
  defaults.
- **Trade-offs / non-goals:** the throttle is per-app-instance state in Postgres
  (fine for the single-instance compose deployment; a multi-instance deployment
  shares the table, which still works since the store is shared). Lockout keyed on
  the TCP peer IP is weaker behind a misconfigured proxy that collapses clients to one
  address — documented. Distributed/credential-stuffing attacks from many IPs against
  many usernames are only partially mitigated; MFA (a later Phase 5 slice) is the
  real answer. Audit rows are written for locked attempts, which is intentional
  (brute-force visibility) and cheap (the locked path skips Argon2).
