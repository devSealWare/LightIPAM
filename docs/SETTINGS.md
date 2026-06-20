# Settings Panel

Light IPAM aims to be highly configurable from the UI, not just from environment
variables. The **Settings** page (sidebar → System → **Settings**) is the home for
that configuration: a tabbed panel where an operator tunes how the product behaves.
Today it ships the **Security**, **Users & Roles**, **Authentication**, **Agent
certificates**, **Backup & Restore**, and **Custom fields** tabs; the remaining tabs
below are planned and tracked here and in `docs/ROADMAP.md`.

## How settings work

- **Storage.** Runtime settings live in the key/value `app_settings` table
  (migration 13). Environment variables provide the **boot defaults**; a stored value
  overrides its default. A missing or invalid key always falls back to the default, so
  the table can never produce an unsafe configuration.
- **Caching.** On startup the app overlays stored values onto the config defaults and
  caches the typed result (e.g. `SecuritySettings`, guarded by an `RWMutex`). Reads on
  hot paths use the cache; a save refreshes it so changes apply immediately.
- **Validation.** Each tab's form is parsed by a **pure, unit-tested** function
  (e.g. `parseSecuritySettingsForm`) that range-checks every field before anything is
  written. Saves are audited (`settings.<tab>.updated`).
- **No client framework.** Tabs are server-rendered links (progressive enhancement,
  strict same-origin CSP, no inline JS), matching the rest of the app.

### Adding a tab

1. Add a route `GET/POST /settings/<tab>` and a handler that renders `settings.html`
   with `ActiveTab: "<tab>"`.
2. Add the tab's typed settings + a pure `parse…Form` validator (with a test), and —
   if the values are runtime-tunable — persist them in `app_settings` and cache them
   like `SecuritySettings`.
3. Add a tab link to the `settings.html` tab bar and a sidebar nav entry if needed.
4. Audit the update and document the tab in this file + `docs/ROADMAP.md`.

## Security boundary (important)

The Settings panel configures the **app**. It must never become a backdoor for the
elevated scanner agent:

- **Agent-local secrets and raw-socket configuration stay on the agent**, never in the
  app database or the Settings UI. This includes SNMP read communities
  (`AGENT_SNMP_*`), nmap egress pinning (`AGENT_SCAN_SOURCE_IP` / `AGENT_SCAN_INTERFACE`),
  the DHCP lease-file path (`AGENT_DHCP_LEASE_FILE`), DNS resolver, and the agent's
  allowlist (`AGENT_ALLOWED_CIDRS`). The agent's local allowlist cannot be widened by
  the app UI alone (see `docs/SECURITY.md`).
- The app's **Scanning** tab therefore holds only **dispatch-time defaults** for jobs
  the app sends over mTLS (default scan type/mode, timeouts, rate cap, default
  targets) — not the agent's nmap/SNMP/DHCP credentials or capabilities.
- App-managed **secrets** that do belong in settings (e.g. a future OIDC client
  secret) must be **encrypted at rest** (Phase 5), never stored or rendered in
  plaintext.

## Tabs

| Tab | Configures | Scope | Status |
| --- | --- | --- | --- |
| **Security** | Login lockout (max attempts, window, lockout duration), session idle + absolute timeouts, and the "log out everywhere" behavior (keep this device vs. sign out all). Active-session review + revoke live here too. Future: minimum password length, secure-cookie enforcement, MFA/OIDC toggles. | App | **Done** (ADR 0017) |
| **Users & Roles** | Manage local accounts; admin vs. read-only operator so a viewer cannot mutate IPAM or scan config; reset passwords; last-admin/self-delete guards. | App | **Done** (ADR 0018) |
| **Authentication** | OIDC SSO (issuer, client id; **client secret sealed at rest**), auto-provision policy, username claim. MFA (TOTP) enrollment + recovery codes live on the per-user **Account** page. | App (secrets encrypted at rest) | **Done** (ADR 0018) |
| **Agent certificates** | Managed CA status (fingerprint/expiry), issue downloadable agent/app mTLS bundles (CN/SANs/TTL), download the CA, and rotate the CA. Replaces the dev CA; agents hot-reload rotated certs. | App (mTLS/cert lifecycle) | **Done** (ADR 0018) |
| **Backup & Restore** | On-demand `pg_dump` (custom format) capturing the schema-migration version; list/download/delete; documented + scripted restore. | App | **Done** (ADR 0018) |
| **Custom fields** | Define operator-managed text attributes per entity type (subnet/address/device); values are edited on each record's form and shown on its detail page. Unique per type; delete cascades to stored values. | App | **Done** (ADR 0019) |
| **General** | Instance/display name, default site, table page size, date/time format, default theme (light/dark). | App | Planned |
| **Scanning (nmap)** | App-side scan **dispatch defaults**: default scan type (Combined) and nmap depth mode (Light/Standard/Deep), per-type timeout defaults, optional rate/timing cap passed to nmap, default targets/allowlist hints, and the scheduler tick. **Agent-local** nmap/SNMP/DHCP credentials and raw-socket config stay on the agent. | App (dispatch defaults only) | Planned |
| **Discovery** | Auto-import policy for trusted agents, reconciliation/conflict handling, and review-queue + last-seen retention/aging (when to mark a record stale). | App | Planned |
| **Notifications** | Change webhooks and alert thresholds (e.g. new conflict, stale record, failed scan). | App | Planned (Phase 6) |
| **Data & Audit** | Audit-log retention/export and the CSV / NetBox import-export entry points. | App | Partial (import/export exists) |

> Per-user **Account** (`/account`, all roles): password change, two-factor (TOTP)
> enrollment with recovery codes, and the user's own active-session review. This is
> self-service and not part of the admin-only Settings area.

This list is the working plan, not a contract; tabs may be split, merged, or
re-sequenced as the phases land. The guiding principle is that anything an operator
might reasonably want to change should be changeable here — within the security
boundary above.
