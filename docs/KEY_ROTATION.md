# Key & Certificate Rotation Runbook

Light IPAM has three classes of cryptographic material. This runbook covers rotating
each. Pairs with `docs/DISASTER_RECOVERY.md`.

| Material | Env / store | Protects | Rotation impact |
| --- | --- | --- | --- |
| App master secret | `APP_SECRET` | session/CSRF tokens; derives the encryption key when `APP_ENCRYPTION_KEY` is unset | invalidates sessions; re-seals secrets if it is the encryption key |
| Encryption key | `APP_ENCRYPTION_KEY` (or derived from `APP_SECRET`) | seals TOTP secrets, the OIDC client secret, the managed-CA key | must re-seal or re-enter sealed secrets |
| Managed CA | `app_ca` (DB, key sealed) | agent/app mTLS | invalidates all issued leaf certs |

## 1. Rotating the app master secret (`APP_SECRET`)

`APP_SECRET` signs/derives session material. If `APP_ENCRYPTION_KEY` is **set**
separately, rotating `APP_SECRET` does **not** touch sealed secrets — it only
invalidates in-flight session/CSRF tokens.

```sh
# Generate a new secret.
openssl rand -base64 32
# Set APP_SECRET in the app environment, then restart.
docker compose up -d app
```

Effect: existing sessions become invalid (users sign in again). No data migration.

> If `APP_ENCRYPTION_KEY` is **unset**, the encryption key is derived from
> `APP_SECRET`, so rotating `APP_SECRET` also rotates the encryption key — follow
> section 2's re-seal steps as well.

## 2. Rotating the encryption key (`APP_ENCRYPTION_KEY`)

The encryption key seals secrets at rest. Rotating it requires **re-sealing** the
secrets it protects, because old ciphertext cannot be opened with the new key.

Recommended procedure (no plaintext on disk):

1. Set a new `APP_ENCRYPTION_KEY` (keep the old value at hand).
2. The managed-CA key, TOTP secrets, and the OIDC client secret were sealed with the
   old key. The simplest supported path is to **re-establish** them under the new key:
   - **Managed CA:** Settings → *Agent certificates* → *Rotate CA*, then re-issue and
     redeploy agent/app bundles.
   - **OIDC client secret:** Settings → *Authentication* → re-enter the client secret
     and save (it is sealed with the new key).
   - **TOTP:** users re-enroll (Settings → *Account* → two-factor), or an admin can
     leave existing enrollments and have affected users re-enroll on next failure.
3. Restart the app.

> Best practice: set a dedicated `APP_ENCRYPTION_KEY` from the start (rather than
> deriving from `APP_SECRET`) so the two can be rotated independently.

## 3. Rotating the managed CA

Use when the CA key is compromised or on a periodic schedule.

1. Settings → **Agent certificates** → **Rotate CA now** (admin only; audited as
   `agent.ca.rotated`). This generates a new CA key and invalidates every previously
   issued leaf.
2. Re-issue bundles from the same tab:
   - *Issue & download agent bundle* → deploy `ca.crt`/`agent.crt`/`agent.key` to each
     agent's certificate volume. The agent **hot-reloads** the new cert (no restart).
   - *Issue & download app bundle* → deploy `ca.crt`/`app.crt`/`app.key` to the app's
     certificate volume and restart the app so dispatch uses the new client cert.
3. Confirm scans still reach agents under `/agents`.

## 4. Rotating leaf certificates (routine)

Leaf certs are short-lived (default 30 days). Before expiry, re-issue from the **Agent
certificates** tab and redeploy; the agent hot-reloads its file without a restart. A
sidecar/cron can automate the re-issue+deploy step.

## Compromise response (fast path)

1. Force-revoke sessions: Settings → *Security* → *Log out everywhere* (and reset
   affected user passwords from *Users & Roles*).
2. Rotate the managed CA (section 3) and redeploy certs.
3. Rotate `APP_SECRET` / `APP_ENCRYPTION_KEY` (sections 1–2).
4. Review the audit log for the relevant events.
