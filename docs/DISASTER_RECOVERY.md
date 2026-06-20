# Disaster Recovery Runbook

How to recover a Light IPAM deployment from loss of the host, the database, or the
secrets. Pairs with `docs/BACKUP_RESTORE.md` (database) and `docs/KEY_ROTATION.md`
(keys/certs).

## What state matters

| State | Where | Backed up by |
| --- | --- | --- |
| Database (all IPAM, users, settings, audit, managed CA) | `pgdata` volume | `pg_dump` backups (Backup & Restore tab) |
| Backups | `backups` volume / `BACKUP_DIR` | copy off-host regularly |
| App master secret | `APP_SECRET` (+ optional `APP_ENCRYPTION_KEY`) | **your** secret store |
| Scanner-agent mTLS material | `deploy/scanner-certs` (or managed-CA issued) | re-issue from the managed CA |

> **Critical:** sealed secrets (TOTP secrets, the OIDC client secret, the managed-CA
> private key) are encrypted with the app key. A database backup is only useful with
> the **matching** `APP_SECRET`/`APP_ENCRYPTION_KEY`. Store the key separately from the
> dumps, and never lose it — losing it means re-enrolling MFA, re-entering the OIDC
> secret, and re-generating the managed CA.

## Scenario A: app container lost, data intact

```sh
docker compose pull        # or rebuild: docker compose build
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/readyz
```

The `pgdata` and `backups` volumes survive container replacement. Embedded migrations
run on boot.

## Scenario B: database lost, restore from backup

1. Ensure `APP_SECRET`/`APP_ENCRYPTION_KEY` match the backup's deployment.
2. Bring up a fresh database and restore:

   ```sh
   docker compose up -d db
   deploy/restore.sh lightipam-YYYYMMDD-HHMMSS-migNN.dump
   docker compose up -d app
   docker compose exec app wget -qO- http://127.0.0.1:8080/readyz
   ```

3. Confirm the applied migration version in `/readyz` is ≥ the dump's `migNN`.

See `docs/BACKUP_RESTORE.md` for the detailed and tested procedure.

## Scenario C: total host loss

1. Provision a new host with Docker + compose.
2. Restore the repo / compose files.
3. Restore `APP_SECRET` (and `APP_ENCRYPTION_KEY`) from your secret store into the
   app environment.
4. Restore the latest off-host `pg_dump` (Scenario B).
5. Re-establish scanner agents:
   - Settings → **Agent certificates** → *Rotate CA* only if the CA key was lost;
     otherwise the restored DB already contains the managed CA.
   - Issue fresh agent + app bundles from the **Agent certificates** tab and deploy
     them to the agent's and app's certificate volumes.
6. Approve agents under `/agents` as needed.

## Scenario D: suspected key/cert compromise

See `docs/KEY_ROTATION.md`. In short: rotate `APP_SECRET`/`APP_ENCRYPTION_KEY` (with
re-seal), rotate the managed CA, re-issue agent/app certs, and force "log out
everywhere" / session revocation.

## Verification checklist

- [ ] `/readyz` returns `ready` with the expected migration version.
- [ ] Admin can sign in (and complete MFA if enabled).
- [ ] Subnets/devices/audit data present.
- [ ] A scan agent reachable from `/agents` (re-issue certs if mTLS fails).
- [ ] A fresh backup can be created from the Backup & Restore tab.
