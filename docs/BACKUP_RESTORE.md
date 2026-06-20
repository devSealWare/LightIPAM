# Backup & Restore

Light IPAM takes logical PostgreSQL backups with `pg_dump` (custom format) and
restores them with `pg_restore`. The web app stays unprivileged: `pg_dump`/
`pg_restore` are ordinary database clients over TCP — no raw sockets, no extra
Linux capabilities.

## What is backed up

A backup is a single `pg_dump -Fc` (custom-format) file of the whole `lightipam`
database: subnets, addresses, devices, MACs, users (including hashed passwords,
sealed TOTP secrets, and OIDC subject links), sessions, audit logs, scan
agents/jobs/discoveries, and `app_settings`. The filename encodes the time and
the **schema-migration version** the dump was taken at, e.g.

```
lightipam-20260619-143005-mig16.dump
```

> Secrets at rest (TOTP secrets, the OIDC client secret) are sealed with the
> app's encryption key (`APP_ENCRYPTION_KEY`, or derived from `APP_SECRET`). A
> backup is therefore only restorable into an app configured with the **same**
> key. Back up your `APP_SECRET`/`APP_ENCRYPTION_KEY` alongside your dumps.

## Creating a backup

- **From the UI:** Settings → **Backup & Restore** → *Create backup now*
  (admin only). Backups are listed with size and migration version; download or
  delete them there.
- **Location:** the `BACKUP_DIR` directory (compose: the persisted `backups`
  named volume at `/var/lib/lightipam/backups`).
- **Manually / on a schedule** (e.g. cron on the host):

  ```sh
  docker compose exec -T db \
    pg_dump -Fc --no-owner --no-privileges -U lightipam lightipam \
    > "lightipam-$(date -u +%Y%m%d-%H%M%S).dump"
  ```

## Restoring

Restoring overwrites data. Do it into a fresh/empty database or a maintenance
window with the app stopped.

1. **Stop the app** so nothing writes during the restore:

   ```sh
   docker compose stop app
   ```

2. **Restore the dump** into the database. With the compose stack and a dump on
   the host:

   ```sh
   # Drop & recreate the schema objects from the dump, then load data.
   cat lightipam-20260619-143005-mig16.dump | \
     docker compose exec -T db \
     pg_restore --clean --if-exists --no-owner --no-privileges \
       -U lightipam -d lightipam
   ```

   `deploy/restore.sh <dump-file>` wraps this for the compose stack.

3. **Start the app.** On boot it runs embedded migrations, so a dump taken at an
   **older** migration is upgraded forward automatically:

   ```sh
   docker compose start app
   docker compose exec app wget -qO- http://127.0.0.1:8080/readyz
   ```

   `/readyz` reports the applied migration version once the DB is reachable.

### Restoring into a brand-new stack

```sh
docker compose up -d db
deploy/restore.sh lightipam-20260619-143005-mig16.dump
docker compose up -d app
```

## Migration-version compatibility

- Restoring a dump from an **older or equal** schema version is safe — the app
  applies any newer migrations on boot.
- Restoring a dump from a **newer** schema version than the running binary is
  **not** supported; deploy a matching (or newer) app image first. The version
  is in the dump filename and shown in the Backup tab so you can check before
  restoring.

## Tested procedure

The restore path above is the supported one. To verify it end-to-end:

```sh
# 1. Seed some data, then back up.
docker compose exec -T db pg_dump -Fc -U lightipam lightipam > test.dump
# 2. Wipe and restore.
docker compose exec -T db psql -U lightipam -d lightipam -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
cat test.dump | docker compose exec -T db pg_restore --clean --if-exists --no-owner --no-privileges -U lightipam -d lightipam
# 3. Confirm the app is ready and data is present.
docker compose restart app
docker compose exec app wget -qO- http://127.0.0.1:8080/readyz
```

## Disaster recovery

See `docs/DISASTER_RECOVERY.md` for the full runbook covering the compose stack,
volumes (`pgdata`, `backups`), secrets, and scanner-agent certificates.
