# Installation and upgrades

LightIPAM supports two Docker Compose paths: published release images for
evaluation and production-style deployments, and local image builds for source
development. Both keep the web app unprivileged; the optional scanner agent is
the only service that receives `NET_RAW`.

## Choose a deployment path

| Goal | Compose file | Image source |
| --- | --- | --- |
| Quick evaluation | `compose.release.yaml` | Published GHCR images |
| Production-style deployment | `compose.release.yaml` | Exact, operator-selected release tag |
| Source development | `compose.yaml` | Built from the local checkout |
| Add discovery | Either file with `--profile scanner` | Matching app and scanner versions |

The current stable release is **v1.2.1**. The release workflow publishes
`ghcr.io/devsealware/lightipam` and
`ghcr.io/devsealware/lightipam-scanner` for amd64 and arm64.

## Prerequisites

- Docker Engine with the Docker Compose plugin, or Docker Desktop.
- A checkout or release archive of this repository. The Compose files also use
  the tracked `deploy/fix-cert-perms.sh` helper and create local scanner-certificate
  and persistent-volume paths.
- A TLS-terminating reverse proxy for any deployment exposed beyond localhost.

## Quick evaluation with published images

Copy the environment example:

```sh
cp .env.example .env
mkdir -p deploy/scanner-certs
```

Creating the certificate directory before Compose starts keeps it owned by the
operator on native Linux. It may remain empty when discovery is disabled.

Generate URL-safe secrets, then paste different values into `POSTGRES_PASSWORD`
and `APP_SECRET` in `.env`:

```sh
openssl rand -hex 32
openssl rand -hex 32
```

Start the app and database:

```sh
docker compose --env-file .env -f compose.release.yaml up -d
docker compose --env-file .env -f compose.release.yaml ps
```

Open <http://localhost:8080> and create the first administrator. To publish a
different host port, set `APP_PORT` in `.env`.

This quick path is intentionally local-only: it serves plain HTTP and defaults
`COOKIE_SECURE` to `false`. Before exposing it on a network, follow the
production steps below.

## Production-style deployment

1. Keep `LIGHTIPAM_VERSION` pinned to the exact stable release you intend to run.
   Do not use `latest` for an unattended production upgrade path.
2. Generate unique `POSTGRES_PASSWORD` and `APP_SECRET` values and store them in
   a secret manager or protected `.env` file. Use URL-safe characters for the
   database password because Compose builds it into `DATABASE_URL`.
3. Optionally set `APP_ENCRYPTION_KEY` to a base64-encoded 32-byte key. If it is
   unset, LightIPAM derives the encryption key from `APP_SECRET`. Preserve the
   selected key with your backups.
4. Terminate TLS with nginx, Caddy, Traefik, or another reverse proxy and set
   `COOKIE_SECURE=true`. See
   [Deploying beyond localhost](SECURITY.md#deploying-beyond-localhost).
5. Start the pinned deployment and verify readiness:

   ```sh
   docker compose --env-file .env -f compose.release.yaml pull
   docker compose --env-file .env -f compose.release.yaml up -d
   docker compose --env-file .env -f compose.release.yaml exec app \
     wget -qO- http://127.0.0.1:8080/readyz
   ```

The `pgdata` and `backups` named volumes persist database state and in-app
backups across container replacement. Copy backups off-host and test the
[restore procedure](BACKUP_RESTORE.md).

## Optional scanner agent

Discovery is opt-in. Before enabling it:

1. Generate or deploy the app and agent mTLS certificates described in
   [Scanner Agent](SCANNER_AGENT.md#mtls).
2. Set `SCANNER_AGENT_ENDPOINT=https://scanner-agent:8443` in `.env` to enable
   bundled-agent auto-enrollment.
3. Replace the safe `AGENT_ALLOWED_CIDRS=127.0.0.1/32` example with only the IPv4
   networks this agent is authorized to scan.
4. Set a real `AGENT_SNMP_COMMUNITY` only if you will use SNMP discovery. It
   remains on the agent and is never sent to the app database.
5. Start the scanner profile:

   ```sh
   docker compose --env-file .env -f compose.release.yaml \
     --profile scanner up -d
   ```

Approve the pending agent under **Agents**, create a subnet, and run a scan.
The agent validates every target against its allowlist independently of the
app. For MAC discovery, routed networks, macvlan, and one-agent-per-VLAN
options, continue with the [scanner deployment guide](SCANNER_AGENT.md).

## Source development

The default Compose file builds from the local checkout:

```sh
docker compose up --build -d
```

Add the scanner to the source-build stack after generating development mTLS
material:

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
docker compose --profile scanner up --build -d
```

The source workflow intentionally retains development defaults. Do not treat
its tracked database credentials or generated application secret behavior as a
production configuration.

## Image tags

For the current stable tag `v1.2.1`, the release workflow publishes:

- `1.2.1` — exact release; recommended for production.
- `1.2` — moving minor-series tag; receives later 1.2.x releases.
- `latest` — moving newest stable release.

Prerelease tags do not move `latest`. App and scanner images should always use
the same version. The default in `compose.release.yaml` changes only through a
reviewed repository update; setting `LIGHTIPAM_VERSION` in `.env` overrides it.

## Upgrade

1. Read the [changelog](../CHANGELOG.md) for migrations and behavior changes.
2. Create and copy off-host a fresh [database backup](BACKUP_RESTORE.md).
3. Change `LIGHTIPAM_VERSION` in `.env` to the new exact release tag without the
   leading `v`.
4. Pull and recreate the services:

   ```sh
   docker compose --env-file .env -f compose.release.yaml pull
   docker compose --env-file .env -f compose.release.yaml up -d
   docker compose --env-file .env -f compose.release.yaml exec app \
     wget -qO- http://127.0.0.1:8080/readyz
   ```

LightIPAM applies additive database migrations at startup. Do not run an older
application image against a database that has already been migrated by a newer
release. See [migration-version compatibility](BACKUP_RESTORE.md#migration-version-compatibility)
before restoring or rolling back.
