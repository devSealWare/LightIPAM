#!/usr/bin/env sh
# Restore a Light IPAM pg_dump (custom format) into the compose "db" service.
#
# Usage: deploy/restore.sh <dump-file>
#
# This OVERWRITES the lightipam database. Stop the app first (the script does not
# stop it for you) and make sure APP_SECRET / APP_ENCRYPTION_KEY match the dump,
# or sealed secrets (TOTP, OIDC client secret) will not decrypt.
set -eu

DUMP="${1:-}"
if [ -z "$DUMP" ] || [ ! -f "$DUMP" ]; then
  echo "usage: $0 <dump-file>" >&2
  exit 1
fi

DB_USER="${POSTGRES_USER:-lightipam}"
DB_NAME="${POSTGRES_DB:-lightipam}"

echo "Restoring $DUMP into database '$DB_NAME' (user '$DB_USER')..."
docker compose exec -T db pg_restore \
  --clean --if-exists --no-owner --no-privileges \
  -U "$DB_USER" -d "$DB_NAME" < "$DUMP"

echo "Restore complete. Start the app: docker compose up -d app"
