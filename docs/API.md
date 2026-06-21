# Machine API & CLI

Light IPAM exposes a small JSON API for automation (CI, scripts, infrastructure-as-code)
and ships a CLI, `lightipam-cli`, that consumes it. See ADR 0024 for the design.

## Authentication

The API authenticates with a **personal API token**, not the session cookie.

1. Sign in and open **Your account** (`/account`).
2. Under **API tokens**, create a token and **copy it immediately** — it is shown once.
3. Send it on every request as `Authorization: Bearer <token>`.

A token carries its owner's role: an **admin** token can read and write; a **viewer**
token is read-only (writes return `403`). Revoke a token from the same page at any time.
Tokens are stored only as a SHA-256 hash; the plaintext is never recoverable.

The API is under `/api/v1` and is cookie-free (so it needs no CSRF token). Reads work
with any valid token; writes require an admin token. Mutations are recorded in the audit
log and trigger change webhooks just like the web UI.

## Endpoints

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/v1/whoami` | any | The token's user, role, and write capability. |
| GET | `/api/v1/subnets` | any | List subnets. |
| POST | `/api/v1/subnets` | admin | Create a subnet (`cidr`, `name`, optional `vlan`, `site_id`, `description`). |
| GET | `/api/v1/subnets/{id}` | any | Get a subnet. |
| PUT | `/api/v1/subnets/{id}` | admin | Update a subnet. |
| DELETE | `/api/v1/subnets/{id}` | admin | Delete a subnet. |
| GET | `/api/v1/subnets/{id}/addresses` | any | List a subnet's addresses. |
| POST | `/api/v1/subnets/{id}/addresses` | admin | Create an address in a subnet (`address`, optional `state`, `hostname`, `device_id`, `notes`). |
| GET | `/api/v1/addresses/{id}` | any | Get an address. |
| PUT | `/api/v1/addresses/{id}` | admin | Update an address. |
| DELETE | `/api/v1/addresses/{id}` | admin | Delete an address. |
| GET | `/api/v1/devices` | any | List devices. |
| POST | `/api/v1/devices` | admin | Create a device (`name`, optional `description`). |
| GET | `/api/v1/devices/{id}` | any | Get a device. |
| PUT | `/api/v1/devices/{id}` | admin | Update a device. |
| DELETE | `/api/v1/devices/{id}` | admin | Delete a device. |

`address` accepts a bare IPv4 host; the containing subnet must already exist. `state` is
`available`/`reserved`/`assigned`/`deprecated`/`conflict` (defaults to `assigned`).
Errors return `{"error": "..."}` with an appropriate status (`400` validation, `401`
no/invalid token, `403` read-only token, `404` not found). A successful `DELETE` returns
`204` with no body.

### curl example

```sh
export TOKEN=lipam_...        # from the Account page
BASE=https://ipam.example.com

curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/subnets"

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"10.20.0.0/24","name":"Lab","vlan":20}' \
  "$BASE/api/v1/subnets"
```

## CLI: `lightipam-cli`

Build it from the repo:

```sh
go build -o lightipam-cli ./cmd/lightipam-cli
```

Configure with flags or environment variables (global flags come **before** the
command):

| Flag | Env | Meaning |
| --- | --- | --- |
| `--url` | `LIGHTIPAM_URL` | Base URL, e.g. `https://ipam.example.com`. |
| `--token` | `LIGHTIPAM_TOKEN` | A personal API token. |
| `--insecure` | `LIGHTIPAM_INSECURE=1` | Skip TLS verification (dev/self-signed certs only). |

### Commands

```sh
export LIGHTIPAM_URL=https://ipam.example.com
export LIGHTIPAM_TOKEN=lipam_...

lightipam-cli whoami

lightipam-cli subnets list
lightipam-cli subnets get <id>
lightipam-cli subnets create --cidr 10.20.0.0/24 --name "Lab" --vlan 20
lightipam-cli subnets update <id> --description "renamed"
lightipam-cli subnets delete <id>

lightipam-cli addresses list <subnet-id>
lightipam-cli addresses create <subnet-id> --address 10.20.0.10 --state assigned --hostname web1
lightipam-cli addresses get <id>
lightipam-cli addresses update <id> --state reserved
lightipam-cli addresses delete <id>

lightipam-cli devices list
lightipam-cli devices create --name sw-core-1 --description "core switch"
lightipam-cli devices update <id> --description "..."
lightipam-cli devices delete <id>
```

`create`/`update` send only the field flags you provide, so `update` is a partial
change. The CLI prints the JSON response and exits non-zero on an API error, printing the
error message to stderr — convenient in scripts and pipelines.
