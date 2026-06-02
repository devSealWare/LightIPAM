# Scanner Agent

The scanner agent is the isolated component that will perform active network
discovery for Light IPAM. It runs as a separate container so the web app can
stay unprivileged. This first version (issue #8) is a **no-op agent**: it
authenticates the app over mTLS and validates scan jobs, but performs no
scanning. Active discovery (Nmap) arrives in a later issue and stays scoped to
this component.

## Responsibilities

- Receive scan jobs from the app over mTLS (`POST /jobs`).
- Verify the app's client certificate identity.
- Validate every job against the agent's registered IPv4 allowlist using
  `scanner.ValidateJobForAgent`.
- Report a result. Today a valid job yields an empty, successful result.

The agent never trusts a job blindly: even if the app submits targets outside
the agent's `AGENT_ALLOWED_CIDRS`, the agent rejects them.

## Endpoints

| Method | Path       | Purpose                                         |
| ------ | ---------- | ----------------------------------------------- |
| GET    | `/healthz` | Liveness; reports service and protocol version. |
| POST   | `/jobs`    | Receive a `ScanJob`, return a `ScanResult`.     |

`POST /jobs` returns `200` with a `succeeded` result for a valid job, `422` with
a `rejected` result for an allowlist/validation failure, and `400` for a
malformed body. Connections without a valid client certificate fail the TLS
handshake.

## mTLS

The app and agent authenticate each other with certificates issued by a shared
private CA:

- `ca.crt` — trust anchor both sides verify against.
- `agent.crt` / `agent.key` — the agent's server identity (CN
  `light-ipam-scanner-agent`).
- `app.crt` / `app.key` — the app's client identity (CN `light-ipam-app`).

The agent requires and verifies the app's client certificate
(`tls.RequireAndVerifyClientCert`) and additionally checks the client CN against
`APP_CLIENT_CN`.

### Generating dev certificates

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
```

This writes the CA, agent, and app material to `deploy/scanner-certs/` (which is
git-ignored — never commit private keys). Add SANs for non-loopback deployments:

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs -dns scanner.example.internal -ip 10.0.0.5
```

Production deployments should issue agent certificates from a managed CA with
rotation rather than this dev generator. See ADR 0002 and the roadmap's Phase 5
(agent mTLS rotation).

## Configuration

| Variable              | Default                      | Purpose                                   |
| --------------------- | ---------------------------- | ----------------------------------------- |
| `AGENT_LISTEN`        | `:8443`                      | Listen address.                           |
| `AGENT_ID`            | `agent-local`                | Agent identity reported in results.       |
| `AGENT_NAME`          | `local-scanner-agent`        | Human-readable name.                      |
| `AGENT_SITE_ID`       | (unset)                      | Optional site association.                |
| `AGENT_ALLOWED_CIDRS` | (required)                   | Comma-separated IPv4 CIDRs the agent may scan. |
| `APP_CLIENT_CN`       | `light-ipam-app`             | Required client certificate CommonName.   |
| `SCANNER_TLS_CERT`    | `/certs/agent.crt`           | Agent server certificate.                 |
| `SCANNER_TLS_KEY`     | `/certs/agent.key`           | Agent server key.                         |
| `SCANNER_TLS_CA`      | `/certs/ca.crt`              | Shared CA.                                |

## Running with Docker Compose

The agent is behind the `scanner` Compose profile, so the default `docker
compose up` (app + db) is unaffected.

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
docker compose --profile scanner up -d --build
```

The service drops all Linux capabilities and runs read-only. `NET_RAW` will be
added here — and only here — when Nmap-based discovery lands.
