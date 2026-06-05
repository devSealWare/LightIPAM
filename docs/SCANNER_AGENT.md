# Scanner Agent

The scanner agent is the isolated component that performs active network
discovery for Light IPAM. It runs as a separate container so the web app can
stay unprivileged. Since issue #10 it performs **real active discovery** with
nmap for non-passive jobs; the privilege to do so (`NET_RAW`) is scoped to this
component only. See `docs/SCANNER_DISCOVERY.md` for the discovery/enrollment flow.

## Responsibilities

- Receive scan jobs from the app over mTLS (`POST /jobs`).
- Verify the app's client certificate identity.
- Validate every job against the agent's registered IPv4 allowlist using
  `scanner.ValidateAgentScope` (allowlist containment).
- Run nmap for active modes (depth bounded by mode) and report observations;
  passive jobs return an empty, successful result.
- Self-describe on `GET /register` so the app can enroll it automatically.

The agent never trusts a job blindly: even if the app submits targets outside
the agent's `AGENT_ALLOWED_CIDRS`, the agent rejects them.

## Endpoints

| Method | Path        | Purpose                                            |
| ------ | ----------- | -------------------------------------------------- |
| GET    | `/healthz`  | Liveness; reports service and protocol version.    |
| GET    | `/register` | Self-reported identity + allowlist for enrollment. |
| POST   | `/jobs`     | Receive a `ScanJob`, return a `ScanResult`.        |

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
| `AGENT_SCAN_SOURCE_IP`| (unset)                      | Pin nmap's probes to the interface owning this IP (the macvlan LAN IP). See "Consistent scans across subnets". |
| `AGENT_SCAN_INTERFACE`| (unset)                      | Name the egress interface directly instead of resolving it from the source IP. |
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

## Layer-2 discovery (MAC addresses) with macvlan

On a plain Docker bridge the agent reaches scan targets as NAT'd, routed TCP.
Service/version detection (`-sV`) works, but nmap never sees the target's ARP
reply, so observations come back with **no MAC address**. Because a discovery is
imported into a device only when it carries a MAC
(`importDiscoveryDevice` in `internal/store/discoveries.go` returns early when
`discovery.MAC == ""`), bridged scans import as **address-only** records — they
show up under a subnet but never on the Devices page.

To populate devices automatically the agent needs **layer-2 (ARP) visibility**
of the LAN. The `deploy/compose.scanner-macvlan.yaml` overlay provides it by
attaching the agent to a **macvlan** network (a real LAN IP) *in addition to*
the bridge:

```sh
docker compose -f compose.yaml -f deploy/compose.scanner-macvlan.yaml \
  --profile scanner up -d
```

- The agent keeps its bridge connection, so the app still reaches it at
  `https://scanner-agent:8443` — **no certificate/SAN change is required.**
- nmap routes LAN-subnet targets out the macvlan interface (directly connected →
  ARP works → MAC reported), while app↔agent mTLS stays on the bridge.

Edit `parent` (the host NIC on the target LAN), `subnet`, `gateway`, and the
agent's `ipv4_address` (a free LAN address) in the overlay to match your
network, and ensure `AGENT_ALLOWED_CIDRS` includes the LAN subnet. By Docker's
macvlan design the host itself cannot talk to the agent over the macvlan
interface — that is expected and harmless, since the host/app use the bridge and
the macvlan carries only the agent's outbound scans.

After re-scanning over macvlan, observations include MACs; importing them (or
auto-import on a trusted agent) then creates the device + MAC record and links
the address to it.

### Consistent scans across subnets

The macvlan agent is **dual-homed**: the control-plane bridge and the LAN
macvlan. Its *default route* points at the bridge, which creates an asymmetry:

- **Same subnet as the agent** (L2-connected over macvlan): the ARP ping
  succeeds — so hostname + MAC come back — but nmap's SYN/OS probes can leave
  (or have replies return on) the bridge instead of the macvlan, so **service
  and OS detection silently return nothing**.
- **Different subnet** (routed): OS + services come back, but **no MAC** — this
  half is inherent to crossing an L3 boundary and cannot be fixed.

The overlay closes the same-subnet gap by pinning every scan to the LAN
interface. It sets `AGENT_SCAN_SOURCE_IP` to the agent's macvlan IP; on startup
the agent finds the interface owning that address and runs nmap with
`-e <iface> -S <ip>`, so all probes egress the macvlan. Same- and cross-subnet
targets then report the **same fields** (minus the MAC across a routed boundary).
Set `AGENT_SCAN_INTERFACE` to name the interface directly if you prefer. With
neither set (the plain bridge setup) nmap chooses its own egress, unchanged.

Verify the pin from inside the container if a same-subnet scan still misses
services:

```sh
docker compose exec scanner-agent ip route get <target-ip>   # should leave the macvlan iface
docker compose exec scanner-agent ip -br addr                # confirm the macvlan IP/iface name
```

## Scan timeouts

A job's timeout is nmap's **per-host** budget (`--host-timeout`): nmap caps each
target at that many seconds, then moves on and exits cleanly with whatever it
found. The agent's own supervising deadline is deliberately *larger* — the
per-host budget across every target plus grace for startup/output, capped at two
hours (`scanBudget`). This lets nmap self-limit and return partial results
instead of being hard-killed at the exact moment its host-timeout fires (which
truncates output and produces an empty `nmap failed:` error). If a heavy
`standard_active`/`deep_active` scan still times out, raise the timeout on the
scan form or narrow the targets; `host_discovery`/`light_active` (`-sn`) needs no
port probing and returns near-instantly.

## App-side dispatch

The app is the mTLS *client*: it dispatches scan jobs to agents (issue #9). The
Compose `app` service mounts the same `deploy/scanner-certs` directory read-only
and reads `app.crt`/`app.key`/`ca.crt` (via `SCANNER_CLIENT_CERT`,
`SCANNER_CLIENT_KEY`, `SCANNER_CLIENT_CA`). If those files are absent the app
still starts, but scan jobs fail with a configuration error instead of
contacting an agent. Register an agent under `/agents` with its endpoint
(e.g. `https://scanner-agent:8443`) and IPv4 allowlist, then run scans from
`/scans` or schedule them under `/schedules`.
