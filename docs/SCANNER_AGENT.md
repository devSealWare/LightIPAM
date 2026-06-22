# Scanner Agent

The scanner agent is the isolated component that performs active network
discovery for Light IPAM. It runs as a separate container so the web app can
stay unprivileged. It performs **real active discovery** for non-passive jobs:
nmap for host/service/OS scanning (the only thing needing `NET_RAW`, scoped to
this component), SNMP for ARP-table harvesting, device inventory, and LLDP/CDP
neighbor harvesting (plain UDP/161), and NetBIOS/mDNS for host-name resolution
(plain UDP/137 and UDP/5353) — the SNMP and name backends need no extra privilege.
See `docs/SCANNER_DISCOVERY.md` for the discovery/enrollment flow and the
per-scan-type behavior.

## Responsibilities

- Receive scan jobs from the app over mTLS (`POST /jobs`).
- Verify the app's client certificate identity.
- Validate every job against the agent's registered IPv4 allowlist using
  `scanner.ValidateAgentScope` (allowlist containment).
- Route each job to the right backend by scan type (a `DiscoveryRouter`): nmap for
  `host_discovery`/`service_detection`/`os_probe`, SNMP for
  `arp_table`/`snmp_inventory`/`lldp_cdp`, NetBIOS/mDNS for `name_lookup`, and a
  combined discoverer for `combined` (deep nmap + both SNMP passes + the name lookup
  + the LLDP/CDP harvest, merged per host, a silent enrichment pass ignored not
  failed).
- Run nmap in **stages** — a fast host-discovery sweep, then service/OS detection
  on only the live hosts — and report observations; passive jobs return an empty,
  successful result.
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

#### Without a local Go toolchain (Docker one-shot)

`scanner-certs` is pure Go — no nmap, no network, no `NET_RAW` — so on a host that
has Docker but not Go (e.g. a Debian deployment box), generate the certs with a
throwaway `golang` container instead. Run it from the repository root:

```sh
docker run --rm \
  -v "$PWD":/src -w /src \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  golang:1.25-alpine \
  go run ./cmd/scanner-certs -dir deploy/scanner-certs
```

The container is deleted on exit (`--rm`); only the generated files in
`deploy/scanner-certs/` remain on the host. The flags matter:

- `-v "$PWD":/src -w /src` mounts the repo so the output lands on the host, not
  inside the (discarded) container.
- `--user "$(id -u):$(id -g)"` makes the written files owned by you rather than
  `root` — important since the private keys are mode `0600`.
- `-e HOME=/tmp` gives Go's build/module cache a writable directory for the
  non-root user (otherwise the build fails trying to write to `/`).
- `golang:1.25-alpine` matches the toolchain in `Dockerfile.scanner`; the image is
  pulled on first use and reused after.

Add the same `-dns`/`-ip` SAN flags to the trailing `go run …` as needed. This is
a one-time step — the agent and app mount the resulting `deploy/scanner-certs/`
read-only.

Production deployments should issue agent certificates from a managed CA with
rotation rather than this dev generator. See ADR 0002 and the roadmap's Phase 5
(agent mTLS rotation).

### Certificate file ownership on Linux

> **Symptom:** on a native-Linux Docker host the `scanner-agent` container exits
> immediately (`Exited (1)`) with
> `read server key … open /certs/agent.key: permission denied`, and the `app`
> logs `scanner dispatch disabled`. **This does not happen on macOS / Docker
> Desktop**, so it typically appears only on the first real Linux deployment.

**Cause.** Both the `app` and `scanner-agent` services run with `cap_drop: ALL`
(the agent keeps only `NET_RAW`). Dropping every capability removes
`CAP_DAC_OVERRIDE`, the capability that normally lets the in-container **root**
bypass file-permission bits. A Linux bind mount preserves the operator's
ownership, so the private keys — mode `0600`, owned by the host user who generated
them — are unreadable to the containers:

- the **agent** runs as **root** but, without `DAC_OVERRIDE`, cannot read a `0600`
  key it does not own, so it crashes on boot;
- the **app** runs as **`lightipam` (uid 100)** and hits the same denial, surfaced
  lazily as `scanner dispatch disabled` (it reads its client key once at startup).

Docker Desktop's VM file-sharing layer does not enforce these bits, which is why
the same `deploy/scanner-certs/` works on a Mac but not on Debian.

**Fix (automatic).** `compose.yaml` includes a one-shot **`cert-perms`** service
that runs `deploy/fix-cert-perms.sh` before `app` and `scanner-agent` start. It
gives each private key to the uid that reads it, keeping mode `0600`:

| File | Owner | Read by |
| --- | --- | --- |
| `agent.key` | `root` (`0:0`) | the agent container (runs as root) |
| `app.key` | `100:101` | the app container's pinned `lightipam` user |
| `*.crt`, `ca.crt` | unchanged (`0644`) | both (already world-readable) |

It holds only `CHOWN` + `FOWNER` for that moment, then exits, and **re-runs on
every `docker compose up`**, so it also self-heals after you regenerate the certs
(which resets them to the operator's `0600`). It is a no-op when the certs are
absent, so the default `app` + `db` stack is unaffected. See ADR 0025.

**Fix (manual),** e.g. on an older checkout without the `cert-perms` service, or
for a non-Compose deployment:

```sh
./deploy/fix-cert-perms.sh                 # self-elevates with sudo on the host
docker compose --profile scanner up -d
```

The app's uid/gid (`100:101`) is **pinned** in `Dockerfile` so this mapping stays
stable across rebuilds; override with `APP_CERT_UID`/`APP_CERT_GID` if you change
it.

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
| `AGENT_SNMP_COMMUNITY`| `public`                     | SNMP v2c read community (lives only on the agent, never the app DB). |
| `AGENT_SNMP_VERSION`  | `2c`                         | SNMP version (only `2c` is wired today; shaped for v3 later). |
| `AGENT_SNMP_PORT`     | `161`                        | SNMP UDP port.                            |
| `AGENT_SNMP_TIMEOUT`  | `5`                          | SNMP per-request timeout (seconds).       |
| `AGENT_SNMP_RETRIES`  | `1`                          | SNMP retry count.                         |
| `AGENT_NETBIOS_PORT`  | `137`                        | NetBIOS name-service UDP port (`name_lookup`). |
| `AGENT_MDNS_PORT`     | `5353`                       | mDNS UDP port (`name_lookup`).            |
| `AGENT_NAME_TIMEOUT`  | `2`                          | NetBIOS/mDNS per-probe timeout (seconds). |
| `AGENT_DNS_SERVER`    | (system resolver)            | Resolver to query for `dns_lookup` (host or host:port, default `:53`); empty uses the agent's system resolver. |
| `AGENT_DNS_TIMEOUT`   | `3`                          | DNS per-lookup timeout (seconds, `dns_lookup`). |
| `AGENT_DHCP_LEASE_FILE`| (unset)                     | Path to a DHCP server lease file the agent can read (`dhcp_leases`); mount it read-only. Unset leaves the scan idle. |
| `AGENT_DHCP_LEASE_FORMAT`| `auto`                    | Lease-file format: `isc`, `dnsmasq`, or `auto` (sniff). |
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

The service drops all Linux capabilities (`cap_drop: ALL`) and adds back only
`NET_RAW` — here, and only here — for nmap's raw-socket probes. The app service
keeps zero capabilities. SNMP discovery uses an ordinary UDP socket and needs no
added capability.

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

A job's timeout is the **per-host** budget (nmap's `--host-timeout`): nmap caps
each target at that many seconds, then moves on and exits cleanly with whatever
it found. The scan form leaves the field blank by default and the app fills a
**generous per-type default** (`app.defaultTimeoutForType`: host_discovery 120s,
service_detection 600s, os_probe 900s, combined 1200s, arp_table 180s,
snmp_inventory 300s, name_lookup 120s, lldp_cdp 300s) — a high `--host-timeout` is
only a ceiling, harmless to fast hosts and protective of slow ones.

From that per-host budget, `scanner.ScanBudget(perHost, targets)` derives the
**whole-job** budget (`perHost × host-count + host-discovery allowance + grace`,
capped at **4h**). Both the agent (supervising the discoverer across its staged
nmap passes) and the app (bounding the single blocking dispatch HTTP call) compute
their deadline from this one function, so the app always outlasts the agent — this
is what fixed the multi-host "context deadline exceeded" where the app gave up
after `perHost + 10s` while the agent legitimately needed `perHost × hosts`. The
generous budget also lets nmap self-limit and return partial results instead of
being hard-killed mid-write. If a heavy scan still times out, raise the timeout on
the scan form or narrow the targets.

## App-side dispatch

The app is the mTLS *client*: it dispatches scan jobs to agents (issue #9). The
Compose `app` service mounts the same `deploy/scanner-certs` directory read-only
and reads `app.crt`/`app.key`/`ca.crt` (via `SCANNER_CLIENT_CERT`,
`SCANNER_CLIENT_KEY`, `SCANNER_CLIENT_CA`). If those files are absent the app
still starts, but scan jobs fail with a configuration error instead of
contacting an agent. Register an agent under `/agents` with its endpoint
(e.g. `https://scanner-agent:8443`) and IPv4 allowlist, then run scans from
`/scans` or schedule them under `/schedules`.
