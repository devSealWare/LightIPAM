# ADR 0027: Routing-aware scanner egress + scan diagnostics

## Status

Accepted.

## Context

A real deployment on an Alpine Linux VM surfaced a silent failure mode. The scanner
agent ran with the `deploy/compose.scanner-macvlan.yaml` overlay, which sets
`AGENT_SCAN_SOURCE_IP` to the agent's macvlan LAN address. Today that env var pins
**every** nmap invocation to the macvlan interface with `-e <iface> -S <ip>`
(`resolveEgress` in `cmd/scanner-agent/main.go` → `EgressOptions` in
`internal/scanner/agent/nmap.go`). That pin was added in #37 to fix a *same-subnet*
asymmetry on a dual-homed agent: the ARP ping succeeds (MAC reported) but service/OS
probes leave the wrong interface and silently return nothing.

The pin is **unconditional**, and that breaks **routed** scans. Example topology from
the report:

```
LightIPAM VM:        192.168.0.3/28
Scanner macvlan IP:  192.168.0.9/28   (eth0, macvlan)
macvlan subnet:      192.168.0.0/28
Docker bridge:       172.18.0.2       (eth1, default route)
target subnet:       192.168.1.0/24   (routed, NOT on the macvlan segment)
```

The container's route to `192.168.1.0/24` is `via 172.18.0.1 dev eth1 src 172.18.0.2`
(the bridge), but `AGENT_SCAN_SOURCE_IP=192.168.0.9` forces nmap to source from the
macvlan (eth0). Source pin and kernel route disagree, so host discovery finds **zero**
live hosts. The job returns:

```json
{ "status": "succeeded", "observations": [],
  "errors": [{ "code": "scan_ignored",
    "message": "Per-host enrichment skipped: no live hosts discovered to query (SNMP, names, DNS)" }] }
```

A *direct* scan of the gateway (`192.168.1.1`) still worked, because SNMP harvested the
router's ARP table — masking the host-discovery failure and making the bug confusing.

A second, secondary failure compounded it: an operator tried a Compose override to add a
static route inside the agent; the override made the agent container **exit**, after
which the app reported `contact agent: Post "https://scanner-agent:8443/jobs": dial tcp:
lookup scanner-agent on 127.0.0.11:53: no such host`. That is Docker DNS only resolving
**running** containers — a deployment failure, not the scan bug, but the app's single
opaque `contact agent: %w` wrapper gave no hint which of the two it was.

The underlying Linux/Docker behavior is **expected** (you cannot ARP-scan a routed
subnet; a source/route mismatch drops probes). The LightIPAM gaps are:

1. The agent pins egress unconditionally and never checks the pin against the route to
   each target.
2. A whole-subnet scan returns `succeeded` with zero observations and a generic notice
   instead of explaining the pin/route mismatch.
3. The app cannot distinguish *no live hosts* from *source/interface mismatch*, *agent
   unreachable*, *container not running*, *DNS failure*, *TLS failure*, or *firewall
   block*.
4. The docs imply source pinning makes same- and cross-subnet scans uniformly
   consistent; it does not for routed targets.

Standing constraints are unchanged: the web app stays unprivileged (zero capabilities,
no nmap); all privileged behavior stays in the agent; no client JS under the strict CSP;
no new runtime dependency unless justified.

## Decision

Make scanner egress **routing-aware by default** and make every "nothing happened"
state **self-explaining**, biasing toward zero operator action for the common case and
clear guidance when a deployment genuinely needs a different mode.

The single most important change is that **pinning becomes per-target and automatic**:
an existing `AGENT_SCAN_SOURCE_IP` deployment will, with no config change, pin
same-subnet targets (keeping the #37 fix) and *not* pin routed targets (fixing this
bug). Everything else is diagnostics and documentation that make the remaining failure
modes legible.

### 1. `AGENT_SCAN_PIN_MODE` — routing-aware egress (core)

Add an agent env var `AGENT_SCAN_PIN_MODE` with three values (default **`auto`**):

| Mode     | Behavior |
| -------- | -------- |
| `auto` (default) | Pin a target to the scan source interface **only when that target is layer-2 adjacent** to it (the target IP falls inside the source interface's own subnet). Routed targets run **unpinned**, using the kernel's default route. Emits an actionable notice when a pin was configured but a target is routed. |
| `always` | Pre-#37 behavior: pin **every** target to the source interface/IP. Correct only when every target is on the macvlan segment; documented as the opt-in for operators who want the old unconditional pin. |
| `off`    | Never pin; let nmap choose egress (plain-bridge behavior even if a source IP is set). |

`same-subnet-only` is accepted as a back-compat **alias of `auto`** (the report listed
it separately; the pin decision is identical — `auto` simply also warns on mismatch). We
keep the surface to three real values on purpose.

**Why `auto` as default, and why it needs no operator change:** the only deployments
that set a source IP today are macvlan ones, and for them `auto` is strictly better than
the current always-pin — same-subnet still pins (the #37 fix is preserved), routed no
longer pins (this bug is fixed). Operators who deliberately want the old behavior set
`AGENT_SCAN_PIN_MODE=always`. This is the "as little user change as possible" property:
the macvlan overlay keeps working and routed scans through it start succeeding after an
agent image update, with no `.env`/compose edit.

**Implementation shape.** The adjacency test is **pure Go, no new binary**: the agent
already resolves the source interface (`interfaceForIP`); extend that to capture the
interface's `*net.IPNet`, and a target is "directly connected" when the net contains it.
The discoverer partitions a job's targets into a *pinned set* (tokens inside the source
subnet) and an *unpinned set* (everything else) and runs the existing staged nmap passes
once per set, merging via the existing `mergeObservations`. A CIDR target that straddles
the source subnet boundary is classified by overlap and flagged with a notice (rare;
documented). The classifier is injectable/hermetic like `snmpSession`/`udpExchanger`, so
it is unit-tested without real interfaces. This deliberately avoids shelling out to
`ip route get` (iproute2 is not guaranteed in the busybox+nmap agent image, and a pure
containment test is testable and dependency-free). The route table is consulted only for
the human-readable diagnostic message (see §3), never as the control path.

### 2. Self-explaining zero-result and mismatch notices

When host discovery returns **zero** live hosts *and* a pin was configured (or a
mismatch was detected), the agent enriches the existing `scan_ignored` notice with the
pin/route context instead of the bare "no live hosts discovered to query". Target
message shape:

> No live hosts were discovered. The scanner is pinned to source IP 192.168.0.9 on eth0,
> but the route to 192.168.1.0/24 uses eth1 (172.18.0.2). This is usually a macvlan
> scanner used for a routed subnet. Use bridge mode for routed scans, put a scanner on
> the target VLAN, or set AGENT_SCAN_PIN_MODE=auto.

In `auto` mode the routed target is no longer pinned, so this becomes a *confirmation*
("scanned 192.168.1.0/24 over the bridge default route; no MACs across the L3 boundary —
use SNMP/ARP-table or a scanner on that VLAN for MACs") rather than a failure. The
existing scan-detail UI already renders `scan_ignored` notices as muted "Skipped" lines
(`partitionScanErrors`, `PageData.ScanNotices`), so **no app-side rendering change is
needed** — only richer message text from the agent.

### 3. Agent `GET /diagnostics` endpoint

Add an mTLS-gated `GET /diagnostics` to the agent (alongside `/healthz`, `/register`,
`/jobs`) returning the agent's network self-view:

```json
{
  "agent_id": "agent-local",
  "interfaces": [{ "name": "eth0", "addrs": ["192.168.0.9/28"] }, ...],
  "scan_source_ip": "192.168.0.9",
  "resolved_scan_interface": "eth0",
  "default_route_interface": "eth1",
  "pin_mode": "auto",
  "nmap_version": "7.94",
  "capabilities": ["NET_RAW"],
  "warnings": ["AGENT_SCAN_SOURCE_IP is on eth0 but the default route is eth1; routed targets will not be pinned (auto) / will be dropped (always)."]
}
```

The app surfaces it from the `/agents/{id}` detail view ("Run diagnostics") so an
operator can see the source/route/interface picture without `docker exec`. Additive,
read-only, same mTLS identity check as the other endpoints. Reading routes/interfaces is
unprivileged.

### 4. Classify app→agent dispatch failures

In `internal/scanner/dispatch/dispatch.go`, replace the single `contact agent: %w` with
a classifier that maps the transport error to an actionable category, using `errors.As`
on standard types:

- **DNS** (`*net.DNSError`, "no such host") → "scanner-agent is not resolvable from the
  app — check the scanner-agent container is running and attached to the Compose
  network." (This is the secondary failure from the report.)
- **TCP** (`*net.OpError`, connection refused / unreachable) → "resolved, but port 8443
  was unreachable."
- **TLS / cert** (`tls.*` / `x509.*` / `tls.RecordHeaderError`) → "reachable, but
  mTLS/certificate validation failed."
- **HTTP** (non-2xx) → keep the status + body (already handled).

Applies to `Dispatch`, `FetchRegistration`, and `HealthCheck` (all three share the
wrapper). Pure error-mapping function, unit-tested.

### 5. Agent self-healthcheck + Compose healthcheck

The agent's HTTP endpoints require a client cert (`RequireAndVerifyClientCert`), so a
plain `wget`/`nc` Compose healthcheck can't complete the handshake. Add a
`scanner-agent --healthcheck` subcommand that dials the configured listen port and exits
0/1, and wire it as the Compose healthcheck:

```yaml
healthcheck:
  test: ["CMD", "scanner-agent", "--healthcheck"]
  interval: 30s
  timeout: 5s
  retries: 3
```

Self-contained (no `nc`/iproute2 dependency, no non-mTLS endpoint to secure), so
`docker compose ps` shows the agent unhealthy/exited — which would have made the
"container not running → DNS failure" chain obvious immediately.

### 6. Documentation (the bulk of the report; partly shipping now)

In `docs/SCANNER_AGENT.md` and the compose comments:

- **Bridge vs macvlan decision matrix** (goal -> recommended mode -> notes).
- **Troubleshooting section** with `docker compose --profile scanner ps`,
  `docker exec ... ip -br addr` / `ip route` / `ip route get <target>`,
  `docker exec ... getent hosts scanner-agent`, and how to read each. The
  `/diagnostics` view + classified errors are the in-product path; the host
  commands remain useful when the app cannot reach the agent.
- **Deployment modes as a concept** (`bridge-routed` / `macvlan-l2` / `custom`)
  expressed through the decision matrix and `AGENT_SCAN_PIN_MODE`, **not** a second
  overlapping env enum. The base `--profile scanner` stack already *is* bridge mode, so
  no redundant `compose.scanner-bridge.yaml` is added; a new
  `deploy/compose.scanner-multivlan.example.yaml` documents the "one scanner per VLAN"
  pattern (the best long-term design for multi-VLAN MAC discovery).
- The live `AGENT_SCAN_PIN_MODE` config-table row documents the implemented values:
  `auto`, `always`, and `off`.

## Implementation

The work was delivered as a small stack:

1. **Core:** §1 `AGENT_SCAN_PIN_MODE=auto` routing-aware egress + §2 richer
   zero-host / mismatch notices. This is the highest-value change and the one that
   needs no operator action.
2. **Clarity:** §4 dispatch error classification.
3. **Ops:** §5 `--healthcheck` + Compose healthcheck.
4. **Support:** §3 `/diagnostics` endpoint + `/agents` detail surfacing.
5. **Docs:** §6 multi-VLAN compose example, final `AGENT_SCAN_PIN_MODE`
   configuration docs, and updated macvlan/bridge guidance.

## Consequences

- Existing macvlan deployments get correct routed-scan behavior on the next agent image
  build **with no config change** (default `auto`); the old unconditional pin is one env
  var away (`always`).
- The same-subnet #37 fix is preserved (same-subnet targets are still pinned under
  `auto`).
- Every "zero results" outcome becomes self-explaining (agent notice) and every
  app→agent failure becomes classified (DNS/TCP/TLS/HTTP), removing the two confusing
  symptoms from the report.
- No new web-app privilege, no client JS, no new mandatory runtime dependency. The
  adjacency test and error classifier are pure and unit-tested; `/diagnostics` and the
  healthcheck are additive.
- Inherent limits are unchanged and now documented: MAC discovery still requires L2
  adjacency or a gateway SNMP/ARP-table source; routed scans get services/OS but not
  MACs.

## Alternatives considered

- **Shell out to `ip route get <target>`** for the pin decision (as the report
  suggested). Rejected as the control path: iproute2 is not guaranteed in the
  busybox+nmap image and exec'ing per target is slower and harder to test. Kept only as
  an optional input to the human-readable `/diagnostics` warning text.
- **A separate `AGENT_SCANNER_MODE=bridge-routed|macvlan-l2|custom` enum** (report rec
  #2). Rejected as redundant with `AGENT_SCAN_PIN_MODE` + the deployment overlays; the
  concept lives in docs instead, avoiding two knobs that can disagree.
- **Keep pinning unconditional and only document the footgun.** Rejected: the report's
  whole point is that the silent zero-result is the problem; docs alone do not fix the
  default behavior.
- **A non-mTLS liveness endpoint** for the healthcheck. Rejected in favor of the
  self-dialing `--healthcheck` subcommand — nothing new to expose or secure.

## References

- Source report: "Scanner macvlan source pin can break routed-subnet scans" (operator
  writeup, 2026-06-27).
- ADR 0006 (SNMP ARP-table — the indirect MAC source for routed subnets), #37 (the
  original egress-pin fix this refines), ADRs 0008/0009/0015 (combined/staged scans the
  egress logic threads through).
