# ADR 0025: Scanner certificate file ownership on Linux

## Status

Accepted.

## Context

The web app and the scanner agent authenticate to each other with mutual TLS using
material generated into `deploy/scanner-certs/` (`go run ./cmd/scanner-certs`, ADR
0002/0003). Both compose services run hardened: `cap_drop: ALL`, `read_only: true`,
`no-new-privileges`. The agent additionally adds back only `NET_RAW` for raw-socket
probes. The private keys are written mode `0600`, owned by the operator who ran the
generator.

On a native-Linux Docker host this combination breaks startup. A bind mount preserves
the host's ownership, and `cap_drop: ALL` removes `CAP_DAC_OVERRIDE` — the capability
that normally lets the in-container **root** bypass file-permission bits. So:

- the **agent** runs as root but, lacking `DAC_OVERRIDE`, cannot read a `0600` key it
  does not own; it crashes on boot with
  `read server key … open /certs/agent.key: permission denied` and exits 1;
- the **app** runs as the unprivileged `lightipam` user (uid 100, set by `USER` in its
  Dockerfile) and hits the same denial reading `app.key`, surfaced as
  `scanner dispatch disabled` because it loads its client certificate once at startup.

This was observed on a Debian deployment. It does **not** reproduce on macOS / Docker
Desktop, whose VM file-sharing layer does not enforce the underlying permission bits —
so the same `deploy/scanner-certs/` "works on my machine" and fails on the first real
Linux host. The fix must not weaken the capability posture (re-adding `DAC_OVERRIDE`
to bypass file perms is exactly the privilege the security model drops), must keep the
keys non-world-readable, and must be seamless — including after a cert regeneration,
which rewrites the keys back to the operator's `0600`.

In-container self-repair is not possible: the cert mount is bind-mounted read-only into
app/agent, and a capless container cannot `chown` a file it does not own.

## Decision

Give each private key to the uid that actually reads it, keeping mode `0600`, and do it
automatically from a dedicated one-shot init service.

- **`deploy/fix-cert-perms.sh`** is the single source of the ownership policy:
  `agent.key → root (0:0)` (the agent runs as root), `app.key → 100:101` (the app's
  `lightipam` user). Public `*.crt`/`ca.crt` stay `0644`, already readable by both. The
  script is a no-op for absent files, and self-elevates with `sudo` when run by hand on
  the host (for older checkouts or non-Compose deployments). The app uid/gid are
  overridable via `APP_CERT_UID`/`APP_CERT_GID`.
- **`cert-perms`** — a one-shot `alpine` service in `compose.yaml` — runs that script
  before `app` and `scanner-agent` (`depends_on … service_completed_successfully`),
  then exits. It is the only component permitted to change cert ownership and holds just
  `CHOWN` + `FOWNER` (still `cap_drop: ALL`, `read_only`, `no-new-privileges`) for that
  moment. It re-runs on every `docker compose up`, so it also self-heals after a cert
  regeneration, and is a no-op when no certs exist, leaving the default `app` + `db`
  stack unchanged.
- The app's **uid/gid are pinned** to `100:101` in `Dockerfile` (`adduser -u 100`,
  `addgroup -g 101`) so the chown target is stable across rebuilds rather than relying
  on `adduser`'s default allocation.

Documented in `docs/SCANNER_AGENT.md` ("Certificate file ownership on Linux") with the
symptom, cause, and both the automatic and manual fixes.

## Consequences

- The agent and app come up cleanly on a native-Linux host out of the box; the failure
  mode that previously required manual `chown` is fixed permanently and self-heals after
  cert regeneration. No host-side step is needed in the normal Compose flow.
- The hardened posture is unchanged: app and agent keep `cap_drop: ALL` (agent +
  `NET_RAW`), and the keys stay `0600` and non-world-readable. The only new privilege is
  an ephemeral `CHOWN`/`FOWNER` on a container that lives for milliseconds and touches
  nothing but cert ownership.
- The ownership map is coupled to the app's container uid. That uid is now pinned in the
  Dockerfile and overridable via env, so the coupling is explicit rather than incidental.
- macOS / Docker Desktop users see no change (the init runs harmlessly). The behavior is
  a native-Linux concern only.
- A managed-CA / online enrollment flow (the deferred Phase 5 item) would issue keys
  with container-appropriate ownership directly and could make this init unnecessary;
  until then `cert-perms` is the seam.
