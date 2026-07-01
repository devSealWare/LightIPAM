# Validation

How to verify a change to LightIPAM before opening a PR. Run the tier that matches
your change; run everything before requesting a merge. **Never report a command as
passing that you did not actually run** — if a step is skipped, say so and why.

## Tier 0 — always (any code change)

```sh
npm ci                              # install pinned Tailwind toolchain (first run / lockfile change)
npm run build:css                   # regenerate the committed Tailwind CSS
go build ./...
go vet ./...
go test ./...
test -z "$(gofmt -l internal cmd)"  # formatting must be clean (prints nothing on success)
```

`gofmt -l internal cmd` lists any misformatted files; if it prints anything, run
`gofmt -w` on those files. A clean tree is required.

## Tier 1 — container builds (Dockerfile / compose / dependency / UI-embed change)

```sh
docker compose build                    # app image (regenerates CSS in the assets stage)
docker compose --profile scanner build  # scanner-agent image
```

The scanner image is only needed when the agent, its Dockerfile, or the scanner
packages changed — but building both is the safe default.

## Tier 2 — runtime smoke test (behavioral change worth exercising)

```sh
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/healthz   # liveness
docker compose exec app wget -qO- http://127.0.0.1:8080/readyz    # readiness (DB + migration version)
docker compose down
```

For the scanner path, generate dev mTLS material first, then bring up the profile:

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
docker compose --profile scanner up -d
```

The app auto-enrolls the bundled agent as `pending`; approve it under **Agents**,
create a subnet, and run a scan from **Scans**. Targets must fall within the agent's
`AGENT_ALLOWED_CIDRS`.

## One command

`scripts/verify.sh` runs the Tier 0 sequence (and, with `--docker`, Tier 1):

```sh
./scripts/verify.sh            # Tier 0
./scripts/verify.sh --docker   # Tier 0 + container builds
```

## CI

`.github/workflows/ci.yml` runs Tier 0 plus both container builds on every pull
request and on pushes to `main`. It does **not** publish images — publishing happens
only in `.github/workflows/release.yml` when a `v*` tag is pushed. Keep local
validation and CI in step: if you change the validation steps here, update the
workflow too.

## Troubleshooting

- **Go cache / sandbox permission errors** (e.g. `go: failed to ... permission
  denied` on `$GOCACHE`): rerun with normal Go build-cache permissions rather than
  editing source or vendoring. Do not "fix" a sandbox issue by changing the code.
- **`go build ./cmd/...` drops stray `/server` or `/scanner-agent` binaries** at the
  repo root. Both are gitignored — do not commit them.
- **Confirm no silent dependency creep in the agent:**
  `go build -mod=readonly ./cmd/scanner-agent`.
- **Dev mTLS keys** under `deploy/scanner-certs/` are gitignored — never commit them.
