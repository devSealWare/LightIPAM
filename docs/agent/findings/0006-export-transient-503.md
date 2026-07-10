# 0006 — Transient 503 on repeated `/subnets/export.csv` requests

- **Priority:** Medium
- **Area:** Reliability
- **Status:** Open — needs reproduction

## Summary

A repeated request to `/subnets/export.csv` returned `200` on the first call and
an immediate `503` on a second, rapid-succession call. This may be benign
contention (e.g. a connection-pool limit under a tight test-harness loop rather
than real user behavior), but it hasn't been root-caused and is worth
reproducing deliberately before dismissing it.

## Affected code

- `internal/app/portability.go:499-521` — `exportSubnetsCSV` (and likely the
  sibling `exportAddressesCSV` / `exportDevicesCSV` share the same DB-connection
  path via `a.store.ListSubnets(r.Context())` etc.).
- The DB connection pool configuration (search for `pgxpool.Config` / pool
  size/`MaxConns` setup, likely in `internal/store` or `cmd/`) — a 503 under
  rapid repeats smells like pool exhaustion or a health-check gate firing.
- Check whether `503` is coming from the app's own readiness gate
  (`internal/app/app.go:267,274` — the `/readyz`-style handler returns
  `{"status":"unavailable",...}` with presumably a `503`) rather than the export
  handler itself; if so, something may be routing export traffic through a
  readiness check unexpectedly, or the DB pool is briefly reporting unhealthy
  under load.

## Fix instructions

1. **Reproduce first.** Script two rapid sequential (or concurrent) requests to
   `/subnets/export.csv` against a local dev instance and confirm: is it
   consistently the 2nd request, does it need concurrency vs. sequential, does
   it also affect `/addresses/export.csv` and `/devices/export.csv`, and what is
   the actual response body / logged error on the 503?
2. Check server logs at the time of the 503 for the underlying error (pool
   exhaustion, context deadline, connection refused) — `a.logger.Error(...)`
   calls in `portability.go` around the `ListSubnets`/`ListAddressesForExport`
   error paths currently return a generic `http.StatusInternalServerError`
   (`500`), not `503`, on a store error — so if the observed status really is
   `503`, confirm where in the stack (proxy? pool wrapper? health middleware?)
   that code is being set, since it doesn't match the export handler's own
   error path at first read.
3. Once root-caused, the fix is likely one of: increase pool size / eviction
   tuning, add a short retry/backoff in the DB layer for a specific transient
   error class, or (if it's a false alarm from a local dev proxy/rate-limiter)
   document it as a non-issue and close this finding.
4. Add a regression test only if the root cause is in application code (e.g. a
   pool-sizing constant); if it's environmental, note that in this file's
   resolution instead of forcing a test.
