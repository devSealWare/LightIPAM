# 0008 — 405 Method Not Allowed returns plain text instead of the JSON error envelope

- **Priority:** Low
- **Area:** API consistency
- **Status:** Open — not yet fixed

## Summary

Every explicit API error uses the JSON envelope `{"error": "..."}` via
`apiError`/`writeJSON` (`internal/app/api.go:100-108`). But an unsupported
method on a registered path (e.g. `DELETE /api/v1/subnets`) falls through to Go
1.22's `http.ServeMux` built-in 405 handling, which writes a plain-text `405
Method Not Allowed` body with no JSON — inconsistent for any API client parsing
error responses.

## Affected code

- `internal/app/app.go:98` — `mux := http.NewServeMux()`, and the
  method-specific `mux.HandleFunc("GET /api/v1/...", ...)` registrations that
  rely on stdlib `ServeMux`'s automatic 405 behavior for registered patterns
  hit with the wrong method.
- `internal/app/api.go:100-108` — `writeJSON`/`apiError`, the envelope every
  other API error already uses.

## Fix instructions

1. Scope this to the **`/api/v1/*`** surface only — the server-rendered UI
   routes should keep whatever plain-text/HTML 405 behavior is standard for
   browser navigation; only the JSON API needs a JSON envelope.
2. `net/http`'s `ServeMux` (Go 1.22+ pattern routing) does not currently expose
   a way to override the automatic 405 response for a specific path group
   without listing every method explicitly. The practical fix: wrap API routes
   in a small middleware that, after the mux fails to match on method, catches
   it — or more simply, register a catch-all fallback per API path that checks
   `r.Method` and calls `apiError(w, http.StatusMethodNotAllowed, "method not allowed")`
   for the disallowed methods, alongside the real handler. Check the Go version
   pinned in `go.mod` for what `ServeMux` features are actually available
   before picking an approach — there may be a cleaner option in the Go version
   this repo targets.
3. Alternative lower-effort approach: a thin middleware applied only to the
   `/api/v1/` prefix that inspects the response after `next.ServeHTTP` and, if
   the status is `405` and `Content-Type` isn't already JSON, rewrites the body
   — fragile (relies on not having written the body yet) and generally worse
   than fixing it at the routing layer; prefer option 2 unless it proves
   impractical.
4. Add a test hitting a registered `/api/v1/...` path with a disallowed method
   and asserting `Content-Type: application/json` and a `{"error": ...}` body.
5. No behavior change for UI routes, no migration, no new dependency.
