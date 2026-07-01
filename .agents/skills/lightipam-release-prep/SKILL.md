---
name: lightipam-release-prep
description: Use when preparing a tagged LightIPAM release — changelog, version references, image tags, and build validation. Does not change product code unless explicitly requested.
---

# LightIPAM Release Prep

Prepare a clean, tagged LightIPAM release. Releases are cut by **pushing a SemVer
`v*` tag**, which triggers `.github/workflows/release.yml` to run tests and build +
push multi-arch `app` and `scanner` images to GHCR. This skill prepares the PR that
precedes the tag; it does not publish images by hand.

## Versioning

SemVer. A **major** bump is required for a breaking change to `/api/v1`, a breaking
scanner-protocol (`v1`) change, or a destructive database migration. Otherwise minor
(new backward-compatible feature) or patch (fixes).

## Checklist

1. **Confirm what shipped since the last tag.** Diff `main` against the last release
   tag; make sure every user-facing change is captured.
2. **Update `CHANGELOG.md`.** Keep a Changelog format: add a `## [X.Y.Z] - YYYY-MM-DD`
   section (Added / Changed / Fixed), and add the version-compare/tag link at the
   bottom. Note explicitly if `/api/v1`, the scanner protocol, or migrations changed.
3. **Bump version references consistently:**
   - `package.json` `version`.
   - `README.md` image pull examples and any version badge/tags
     (`ghcr.io/devsealware/lightipam:X.Y.Z` and `...-scanner:X.Y.Z`).
   - Confirm the compose/Dockerfile `VERSION` arg still defaults sanely (`dev`); the
     release workflow passes the git tag as `VERSION`.
4. **Confirm image naming consistency** — app image `lightipam`, scanner image
   `lightipam-scanner`, matching `release.yml`'s matrix and the README.
5. **Sync docs.** Run the `lightipam-doc-sync` skill: `docs/agent/PROJECT_STATE.md`
   (release + migration number), `docs/ROADMAP.md`, and README "Project status" must
   match the changelog.
6. **Validate the build.** [`VALIDATION.md`](../../../docs/agent/VALIDATION.md) Tier 0
   + Tier 1 (`docker compose build` and `docker compose --profile scanner build`). The
   release workflow also runs `go vet` + `go test`.
7. **Open the release PR.** No product code changes unless explicitly requested —
   release prep is docs/version metadata only. After merge, the maintainer pushes the
   `vX.Y.Z` tag; a non-prerelease tag also moves `latest`.

## Done when

- `CHANGELOG.md`, `package.json`, README tags, and `PROJECT_STATE.md` all name the same
  version and agree on what shipped.
- Both images build locally, and the diff is confined to changelog/version/docs.
