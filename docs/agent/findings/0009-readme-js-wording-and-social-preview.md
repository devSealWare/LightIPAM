# 0009 — README JS-framework wording could mislead; social-preview image still unset

- **Priority:** Low
- **Area:** Docs
- **Status:** Open — not yet fixed

## Summary

Documentation was found to be accurate and unusually thorough overall — no false
claims. Two small polish items:

1. `README.md:126-127` says "No client-side JavaScript framework," which is
   true (no React/Vue/etc.), but the app does serve several first-party JS
   files (`columns.js`, `scan_form.js`, `bulk.js` under
   `internal/ui/static/`) for progressive enhancement. The phrasing is
   technically correct but a skimming reader could come away expecting *zero*
   JavaScript, then be surprised finding `.js` files in the static bundle.
2. `README.md:251-253` already documents that the GitHub social-preview image
   is committed but must be set manually in repo Settings — this is a
   maintainer action item, not a docs bug. Confirm whether it's been set; if
   not, this is a one-click maintainer task, not something an agent PR can fix
   (repository settings aren't in version control).

## Affected docs

- `README.md:122-131` — "Stack" section, JS-framework line.
- `README.md:251-253` — social preview note (already accurate; just flagging
  the outstanding manual step for the maintainer).

## Fix instructions

1. Reword `README.md:126-127` to be explicit about progressive enhancement,
   e.g.: "No client-side JavaScript framework — a few small first-party scripts
   (`internal/ui/static/*.js`) progressively enhance specific forms (bulk edit,
   scan form, column preferences); strict CSP (no inline JS/CSS)." Keep it to
   one or two sentences; this is a wording fix, not a rewrite of the Stack
   section.
2. No change needed to the social-preview text — it's already accurate.
   Separately (not a docs PR item), the maintainer should check whether
   `.github/assets/github-social-preview.png` is actually set in GitHub repo
   Settings → Social preview, and set it if not.
3. No code, no migration, no CHANGELOG entry (wording-only, not a behavior
   change).
