<p align="left">
  <img src="../.github/assets/lightipam-lockup-light.svg#gh-light-mode-only" alt="LightIPAM" width="260">
  <img src="../.github/assets/lightipam-lockup-dark.svg#gh-dark-mode-only" alt="LightIPAM" width="260">
</p>

# Branding

LightIPAM logo assets live in two places:

- `internal/ui/static/brand/` for runtime web UI assets embedded into the Go binary.
- `.github/assets/` for README and repository presentation assets.

## Asset Usage

- `mark` is the square app icon for favicons, browser tabs, Apple touch icons, and compact UI placement.
- `lockup-light` is the horizontal wordmark for light backgrounds.
- `lockup-dark` is the horizontal wordmark for dark backgrounds.
- `github-social-preview` is the repository social card image.

GitHub does not automatically use committed social preview images. A maintainer must set `.github/assets/github-social-preview.png` manually in repository settings under Settings -> Social preview.

## GitHub Repository Assets

- `README.md` uses `.github/assets/lightipam-lockup-light.svg` and `.github/assets/lightipam-lockup-dark.svg` with GitHub's light/dark theme fragments.
- `.github/assets/lightipam-mark.svg` is the compact repository/logo mark.
- `.github/assets/github-social-preview.png` is the image to upload manually in repository Settings -> Social preview.
- `.github/assets/github-social-preview.svg` is the editable source for that preview image.

GitHub repositories do not automatically expose a committed file as the repo logo or social preview. The committed assets keep the README and docs branded; the social preview must still be selected manually in GitHub settings.

## Web Paths

- `/favicon.ico`
- `/static/favicon-32x32.png`
- `/static/favicon-16x16.png`
- `/static/apple-touch-icon.png`
- `/static/brand/mark.svg`
- `/static/brand/mark-transparent.svg`
- `/static/brand/lockup-light.svg`
- `/static/brand/lockup-dark.svg`

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| BG | `#0f172a` | Mark background |
| DIVIDER | `#334155` | Horizontal rule |
| TEXT_PRI | `#e2e8f0` | `/24` label |
| TEXT_MUT | `#64748b` | CIDR sub-label, light |
| TEXT_HDG | `#0f172a` | IPAM wordmark on light backgrounds |
| TEXT_HDG_DK | `#f1f5f9` | IPAM wordmark on dark backgrounds |
