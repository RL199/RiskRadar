# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2]

### Changed
- On pages the browser forbids extensions from scripting (the Chrome Web Store, and the Edge
  Add-ons store on Edge), the Content Analysis, Links, and AI Analysis categories now show an
  explicit **Restricted** verdict with a "Chrome blocks extensions on this page" note instead of
  the generic **Unknown**, and the AI **Analyze** button is disabled there. URL & Domain and
  Reputation still run on these pages and the trust score is computed from them alone.

## [1.0.1]

### Added
- Support for Anthropic's Claude Sonnet 5 model
- In settings, added an option to select the default AI provider.

## [1.0.0]

### Added
- Chrome Web Store listing and auto-publish workflow on merge to `main`.

## [0.1.0]

### Fixed

### Added

- Safety warning when a risky URL is entered directly in the address bar: the background worker
  watches `webNavigation` for omnibox navigations and pops the same confirmation the malicious-link
  guard uses when the destination is on the phishing blocklist or carries strong phishing traits,
  backing the tab out if declined. Adds the `webNavigation` permission.
- **Safety warnings** section in the options page with two toggles: **Warn before opening malicious
  links** (gates the existing red-link click confirmation) and **Warn when I type a risky address**.
- Preview chips in the **Content highlights** and **Link highlights** options: every toggle now shows
  a small page-like sample drawing the exact mark it controls (the red phrase highlight, the red
  password-form outline, and the green/blue/red link outlines, in the same colours the injected
  highlighters use), localized in both languages and dimmed while the toggle is off.

### Changed

- Options page restyled to match the extension icon: brand green replaces blue on toggles, links,
  focus rings and the Save button, the header shield glows, and a faint radar rings and sweep
  backdrop echoes the radar inside the shield. The sweep animation is disabled when the OS asks
  for reduced motion.
- Options page layout now supports ultrawide screens: the card grid has no width cap, flowing into
  as many columns as fit, with unused columns collapsed so the cards always fill the row. Cards
  pack masonry style: each card spans grid rows matching its own measured height (refreshed via a
  ResizeObserver), so short cards no longer leave tall empty bands before the next row.
- The Save button (with its saved status flash) moved from below the cards to the top right corner
  of the options page header, mirrored under RTL.
- Popup restyled to the same brand palette as the options page: the footer actions, inline key
  buttons, Analyze and modal buttons, and focus rings switch from blue to the brand green (with the
  same on-accent text and glow treatment), and the header shield logo glows. The shared green
  accent tokens moved into `styles/theme.css`. The category icon tiles keep their distinct palette.

## [0.0.1]

Initial project scaffold.

### Added

- Manifest V3 extension manifest with `storage`, `activeTab`, and `scripting` permissions.
- Popup entry point (`popup/popup.html`) wired into the toolbar action.
- Risk Radar shield-and-radar icon set (16/32/48/128 px PNG) plus the source SVG.
- Project README with overview, feature list, and local development instructions.
- Privacy policy (`PRIVACY.md`) and MIT license.
- GitHub Actions workflow to package the extension and publish to the Chrome Web Store on merge to `main`.
