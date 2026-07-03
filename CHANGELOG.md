# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Fixed

### Added

- Safety warning when a risky URL is entered directly in the address bar: the background worker
  watches `webNavigation` for omnibox navigations and pops the same confirmation the malicious-link
  guard uses when the destination is on the phishing blocklist or carries strong phishing traits,
  backing the tab out if declined. Adds the `webNavigation` permission.
- **Safety warnings** section in the options page with two toggles: **Warn before opening malicious
  links** (gates the existing red-link click confirmation) and **Warn when I type a risky address**.

### Changed

## [0.0.1]

Initial project scaffold.

### Added

- Manifest V3 extension manifest with `storage`, `activeTab`, and `scripting` permissions.
- Popup entry point (`popup/popup.html`) wired into the toolbar action.
- Risk Radar shield-and-radar icon set (16/32/48/128 px PNG) plus the source SVG.
- Project README with overview, feature list, and local development instructions.
- Privacy policy (`PRIVACY.md`) and MIT license.
- GitHub Actions workflow to package the extension and publish to the Chrome Web Store on merge to `main`.
