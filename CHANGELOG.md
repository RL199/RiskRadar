# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1]

### Added
- The **Check the reputation of links I click** scan now has a **How to open the site while the
  check runs** choice in **Settings → Scanning**, with three modes. **Open the site right away and
  show the verdict overlay** (the default) keeps the existing behaviour: the site loads immediately
  and the corner overlay reports the verdicts. The two new wait modes park the tab on a Risk Radar
  checking page until the verdicts are in: a click whose addresses come back safe or unknown enters
  the site on its own, while one that comes back with a caution or dangerous verdict either offers a
  **Continue anyway** choice (**warn me if the site is not safe**) or is refused outright (**block
  the site if it is not safe**). The checking page replaces the held site's history entry, so **Go
  back** returns to the page the click started from rather than to the unchecked site.
- Two new tells in the **Suspicious Links** classification: a **plain `http:` destination** (the
  link's traffic is unencrypted) and **IPv6 literal hosts** (`http://[2001:db8::1]/`), which the
  existing raw-IP tell (previously IPv4 only) now also catches.

### Fixed
- The **displayed-vs-real URL mismatch** tell (Malicious Redirects) missed links whose visible text
  is a raw-IP URL, common on threat-feed listings where the text reads
  `http://105.224.66.14:53221/bin.sh` but the href opens a different page.


## [1.1.0]

### Added
- A phishing benchmark harness (`npm run bench:phish`, `test/phish-bench.ts`) that runs the shipped
  URL judgement (`classifyAddressBarUrl` plus the cached Phishing.Database blocklist) against live
  phishing feeds ([OpenPhish](https://openphish.com/phishing_feeds.html),
  [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), or a local
  [PhishTank](https://phishtank.org/developer_info.php) CSV) and the benign
  [Tranco top sites](https://tranco-list.eu/) list, reporting detection rate, false positive rate,
  and a per reason breakdown. Dev tooling only, no extension behaviour change.
- In settings, a **Check the reputation of links I click** toggle in the **Scanning** section, off by default.
  When on, following a link runs the six reputation checks (Google Safe Browsing, VirusTotal, Sucuri
  SiteCheck, Phishing Database, DNS blacklists, and server IP reputation) on both the clicked URL and
  the URL the navigation finally lands on, including a client side redirect right after the click,
  since shorteners and redirect wrappers often rewrite the destination mid flight. A small corner
  overlay shows a spinner while the checks run and then a colour coded verdict per address, dismissing
  itself when everything is clean and staying up with a close button when a warning or risky verdict
  appears.
- The **Links** category now checks every link on the page against the locally cached
  [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) blocklist, in both the
  popup and automatic scanning, with all of the page's link hosts resolved through the background
  worker in a single batch message so even thousands of links are checked instantly and offline.
  A link to a listed domain is flagged **Suspicious** with a "destination is on the phishing blocklist"
  reason that wins over every other bucket, and a single such link already turns the **Suspicious
  Links** row risky. Flagged links get the same red outline, hover label, and click guard (warn or
  block) as other red links.

### Changed
- The **Internal Links** and **External Links** highlight toggles in the **Link highlights** settings
  section are now **off by default**. These two buckets are informational rather than warnings, so
  their outlines are opt-in; the Suspicious Links and Malicious Redirects highlights stay on by
  default.
- The link scanner now reads up to 2,000 links per page (previously 500).

## [1.0.2]

### Added
- In settings, a **What to do when a risky navigation is caught** option in the **Safety warnings**
  section, deciding what both guards (the malicious-link click guard and the risky typed-address guard)
  do when they catch a risky navigation. **Warn** (the default) keeps the existing confirmation the user
  can accept to continue anyway; **Block** cancels the navigation outright and shows a message that the
  website is blocked: a click on a flagged link never navigates, and a risky typed address is backed out
  of unconditionally after the notice; **Do nothing** lets the navigation through with no interruption at
  all, while flagged links keep their outlines and hover labels.

### Removed
- The two **Safety warnings** toggles (**Warn before opening malicious links** and **Warn when I type a
  risky address**) were replaced by the single action option above, which always applies to both guards.
  Turning both off is now expressed by choosing **Do nothing**.

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
