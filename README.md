<p align="center">
  <img src="assets/icon.svg" alt="Risk Radar logo" width="128" height="128">
</p>

<h1 align="center">Risk Radar</h1>

<p align="center">
  A Chromium browser extension that analyzes website trustworthiness and risk in real time —
  detecting phishing, social engineering, and manipulative content while you browse.
</p>

## Overview

Risk Radar inspects each site you visit and produces a **trust score (1–100)** alongside an
explanation of the risks it found. It combines URL analysis, page-content (DOM) inspection,
third-party reputation services, and an AI model to surface threats before they reach you.

## Features

- **URL analysis** — protocol, domain, and structure checks (e.g. HTTP vs. HTTPS).
- **Content scanning** — inspects the page DOM for suspicious patterns.
- **Link scanning** — evaluates internal and external links on the page.
- **Reputation integration** — Google Safe Browsing, VirusTotal, Sucuri SiteCheck, threat-filtering DNS (Cloudflare, Quad9), and server-IP reputation (SANS ISC / DShield).
- **AI analysis** — textual and behavioral analysis of page content via an API.
- **Clear results** — a trust score plus risk indicators, explained at varying levels of detail.

## How it works

1. You navigate to a website and the extension activates automatically.
2. It collects the page content, URL, and links.
3. Requests are sent to an AI service and reputation services (e.g. VirusTotal).
4. A risk score is calculated and displayed:
   - **Legitimate site** → high score, no warnings.
   - **Phishing site** → low score + a clear alert.
   - **New / unknown site** → intermediate score + an uncertainty note.

## Risk logic

Each check produces a status — **good** (✓), **warning** (!), or **risky** (✕) — and the
category's overall verdict reflects its worst finding.

### URL & Domain

| Check                   | How it's computed                                                  | Risk logic                                                                          |
| ----------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| **Protocol**            | `URL.protocol` of the active tab                                   | `https` → good; `http` → risky (traffic is unencrypted).                            |
| **Domain Age**          | Registration date via [RDAP](https://about.rdap.org/) (see below)  | `< 30 days` → risky; `< 6 months` → warning; otherwise good. Unknown registries are reported as _Unknown_. |
| **Subdomain**           | Hostname split into subdomain + registrable domain                 | Raw IP host → risky; deeply nested subdomains → warning; `www` or a single label → good. |
| **URL Length**          | Character count of the full URL                                    | `< 54` Short → good; `≤ 100` Medium → good; `> 100` Long → warning.                 |
| **Suspicious Keywords** | Host, path, and query scanned against a short phishing wordlist          | None → good; 1–2 matches → warning; 3+ matches → risky. Matches are listed.         |

**Domain age lookup.** Classic WHOIS runs over TCP port 43 and can't be reached from a browser,
so domain age is resolved with **RDAP** — the JSON-based successor to WHOIS. The extension queries
the IANA bootstrap endpoint `https://rdap.org/domain/<domain>`, which redirects to the authoritative
registry for the TLD, and reads the `registration` event date. It needs no API key and works from
the popup because the extension's `<all_urls>` host permission bypasses CORS.

### Reputation

This category cross-checks the host against external threat intelligence. **Five of the six checks run
without any API key** — Safe Browsing, Sucuri SiteCheck, Phishing Database, Blacklist Status, and Server
IP Reputation each produce a verdict keylessly. Only **VirusTotal** needs a key (its public API and web
UI are gated behind authentication and reCAPTCHA, so there is no honest keyless lookup); Safe Browsing
also accepts an optional key to upgrade it to Google's official API. A check that can't be completed (a
network or lookup failure, no data, or a missing key) is reported as _Unknown_ / _Not checked_ and
excluded from the verdict rather than counted as good — so the category's verdict reflects only the
checks that ran.

| Check                     | How it's computed                                                                                                         | Risk logic                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Google Safe Browsing**  | **Keyless by default:** the host is checked against Google's public [Transparency Report](https://transparencyreport.google.com/safe-browsing/search) endpoint (the backend of the "Safe Browsing site status" page). With a key, the official [Lookup API v4](https://developers.google.com/safe-browsing/v4/lookup-api) (`threatMatches:find`) is used instead. | Listed as a threat → risky (shown as _Unsafe_, or the matched threat with a key); clean → good; no data / error → _Unknown_. |
| **VirusTotal**            | **Keyed:** [VirusTotal API v3](https://docs.virustotal.com/reference/domain-info) (`/domains/<host>`) is queried with a key from Settings and `last_analysis_stats` read. (VirusTotal has no keyless lookup — both its API and web UI require authentication/reCAPTCHA.) | `malicious > 0` → risky; `suspicious > 0` → warning; otherwise good, showing `malicious / total` vendor verdicts. No key → _Not checked_ (excluded from the verdict). |
| **Sucuri SiteCheck**      | **Keyless:** the host is scanned via [Sucuri SiteCheck](https://sitecheck.sucuri.net/)'s public API (`/api/v3/?scan=<host>`), which aggregates several vendor blacklists (Google, Sucuri Labs, Norton, McAfee, ESET, Yandex, PhishTank…) plus its own malware checks. | A `blacklists` hit → _Blacklisted_ → risky; a `warnings.security` malware finding → _Unsafe_ → risky; a clean scan → good. A failed/timed-out scan → _Unknown_. |
| **Phishing Database**     | **Keyless:** the host is checked against a local, offline copy of the [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) project's active phishing-domain list (~600k domains), cached and kept current by the background worker (see below). | Host (or its registrable domain) on the list → _Listed_ → risky; not on it → _Not listed_ → good. While the first download is in progress → _Updating…_ (excluded). |
| **Blacklist Status**      | The host is resolved over [DNS-over-HTTPS](https://developer.mozilla.org/en-US/docs/Glossary/DoH) through two threat-filtering resolvers — Cloudflare (`security.cloudflare-dns.com`) and [Quad9](https://quad9.net/) (`dns.quad9.net`) — and compared with a non-filtering baseline (`dns.google`). | Either resolver sinkholes a host that otherwise resolves (a `0.0.0.0` answer or `NXDOMAIN`) → _Blacklisted_ → risky; both resolve normally → _Clean_ → good. Lookup error → _Unknown_. |
| **Server IP Reputation**  | **Keyless:** the host is resolved to its server IP, which is looked up in the [SANS ISC / DShield](https://isc.sans.edu/) database (`isc.sans.edu/api/ip/<ip>?json`) — a feed of addresses reported attacking internet honeypots. | The IP has attack reports → _Reported_ → warning; none → good. A shared **CDN/cloud** IP (Cloudflare, Akamai, AWS…) is reported as _Shared CDN_ → _Unknown_ and excluded, since it isn't the site's own server. Lookup error → _Unknown_. |

**Phishing.Database cache.** [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database)
is a first-class keyless source, but it ships as bulk flat files (the active domain list is ~10 MB) with
no per-host lookup — far too large to fetch on every popup. A **background service worker** therefore
downloads the list once into **IndexedDB** (`unlimitedStorage`), fully refreshes it daily and tops it up
hourly from the project's "new in the last hour" feed (both via `chrome.alarms`), and the popup queries
it with an instant, offline message round-trip. A listed registrable domain also covers its subdomains.

**Blacklist via filtering DNS.** The Blacklist check exploits the fact that security DNS resolvers
*sinkhole* known-malicious hosts: instead of the real address they return `0.0.0.0` (Cloudflare) or
`NXDOMAIN` (Quad9). The extension resolves the host once through a neutral baseline (`dns.google`) and
once through each filtering resolver via their JSON DoH endpoints; if the baseline resolves but a filter
does not, that resolver is treating the host as a threat. This needs no API key and works from the popup
because the `<all_urls>` host permission bypasses CORS. A transient resolver error (e.g. `SERVFAIL`) is
treated as _Unknown_, never as a positive hit.

**Server IP reputation (and why it's conservative).** IP blocklists track *attacking infrastructure*
(brute-force, scanning, spam) rather than phishing/malware hosting, and most sites today sit behind a
shared CDN/cloud address, so a raw IP verdict would be noisy or misleading. The check therefore (1)
detects shared CDN/cloud ranges by AS name and reports them as _Shared CDN_ (excluded from the verdict)
instead of judging an address that isn't the site's own, and (2) caps a positive hit at a **warning**,
never a hard "risky", because the signal is circumstantial. It's a complementary infrastructure angle,
not a primary trust signal.

**API keys.** The two keyed paths live under **Settings → Reputation** and are stored on-device in
`chrome.storage.local`. VirusTotal requires a (free-tier) key for its inline `malicious / total`
verdict — without one the row shows a _Key needed_ prompt with an **Add key** button that opens a modal
to enter it inline (no need to open Settings); the key is saved and the row re-runs immediately. Safe
Browsing's key is optional: it switches the check from the public Transparency Report to Google's
official Lookup API. The other four checks need no key at all.

## Tech stack

- **Languages:** TypeScript, HTML, CSS
- **Platform:** Chrome Extension API (Manifest V3), including a background service worker (IndexedDB + `chrome.alarms`)
- **External services:** AI and reputation APIs
- **CI/CD:** GitHub Actions
- **Version control:** Git / GitHub

## Installation

### From a release (recommended)

1. Download `RiskRadar.zip` from the [latest release](../../releases/latest).
2. Extract it to a folder.
3. Open `chrome://extensions/` and enable **Developer mode** (top-right).
4. Click **Load unpacked** and select the extracted folder.

## Development

This is a Manifest V3 extension written in TypeScript and bundled with [esbuild](https://esbuild.github.io/).
The source is **not** loaded directly — it is compiled into a `dist/` folder, which is what Chrome loads.

### Prerequisites

- [Node.js](https://nodejs.org/) 24 or newer

### Build and load

```bash
npm install      # install dev dependencies
npm run build    # compile TypeScript and copy assets into dist/
```

Then load it in Chrome:

1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** and select the generated **`dist/`** folder (not the repo root).

### Scripts

| Command             | Description                                             |
| ------------------- | ------------------------------------------------------- |
| `npm run build`     | Production build into `dist/`.                          |
| `npm run watch`     | Rebuild `dist/` automatically on file changes.          |
| `npm run typecheck` | Type-check the project with `tsc` (no output emitted).  |
| `npm run lint`      | Lint the project with ESLint.                           |
| `npm run lint:fix`  | Lint and auto-fix where possible.                       |

During development, run `npm run watch` and reload the extension from `chrome://extensions/`
after each rebuild.

See [PRIVACY.md](PRIVACY.md) for data-handling practices.
