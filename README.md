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
- **Reputation integration** — third-party services such as VirusTotal.
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

## Tech stack

- **Languages:** TypeScript, HTML, CSS
- **Platform:** Chrome Extension API (Manifest V3)
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
