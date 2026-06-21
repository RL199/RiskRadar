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

## Tech stack

- **Languages:** TypeScript, HTML, CSS
- **Platform:** Chrome Extension API (Manifest V3)
- **External services:** AI and reputation APIs
- **CI/CD:** GitHub Actions
- **Version control:** Git / GitHub

## Development

This is a Manifest V3 extension. To run it locally:

1. Open `chrome://extensions/` and enable **Developer mode**.
2. Choose **Load unpacked** and select this project folder.

See [PRIVACY.md](PRIVACY.md) for data-handling practices.
