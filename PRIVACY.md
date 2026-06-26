# Risk Radar Privacy Policy

Risk Radar is a Chromium browser extension that analyzes the trustworthiness of the
sites you visit. This policy explains exactly what data the extension touches, what
stays on your device, and what is sent to third parties (and only then, when and why).

## Summary

- **No accounts, no tracking, no analytics.** Risk Radar has no backend server of its
  own. It does not create an account, assign you an identifier, serve ads, or send any
  usage, telemetry, or analytics data anywhere.
- **Your settings and API keys stay on your device.** They live in
  `chrome.storage.local` and are never transmitted to us (there is no "us" to transmit
  to) or to anyone other than the matching service the key belongs to.
- **Most analysis is offline.** The URL, Content, and Links checks run entirely inside
  your browser. Page text and page links are read locally and are **not** sent anywhere
  for those checks.
- **Some checks query third parties about the site, not about you.** The Reputation and
  Domain Age checks send the **host name** (or its server IP) of the site you are
  actively viewing to public reputation and lookup services so they can return a verdict.
- **AI analysis is opt-in per page.** Page content is sent to an AI provider **only when
  you explicitly press "Analyze this page,"** and only to the provider you chose, under
  your own API key.

## What is stored on your device

All extension settings are saved locally in `chrome.storage.local` under a single
`settings` record and never leave your device except as noted below. This includes:

- Your theme and language preference.
- The per-page highlight toggles (which marks the extension draws on a page).
- Your selected AI provider and model.
- Your API keys: Claude (Anthropic), DeepSeek, Google Safe Browsing, and VirusTotal.

In addition, a **background service worker** keeps an offline copy of a public
phishing-domain list in **IndexedDB** so it can check the current host instantly. This
cache contains only the public blocklist itself; it holds none of your data and no
record of the sites you visit.

The extension keeps **no browsing history**. It analyzes the tab you are looking at when
you open the popup and does not log, store, or accumulate the pages you visit.

## What is sent to third parties, and when

### Runs when you open the popup on a page

For the site you are actively viewing, the extension contacts the services below. Except
for VirusTotal, these run keylessly and receive only the site's host name (or, for one
check, its resolved server IP). They are told about **the site you are visiting**, not
about you personally.

| Service | What is sent | Purpose | Provider policy |
| --- | --- | --- | --- |
| RDAP via [`rdap.org`](https://about.rdap.org/) (redirects to the TLD registry) | The site's domain name | Look up the domain's registration date (age) | Set by each TLD registry |
| Google Safe Browsing: [Transparency Report](https://transparencyreport.google.com/safe-browsing/search) (keyless) or [Lookup API](https://developers.google.com/safe-browsing/v4/lookup-api) (with your optional key) | The site's host/URL | Check the host against Google's threat list | [Google](https://policies.google.com/privacy) |
| [VirusTotal API](https://docs.virustotal.com/reference/domain-info) (**only if you add a key**) | The site's host **and your VirusTotal API key** | Read vendor verdicts for the domain | [VirusTotal](https://docs.virustotal.com/docs/virustotal-privacy-policy) |
| [Sucuri SiteCheck](https://sitecheck.sucuri.net/) (keyless) | The site's host | Aggregate blacklist / malware scan | [Sucuri](https://sucuri.net/privacy-policy/) |
| DNS over HTTPS via [`dns.google`](https://developers.google.com/speed/public-dns/docs/doh), [Cloudflare](https://developers.cloudflare.com/1.1.1.1/), and [Quad9](https://quad9.net/) | The site's host name | Detect threat-filtering resolvers that sinkhole the host | [Google](https://policies.google.com/privacy), [Cloudflare](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/), [Quad9](https://quad9.net/privacy/policy/) |
| [SANS ISC / DShield](https://isc.sans.edu/) | The site's resolved **server IP** | Check the server IP against an attack-reports feed | [SANS ISC](https://isc.sans.edu/privacy.html) |

### Runs in the background

The service worker periodically downloads a public phishing-domain blocklist from
[`raw.githubusercontent.com`](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
(the [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) project).
This is an ordinary file download. It sends **no information about you or the sites you
visit**; it only fetches the list.

### Runs only when you click "Analyze this page" (AI analysis)

This is the **only** feature that sends page content off your device, and it never runs
on its own. When you press **Analyze this page** (or **Re-analyze**), the extension
sends a small summary of the current page to the AI provider you selected, using your
own API key:

- The page **title** and **host**.
- The page's **visible text**, capped at roughly 6,000 characters.
- The number of **password fields** and a per-form note of whether a password form
  leaves its origin or uses plain HTTP.

The request goes **only** to the provider you chose:

- **Claude**: Anthropic's [Messages API](https://docs.claude.com/en/api/messages)
  (`api.anthropic.com`). See [Anthropic's Privacy Policy](https://www.anthropic.com/legal/privacy).
  Inputs and outputs sent through the API are handled under Anthropic's
  [Commercial Terms](https://www.anthropic.com/legal/commercial-terms).
- **DeepSeek**: the [chat completions endpoint](https://api-docs.deepseek.com/api/create-chat-completion)
  (`api.deepseek.com`). See [DeepSeek's Privacy Policy](https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html).

Because the page summary is processed under **your own API key**, its handling,
retention, and any use for model training are governed by **that provider's terms**, not
by Risk Radar. Review the provider's policy before enabling AI analysis on sensitive
pages, and avoid running it on pages containing personal or confidential information you
do not want to share with a third party.

## What is never sent anywhere

The URL, Content, and Links categories are fully offline. The page's DOM text, its
forms, and its links are read **inside your browser only** and are used solely to compute
the on-screen verdict and to draw the highlights on the page. None of that content is
transmitted for those checks. (Page text reaches a third party only through the opt-in AI
analysis described above.)

## Permissions and why they are needed

- **`storage` / `unlimitedStorage`**: save your settings and API keys, and cache the
  offline phishing blocklist locally.
- **`activeTab` + `scripting`**: read the current tab's content and links (and draw the
  highlights) only when you open the popup on that tab.
- **`alarms`**: schedule the periodic refresh of the offline blocklist.
- **`host_permissions: <all_urls>`**: let the extension analyze whatever site you are on
  and reach the reputation, lookup, and (opt-in) AI services from the extension page. This
  permission is used to fetch verdicts, not to monitor your browsing.

## Data sharing and sale

Risk Radar does not sell, rent, or share your data. There is no advertising, no
profiling, and no third-party analytics. The only outbound requests are the
service-by-service lookups described above, each made to answer a check about the site
you are viewing.

## Children

Risk Radar is a general-purpose security tool and is not directed at children.

## Changes to this policy

If the extension's data practices change, this document will be updated and the "Last
updated" date above will change. Material changes will be reflected here and in the
extension's release notes.

## Contact

Questions about this policy or the extension's data handling can be raised as an issue on
the project's GitHub repository, or by email to **rrooyy199@gmail.com**.
