<p align="center">
  <img src="assets/icon.svg" alt="Risk Radar logo" width="128" height="128">
</p>

<h1 align="center">Risk Radar</h1>

<p align="center">
  A Chromium browser extension that analyzes website trustworthiness and risk in real time,
  detecting phishing, social engineering, and manipulative content while you browse.
</p>

## Overview

Risk Radar inspects each site you visit and produces a **trust score (1 to 100)** alongside an
explanation of the risks it found. It combines URL analysis, page-content (DOM) inspection,
third-party reputation services, and an AI model to surface threats before they reach you.

## Features

- **URL analysis:** protocol, domain, and structure checks (e.g. HTTP vs. HTTPS).
- **Content scanning:** inspects the page DOM for suspicious patterns, and marks the matches on the page.
- **Link scanning:** classifies the page's links into internal, external, suspicious, and malicious redirects, marks them on the page, and warns before following a red (suspicious or malicious-redirect) link.
- **Reputation integration:** Google Safe Browsing, VirusTotal, Sucuri SiteCheck, threat-filtering DNS (Cloudflare, Quad9), and server-IP reputation (SANS ISC / DShield).
- **AI analysis:** on-demand phishing / social-engineering assessment of the page by a large language model (Claude or DeepSeek, your choice).
- **Automatic scanning (optional):** scan every page as you browse without opening the popup, surfacing the verdict as a colour-coded badge and a matching tint on the toolbar icon, and applying the on-page highlights.
- **Safety warnings (optional):** a confirmation prompt before following a malicious link, and before a risky address you type into the URL bar is allowed to stay. Each can be toggled independently in the options page.
- **Clear results:** a trust score plus risk indicators, explained at varying levels of detail.

## How it works

1. You navigate to a website and the extension activates automatically.
2. It collects the page content, URL, and links.
3. Requests are sent to an AI service and reputation services (e.g. VirusTotal).
4. A risk score is calculated and displayed:
   - **Legitimate site** → high score, no warnings.
   - **Phishing site** → low score + a clear alert.
   - **New / unknown site** → intermediate score + an uncertainty note.

## Risk logic

Each check produces a status, either **good** (✓), **warning** (!), or **risky** (✕), and the
category's overall verdict reflects its worst finding. While a category is still scanning, its chip on
the main list reads a muted **Loading** rather than a verdict, so a stale or default "Good" is never
shown mid-scan; it switches to the real verdict once that category finishes (the AI chip instead reads
**Not run** until a scan starts, then **Loading** while it runs). The five category verdicts roll up
into a single **trust score (1 to 100)** shown in the header ring (see [Trust score](#trust-score)
below); the dot beside the site name, and the extension's **toolbar icon**, both take the colour of that
score's band (green / amber / red), so the icon in the toolbar reflects the verdict even after the popup
is closed. Both the ring and the dot show a muted pulse
while the automatic categories scan, then settle once every expected category is in (or stay muted with
a "Can't scan this page" note on pages with no scannable content, such as `chrome://` pages). AI
analysis is on demand, so it feeds the score only when a scan actually runs (auto mode on open, or when
you press Analyze): the header returns to its scanning pulse and folds the AI verdict into the score once
it finishes. In manual mode without a scan, the score is computed from the four automatic categories alone.

The footer's **Rescan** button re-runs every category against the current tab from a clean slate: it
clears the header score back to its scanning pulse, re-runs the four automatic categories, and resets
the AI view to idle (re-running it too only in automatic mode with a key already set, so a rescan never
bills you unprompted or pops the key modal).

### Trust score

The header number is a weighted average of the category verdicts with hard caps, so a broadly clean
site scores high while a single authoritative red flag can never be averaged away into a green score.

1. **Weighted average.** Each determinate category verdict maps to points (good = 100, warning = 55,
   risky = 10) and is combined by weight: **Reputation 0.40, AI 0.20, Content 0.20, URL 0.15, Links
   0.05**. Reputation leads because it is the only category backed by authoritative threat intelligence;
   outbound links are the lightest signal. Categories that come back _Unknown_ (or the AI when it hasn't
   run) are left out and the remaining weights are renormalized, so a missing check never skews the score.
2. **Hard caps.** A **confirmed-malicious** signal caps the score at **15** (deep red): an authoritative
   blocklist/malware hit (Safe Browsing, VirusTotal _malicious_, Sucuri, Phishing Database, or a DNS
   sinkhole) or a password form that submits credentials in cleartext. Failing that, a **strong phishing
   heuristic** caps it at **49** (no higher than the warning band): a raw-IP host, a brand-new domain
   (< 30 days), brand impersonation on a credential page, or the AI rating the page high-risk. Softer
   signals (a long URL, urgent wording, a cross-origin login form, suspicious outbound links) only lower
   the average; they never cap.
3. **Bands.** The final 1-100 score is coloured by the same thirds the rows use: **67-100** safe (green),
   **34-66** caution (amber), **1-33** dangerous (red). A page with nothing determinate to score shows a
   muted "Can't scan this page" instead of a number.

### URL & Domain

| Check                   | How it's computed                                                  | Risk logic                                                                          |
| ----------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| **Protocol**            | `URL.protocol` of the active tab                                   | `https` → good; `http` → risky (traffic is unencrypted).                            |
| **Domain Age**          | Registration date via [RDAP](https://about.rdap.org/) (see below)  | `< 30 days` → risky; `< 6 months` → warning; otherwise good. Unknown registries are reported as _Unknown_. |
| **Subdomain**           | Hostname split into subdomain + registrable domain                 | Raw IP host → risky; deeply nested subdomains → warning; `www` or a single label → good. |
| **URL Length**          | Character count of the full URL                                    | `< 54` Short → good; `≤ 100` Medium → good; `> 100` Long → warning.                 |
| **Suspicious Keywords** | Host, path, and query scanned against a short phishing wordlist          | None → good; 1 to 2 matches → warning; 3+ matches → risky. Matches are listed.         |

**Domain age lookup.** Classic WHOIS runs over TCP port 43 and can't be reached from a browser,
so domain age is resolved with **RDAP**, the JSON-based successor to WHOIS. The extension queries
the IANA bootstrap endpoint `https://rdap.org/domain/<domain>`, which redirects to the authoritative
registry for the TLD, and reads the `registration` event date. It needs no API key and works from
the popup because the extension's `<all_urls>` host permission bypasses CORS.

### Reputation

This category cross-checks the host against external threat intelligence. **Five of the six checks run
without any API key**: Safe Browsing, Sucuri SiteCheck, Phishing Database, Blacklist Status, and Server
IP Reputation each produce a verdict keylessly. Only **VirusTotal** needs a key (its public API and web
UI are gated behind authentication and reCAPTCHA, so there is no honest keyless lookup); Safe Browsing
also accepts an optional key to upgrade it to Google's official API. A check that can't be completed (a
network or lookup failure, no data, or a missing key) is reported as _Unknown_ / _Not checked_ and
excluded from the verdict rather than counted as good, so the category's verdict reflects only the
checks that ran.

| Check                     | How it's computed                                                                                                         | Risk logic                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Google Safe Browsing**  | **Keyless by default:** the host is checked against Google's public [Transparency Report](https://transparencyreport.google.com/safe-browsing/search) endpoint (the backend of the "Safe Browsing site status" page). With a key, the official [Lookup API v4](https://developers.google.com/safe-browsing/v4/lookup-api) (`threatMatches:find`) is used instead. | Listed as a threat → risky (shown as _Unsafe_, or the matched threat with a key); clean → good; no data / error → _Unknown_. |
| **VirusTotal**            | **Keyed:** [VirusTotal API v3](https://docs.virustotal.com/reference/domain-info) (`/domains/<host>`) is queried with a key from Settings and `last_analysis_stats` read. (VirusTotal has no keyless lookup; both its API and web UI require authentication/reCAPTCHA.) | `malicious > 0` → risky; `suspicious > 0` → warning; otherwise good, showing `malicious / total` vendor verdicts. No key → _Not checked_ (excluded from the verdict). |
| **Sucuri SiteCheck**      | **Keyless:** the host is scanned via [Sucuri SiteCheck](https://sitecheck.sucuri.net/)'s public API (`/api/v3/?scan=<host>`), which aggregates several vendor blacklists (Google, Sucuri Labs, Norton, McAfee, ESET, Yandex, PhishTank…) plus its own malware checks. | A `blacklists` hit → _Blacklisted_ → risky; a `warnings.security` malware finding → _Unsafe_ → risky; a clean scan → good. A failed/timed-out scan → _Unknown_. |
| **Phishing Database**     | **Keyless:** the host is checked against a local, offline copy of the [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) project's active phishing-domain list (~600k domains), cached and kept current by the background worker (see below). | Host (or its registrable domain) on the list → _Listed_ → risky; not on it → _Not listed_ → good. While the first download is in progress → _Updating…_ (excluded). |
| **Blacklist Status**      | The host is resolved over [DNS-over-HTTPS](https://developer.mozilla.org/en-US/docs/Glossary/DoH) through two threat-filtering resolvers, Cloudflare (`security.cloudflare-dns.com`) and [Quad9](https://quad9.net/) (`dns.quad9.net`), and compared with a non-filtering baseline (`dns.google`). | Either resolver sinkholes a host that otherwise resolves (a `0.0.0.0` answer or `NXDOMAIN`) → _Blacklisted_ → risky; both resolve normally → _Clean_ → good. Lookup error → _Unknown_. |
| **Server IP Reputation**  | **Keyless:** the host is resolved to its server IP, which is looked up in the [SANS ISC / DShield](https://isc.sans.edu/) database (`isc.sans.edu/api/ip/<ip>?json`), a feed of addresses reported attacking internet honeypots. | The IP has attack reports → _Reported_ → warning; none → good. A shared **CDN/cloud** IP (Cloudflare, Akamai, AWS…) is reported as _Shared CDN_ → _Unknown_ and excluded, since it isn't the site's own server. Lookup error → _Unknown_. |

**Phishing.Database cache.** [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database)
is a first-class keyless source, but it ships as bulk flat files (the active domain list is ~10 MB) with
no per-host lookup, far too large to fetch on every popup. A **background service worker** therefore
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
verdict; without one the row shows a _Key needed_ prompt with an **Add key** button that opens a modal
to enter it inline (no need to open Settings); the key is saved and the row re-runs immediately. Safe
Browsing's key is optional: it switches the check from the public Transparency Report to Google's
official Lookup API. The other four checks need no key at all.

### Content

This category inspects the **page itself** rather than its URL or reputation. Because the popup can't
read another tab's DOM directly, it injects a small, self-contained extractor into the active tab with
[`chrome.scripting.executeScript`](https://developer.chrome.com/docs/extensions/reference/api/scripting)
(granted by `activeTab` + `scripting` + the `<all_urls>` host permission). The extractor returns a tiny
JSON summary: the page title, its visible text (capped), the number of password fields, and a per-form
note of whether each password form leaves the origin or uses plain HTTP. The risk logic then runs in the
popup. Pages with no readable DOM (a `chrome://` page, the new-tab page, the Web Store) are reported as
_Unknown_ and excluded from the verdict. All four checks are offline and textual/structural; no page
content ever leaves the browser.

| Check                    | How it's computed                                                                                                                                            | Risk logic                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| **Phishing Indicators**  | The page title + visible text are scanned for a curated list of **credential-bait phrases** ("verify your account", "confirm your password", "unusual sign-in activity"…). | None → good; 1 to 2 matches → warning; 3+ → risky. The count is shown, and the matched phrases are listed under the row.                                   |
| **Suspicious Forms**     | Every `<form>` containing an `<input type="password">` is checked: does it submit to a **different registrable domain** (cross-origin) or over **plain HTTP**?       | No such form → good; a cross-origin (HTTPS) password POST → warning; a cleartext **HTTP** password POST → risky. The count is shown, and the kind of leak (cleartext HTTP and/or cross-domain) is listed under the row. |
| **Urgent Language**      | The title + text are scanned for **time-pressure / fear wording** ("act now", "within 24 hours", "final notice", "your account will be suspended"…).            | None → good; 1 to 2 matches → warning; 3+ → risky. The count is shown, and the matched phrases are listed under the row.                                   |
| **Brand Impersonation**  | A well-known brand (Microsoft, Google, Amazon, Apple, PayPal, banks, couriers…) is named in the title/text while the host **isn't** one of that brand's own domains, **and** the page asks for a password. | Mismatch on a credential-entry page → risky, naming the impersonated brand and listing the brand wording that matched; otherwise good.                 |

**The wordlists ("small database").** The phrases and brands the three text checks match against live in
their own module, [`scripts/shared/content-data.ts`](scripts/shared/content-data.ts), separate from the
matching logic so they can grow without touching the algorithms. The phishing/urgency wording follows
common phishing-email keyword round-ups ([Expel](https://expel.com/blog/top-phishing-keywords/),
[KnowBe4](https://blog.knowbe4.com/a-look-at-phishing-keywords),
[MetaCompliance](https://www.metacompliance.com/blog/phishing-and-ransomware/words-terminology-phishing-emails),
[TechRepublic](https://www.techrepublic.com/article/the-top-keywords-used-in-phishing-email-subject-lines/)),
and the brand table follows the quarterly _most-impersonated-brand_ reports
([Check Point Research](https://blog.checkpoint.com/research/microsoft-remains-the-most-imitated-brand-in-phishing-attacks-in-q4-2025/)'s
Q4 2025 top ten was Microsoft, Google, Amazon, Apple, Facebook/Meta, PayPal, Adobe, Booking, DHL and
LinkedIn), extended with the shipping
(FedEx, UPS, USPS), banking (Chase, Wells Fargo, Bank of America, Citi, Amex…), crypto (Coinbase, Binance)
and gaming (Roblox, Steam) brands phishing kits routinely clone. Each brand carries both the phrases that
signal it and the set of registrable labels that are legitimately its own.

**Hebrew (Israel) coverage.** The same three text checks also carry the wording Israeli phishing SMS,
emails and pages actually use (for example `פעילות חשודה בחשבון`, `החשבון שלך נחסם`, `לאמת את החשבון`,
`חבילה ממתינה במכס`, `חוב אגרה`, and urgency wording like `דחוף`, `תוך 24 שעות`, `לחץ על הקישור`), plus
the local bodies most impersonated in Israel: Highway 6 (כביש 6) tolls, the banks and credit-card issuers
(Bank Hapoalim, Leumi, Discount, Mizrahi-Tefahot, Isracard, Cal, Max), Israel Post (דואר ישראל), the Tax
Authority, El Al, the Electric Company and National Insurance. This follows Israeli phishing round-ups and
national guidance: [mako](https://www.mako.co.il/nexter-news/Article-0e0541aa5257c91027.htm) and
[Ynet](https://www.ynet.co.il/digital/technews/article/byvvjxhfj) on the most-impersonated bodies and the
most common local scam messages, the Israel National Cyber Directorate's
[how-to-recognize-phishing guide](https://www.gov.il/en/pages/recognize_phishing_2711),
[ISOC-IL](https://www.isoc.org.il/digital-literacy/online-safety-guides/guides-users/how-to-spot-phishing),
[Israel Post's own fake-SMS notice](https://israelpost.co.il/%D7%A9%D7%99%D7%A8%D7%95%D7%AA%D7%99%D7%9D/sms-%D7%9E%D7%94%D7%93%D7%95%D7%90%D7%A8-%D7%9B%D7%9A-%D7%AA%D7%95%D7%95%D7%93%D7%90%D7%95-%D7%A9%D7%9C%D7%90-%D7%9E%D7%93%D7%95%D7%91%D7%A8-%D7%91%D7%94%D7%95%D7%93%D7%A2%D7%AA-%D7%A4%D7%99%D7%A9%D7%99%D7%A0%D7%92/),
a [penetrationtest.co.il SMS-fraud guide](https://penetrationtest.co.il/sms-fraud/), and the
[Jerusalem Post report on the Israel Electric scam](https://www.jpost.com/israel-news/israel-electric-warns-of-phishing-scam-trying-to-steal-customer-details-673983).

> **Note.** These are deliberately **short, hardcoded lists**; they cover the *most common* phishing
> wording and the *most-impersonated* brands rather than aiming to be exhaustive. The goal is to catch
> typical attacks while keeping false positives low; the lists can be extended at any time in
> [`content-data.ts`](scripts/shared/content-data.ts).

**Matching is whole-word and de-duplicated.** Text is matched case-insensitively with the page's title and
body folded to one normalized string (smart quotes → ASCII, whitespace collapsed so a phrase still matches
across a line break). Terms match on **word boundaries**, so a short token like `ups` can't fire inside
`backups` and `apple` can't fire inside `pineapple`. The boundary is **Unicode-aware** (it treats any
Unicode letter or number as a word character) rather than the ASCII-only `\b`, so the Hebrew terms match
exactly the same whole-word way the English ones do. When a broad term and a more specific one cover the
same text (`action required` inside `immediate action required`), only the longer match is counted, so a
single phrase can't inflate the score.

**How the page is read.** The extractor (`extractPageContent` in `scripts/shared/content-analysis.ts`)
is written to be fully self-contained, referencing no imports or module-scope helpers, only the page's
DOM, so it survives being serialized and run in the page's world by `executeScript`. It runs in the
content script's isolated world, which is enough to read the DOM (it never needs to touch page-script
state). The popup then judges the returned summary, keeping all the risk logic in one shared, testable
module alongside the URL and Reputation checks.

**Why Brand Impersonation is gated on a password field.** Most pages mention big brands harmlessly: a
"Log in with Google" button, a "We accept PayPal" footer, a news article. Flagging every mention would
be noise. Impersonation only *matters* where it harvests credentials, so the check fires only when the
page also has a password field, which sharply cuts false positives (a stated project goal). The host is
compared by its **registrable primary label** (the part before the public suffix), so a brand's many
legitimate domains and ccTLDs (`google.com`, `google.co.uk`, `microsoftonline.com`) all count as genuine,
while look-alikes (`paypal-secure.tk`, `microsoft-verify.com`) do not.

**Why the form check distinguishes HTTP from cross-origin.** A password field that POSTs over plain HTTP
sends credentials in clear text, an unambiguous, hard risk. A password field that POSTs cross-origin
over HTTPS is *suspicious* but can be legitimate (federated/SSO login often posts to an auth domain), so
it's capped at a warning rather than treated as a certain compromise.

**Marking matches on the page.** Besides listing what it found in the popup, the Content view marks the
same findings on the page itself. After scanning, the popup injects a second self-contained function
(`highlightPageMatches`) that gives every flagged phrase (phishing wording, urgent language, and the
matched brand keywords) a **light red highlight**, and every **suspicious password form** a **red
outline**. Hovering a mark names its category (for example _"Phishing Indicators"_, _"Urgent Language"_,
or _"Suspicious Forms"_), so it's clear at a glance why each was flagged. The phrase highlight uses the
[CSS Custom Highlight API](https://developer.mozilla.org/en-US/docs/Web/API/CSS_Custom_Highlight_API),
which paints text ranges without inserting any wrapper elements, so it never changes the page's structure;
because a painted highlight can't carry a tooltip, the popup hit-tests the cursor against the marked ranges
on hover and shows a small floating label, while a form (a real element) uses a native `title`. The marks
are non-destructive and reversible (the form outline and any borrowed `title` are restored on the next
scan), the highlighter runs in the page's **main world** so it shares the page's CSS highlight registry,
and re-running clears the previous pass so a now-clean page is left unmarked. Each of these marks
(Phishing Indicators, Urgent Language, Brand Impersonation, and Suspicious Forms) can be **switched off
individually** from the **Content highlights** section of the options page, where every toggle shows a
**live preview chip** of its mark (a sample flagged phrase with the red text highlight, and a mock
password field with the red form outline) so it's clear what each switch turns off; a disabled category
is simply left unmarked on the next scan.

> **A note on false positives.** Several of these signals also show up on perfectly legitimate pages: your
> bank's real login genuinely says "verify your account", a real promotion genuinely says "limited time
> offer" or "act now", and a real federated login genuinely posts your password to a separate auth domain.
> Risk Radar treats each check as an **advisory signal, not a standalone verdict**, and is tuned to keep
> these cases quiet: it never blocks a page, the wording checks need **three or more** matches before they
> turn risky (one or two are only a warning), Brand Impersonation fires only when the page also asks for a
> password, and a cross-origin (HTTPS) password form is capped at a warning rather than called a certain
> compromise. Because every match is **listed in the popup and highlighted on the page**, you can see
> exactly what was flagged and judge it in context. A flagged legitimate page is expected now and then;
> weigh the Content verdict alongside the URL, Reputation, and Links categories rather than on its own.

### Links

This category inspects the **links on the page** rather than the page's own URL or reputation. Like
Content, the popup can't read another tab's DOM directly, so it injects a small, self-contained extractor
([`extractPageLinks` in `scripts/shared/link-analysis.ts`](scripts/shared/link-analysis.ts)) into the
active tab with [`chrome.scripting.executeScript`](https://developer.chrome.com/docs/extensions/reference/api/scripting)
(granted by `activeTab` + `scripting` + the `<all_urls>` host permission). The extractor returns a tiny
JSON summary: the page URL, the total number of `<a href>` links, and, for the first 500 in document
order, each link's resolved href and visible text. The risk logic then runs in the popup, sorting every
link into one bucket: **internal** (same registrable domain), **external** (a different domain with no
risk traits), **suspicious**, **redirect**, or **ignore** (a `mailto:` / `tel:` / `javascript:` link or a
same-page `#` anchor). Pages with no readable DOM (a `chrome://` page, the new-tab page, the Web Store)
are reported as _Unknown_ and excluded from the verdict. All checks are offline; no link ever leaves the
browser.

| Check                    | How it's computed                                                                                          | Risk logic                                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **Total Links**          | Count of every `<a href>` on the page.                                                                     | Informational; never affects the verdict.                                                                          |
| **External Links**       | Links whose **registrable domain differs** from the page's.                                                | Normal and expected → good. The distinct external domains are listed.                                              |
| **Suspicious Links**     | External links whose **destination itself** looks dangerous (see below).                                   | None → good; 1 to 2 → warning; 3+ → risky. The flagged hosts are listed.                                           |
| **Malicious Redirects**  | Links that **hide or bounce** their true destination (see below).                                          | None → good; a parameter bounce → warning; a displayed-vs-real URL mismatch → risky. The destinations are listed.  |

**What makes a link "suspicious".** A suspicious link points off-site to a destination that itself carries
a phishing tell, drawn from the standard anti-phishing URL indicators (CISA, the APWG, OWASP): a raw **IP
address** host; a **punycode / IDN homograph** domain (`xn--`); **credentials embedded in the URL**
(`https://paypal.com@evil.com`); a **brand look-alike**, where a known brand token appears in the host but
the registrable domain is not that brand's (`paypal.secure-login.com`); a **URL shortener** that hides the
real destination; **unusually deep subdomains** (`login.account.secure.verify.evil.tld`); or **stacked
phishing keywords** in the host (two or more of `secure`, `login`, `verify`, `account`… as in
`secure-account-login.com`). Single signals are kept high-signal to limit false positives (a stated
project goal): a lone `login.` subdomain, a real brand domain, and an ordinary external link all stay good.

**What counts as a "malicious redirect".** A redirect is a link that **disguises where it really goes**,
caught before the internal/external check so an open redirect hosted on the page's own trusted domain is
still flagged. Two patterns are detected: an **open-redirect parameter** carrying an absolute off-domain
URL (`https://trusted.com/out?url=https://evil.com`, scanning common parameter names like `url`, `next`,
`redirect`, `dest`, `continue` in both the query and the fragment); and a **displayed-vs-real URL
mismatch**, where the visible link text is presented as one domain (`https://www.mybank.com/login`) while
the href opens another. A redirect that stays within the same domain family (a `continue=` back to a
sibling subdomain) is not flagged.

**The look-alike token list and shorteners.** The distinctive brand tokens the look-alike check watches
for live alongside the Content wordlists in
[`scripts/shared/content-data.ts`](scripts/shared/content-data.ts) (`BRAND_URL_TOKENS`), kept to long,
unambiguous brand words so short or dictionary-ish labels don't trip it. The shortener and redirect
parameter lists live in [`link-analysis.ts`](scripts/shared/link-analysis.ts) and can be extended at any
time.

**Marking links on the page.** After scanning, the popup injects a second self-contained function
(`highlightPageLinks`) that outlines the same links on the page itself, in document order so each mark
lines up with its verdict: **internal links get a subtle green outline**, **suspicious links and malicious
redirects a red one**, and **every mark carries a hover label** naming exactly what it is (greens
included), for example _"Internal link (same domain)"_, _"Suspicious link: domain imitates a known brand"_,
or _"Malicious redirect: link text shows a different domain than it opens"_. The marks are non-destructive
(an `outline` plus a borrowed `title`, both restored on the next scan) and re-running clears the previous
pass. **Benign external links are counted but deliberately not painted red:** an ordinary page links out
to many legitimate sites (CDNs, social, references), so flagging every external link would bury the real
warnings; only off-site links with an actual phishing tell are marked. Each link bucket (Internal,
External, Suspicious, and Malicious Redirects) can be **switched off individually** from the **Link
highlights** section of the options page, where every toggle shows a **live preview chip** of its outline
(a sample link drawn in that bucket's exact colour and weight) so it's clear what each switch turns off;
a disabled bucket is left unmarked on the next scan.

**Warning before following a red link.** Marking alone is passive, so the highlighter also **guards clicks
on the red links**: clicking a suspicious link or a malicious redirect pops a
[`confirm()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/confirm) naming what was flagged,
its reason, and the real destination host, and the page only navigates if the user chooses to continue.
A single capture-phase listener on the document drives every guarded link (it reads a per-anchor
`data-riskradar-warn` attribute holding the message, set from the same dictionary as the hover label), so
re-scans never stack listeners; the guard covers `click` (left- and modifier-clicks) and `auxclick`
(middle-click open-in-new-tab). Only the red buckets are guarded, so the green/blue internal and external
links navigate untouched, and a bucket switched off in the **Link highlights** options is neither marked
nor guarded. This click guard can be turned off with the **Warn before opening malicious links** toggle in
the **Safety warnings** section of the options page; when off, red links are still outlined but clicking
one navigates without a prompt.

**Warning on a risky address typed into the URL bar.** The same confirmation also protects URLs the user
enters directly in the address bar, not just links clicked on a page. The background worker listens on
[`chrome.webNavigation.onCommitted`](https://developer.chrome.com/docs/extensions/reference/api/webNavigation#event-onCommitted)
and, for a main-frame navigation the browser tags as coming from the omnibox (a `typed` / `generated` /
`keyword` transition, or the `from_address_bar` qualifier), judges the destination the moment it commits.
A host on the offline [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) blocklist,
or a URL carrying a strong phishing tell (an IP-literal host, a punycode/IDN homograph, embedded
credentials, a brand look-alike, a link shortener, unusually deep subdomains, stacked phishing keywords, or
an off-domain redirect parameter — the same tells the Links view uses, reused via `classifyAddressBarUrl`),
triggers the same-style
[`confirm()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/confirm). Because `confirm()` blocks
the page's own scripts while it is open, catching it at commit time means declining can step the tab back
off the page (via [`chrome.tabs.goBack`](https://developer.chrome.com/docs/extensions/reference/api/tabs#method-goBack),
or a blank tab when there is no history) before the site really runs. This guard is governed by the
**Warn when I type a risky address** toggle in the **Safety warnings** section, and needs the
[`webNavigation`](https://developer.chrome.com/docs/extensions/reference/api/webNavigation) permission.

### AI

Where the other four categories are heuristic and offline (URL, Content, Links) or query keyless
reputation feeds (Reputation), this category asks a **large language model** to read the page and judge
its intent. It reuses the same self-contained extractor as Content
([`extractPageContent`](scripts/shared/content-analysis.ts)) to gather a small JSON summary (title, host,
visible text capped at ~6,000 characters, password-field count, and a per-form leak note), sends it to the
chosen provider, and renders the model's structured verdict. The risk logic and both API calls live in
[`scripts/shared/ai-analysis.ts`](scripts/shared/ai-analysis.ts).

| Check                     | How it's computed                                                                 | Risk logic                                                                           |
| ------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **Phishing Probability**  | The model returns a `0`–`100` likelihood that the page is a phishing attempt.      | `< 34` → good; `34`–`66` → warning; `≥ 67` → risky. Shown as a percentage.            |
| **Social Engineering**    | The model rates the page's manipulation / pressure as `low` / `medium` / `high`.   | `low` → good; `medium` → warning; `high` → risky.                                     |
| **Content Risk Score**    | The model returns an overall `0`–`100` content-risk score.                          | `< 34` → good; `34`–`66` → warning; `≥ 67` → risky. Shown as `score / 100`.           |
| **Summary**               | One or two sentences from the model explaining its verdict.                         | Shown in the **Summary** note; the category verdict is the worst of the three rows.  |

**On-demand by default.** Unlike the other categories (which run for free on every popup open), an
AI request costs money per scan, so by default this category never calls the API on its own: the view
opens in an idle state and only contacts the model when you press **Analyze this page** (and
**Re-analyze** afterwards). No page content is sent anywhere until you click.

**When to scan with AI.** A **Settings → AI** dropdown (`aiScanMode` in `chrome.storage.local`,
default `manual`) chooses when the scan runs: **When I click Analyze** keeps the on-demand behaviour
above, while **Automatically when the popup opens** runs the analysis as soon as the popup opens on a
scannable page. Automatic mode only fires when a key for the selected provider is already set, so
opening the popup never pops the key modal unprompted; without a key it falls back to the idle state
until you click. Because automatic mode bills your provider on every popup open, the dropdown's help
text spells that out.

**Two providers, your choice.** A provider selector in the view chooses between **Claude** and
**DeepSeek**; the choice is saved on-device (`aiProvider` in `chrome.storage.local`). Both keys live under
**Settings → AI**; if the selected provider has no key yet, the button becomes **Add key** and opens the
same inline key modal the Reputation view uses, then runs the analysis. Both are called directly from the
popup with `fetch` (no SDK) — the `<all_urls>` host permission lets the extension reach
`api.anthropic.com` and `api.deepseek.com` cross-origin.

**Pick the model.** Each provider has a model dropdown under **Settings → AI**, saved on-device
(`claudeModel` / `deepseekModel` in `chrome.storage.local`). The available options live in `CLAUDE_MODELS`
and `DEEPSEEK_MODELS` in `ai-analysis.ts`, so adding or removing a model is a one-line change there:

- **Claude** — Anthropic's [Messages API](https://docs.claude.com/en/api/messages) (`POST
  https://api.anthropic.com/v1/messages`), choosing between
  [Opus 4.8, Sonnet 4.6, and Haiku 4.5](https://docs.claude.com/en/docs/about-claude/models/overview)
  (default **Sonnet 4.6**). The response shape is pinned with
  [structured outputs](https://docs.claude.com/en/docs/build-with-claude/structured-outputs)
  (`output_config.format` + a JSON schema), and the
  [`anthropic-dangerous-direct-browser-access`](https://docs.claude.com/en/api/client-sdks) header opts
  the extension page into direct browser calls.
- **DeepSeek** — the OpenAI-compatible
  [chat completions](https://api-docs.deepseek.com/api/create-chat-completion) endpoint (`POST
  https://api.deepseek.com/chat/completions`), choosing between
  [V4 Flash and V4 Pro](https://api-docs.deepseek.com/quick_start/pricing) (default **V4 Flash**), with
  [JSON output mode](https://api-docs.deepseek.com/guides/json_mode)
  (`response_format: { type: "json_object" }`). These V4 models replace the legacy `deepseek-chat` /
  `deepseek-reasoner` aliases, which DeepSeek deprecates on 2026-07-24.

Whatever the model returns is treated defensively: the response is parsed tolerantly (code fences and
stray prose are stripped before the first `{…}` is read) and every score is clamped into range, so a
malformed answer degrades to an error row instead of breaking the popup. Any network, key, or parse
failure shows an explanatory note and leaves the rest of the popup working.

> **Privacy note.** This is the only category that sends page content off-device, and only when you
> explicitly run it. The page summary above is transmitted to the provider you selected (Anthropic or
> DeepSeek) under your own API key, subject to that provider's data-handling terms. See
> [PRIVACY.md](PRIVACY.md).

## Automatic scanning

By default the extension only scans when you open the popup. **Settings → Scanning → Scan pages
automatically** (`autoScan` in `chrome.storage.local`) flips this on: the **background service worker**
then scans each page on its own, with the popup never opened.

It hooks Chrome's tab events
([`chrome.tabs.onUpdated`](https://developer.chrome.com/docs/extensions/reference/api/tabs#event-onUpdated)
when a page finishes loading in the active tab, and
[`chrome.tabs.onActivated`](https://developer.chrome.com/docs/extensions/reference/api/tabs#event-onActivated)
when you switch tabs), then runs the same URL, reputation, content, and link checks the popup runs —
injecting the same self-contained extractors and highlighters via
[`chrome.scripting.executeScript`](https://developer.chrome.com/docs/extensions/reference/api/scripting#method-executeScript)
and honouring your per-element highlight toggles. The four categories are folded into the **same weighted
trust score the popup shows** (see [Trust score](#trust-score); AI is never run automatically, so it is
left out), and that score's band is shown two ways on the toolbar icon: a colour-coded **badge** via the
[`chrome.action`](https://developer.chrome.com/docs/extensions/reference/api/action#method-setBadgeText)
badge API (**✓** green for a safe score, **!** amber for caution, **✕** red for dangerous, and a muted
**…** while a scan is in flight), and a **matching tint of the icon itself** via
[`chrome.action.setIcon`](https://developer.chrome.com/docs/extensions/reference/api/action#method-setIcon).
Because both come from the trust score rather than a worst-of category verdict, the badge and icon always
agree with the popup's ring (a single category warning on an otherwise clean site stays green, as the
score does). A page no verdict is possible for — a `chrome://` page, the new-tab page, or one where every
category comes back unknown — shows a grey **?** and the default green icon, the popup's "Can't scan this
page" state.

**How the icon is tinted.** The packaged icon is the green radar shield, so the amber/red variants are
produced at runtime rather than shipped as extra files: the green PNG is decoded with
[`createImageBitmap`](https://developer.mozilla.org/en-US/docs/Web/API/Window/createImageBitmap), drawn to
an [`OffscreenCanvas`](https://developer.mozilla.org/en-US/docs/Web/API/OffscreenCanvas), and each opaque
pixel is hue-shifted to the band's hue while keeping its saturation, lightness and transparency, so the
shield's shading and the radar sweep are preserved and only the hue changes. PNG decoding via
`createImageBitmap` works in both the popup and the background service worker (SVG decoding does not work
off the main thread), so [`scripts/shared/icon.ts`](scripts/shared/icon.ts) serves both: opening the popup
tints the active tab's icon from the same trust score it shows in the ring, and the auto-scan worker tints
each tab as it scans. The packaged green PNGs are referenced by **absolute extension URL** via
[`chrome.runtime.getURL`](https://developer.chrome.com/docs/extensions/reference/api/runtime#method-getURL)
rather than a bare relative path, because `setIcon` resolves a relative `path` against the calling context
(the extension root from the worker, but the `popup/` directory from the popup document, where the relative
path would not exist) — an absolute URL resolves the same way from either caller.

The **AI analysis is never run automatically here** — it bills your provider, so it stays governed by
the [**When to scan with AI**](#ai) dropdown and only ever runs from the popup. To keep network load and
third-party rate limits in check, the worker scans only the tab you are actually looking at and skips a
tab whose current URL it has already scanned. Turning the option off clears every badge and restores the
default green icon.

## Localization

The interface ships in **English** and **Hebrew**, built on Chrome's official
[`chrome.i18n`](https://developer.chrome.com/docs/extensions/reference/api/i18n) infrastructure. Every
user-visible string lives in a per-language
[`messages.json`](https://developer.chrome.com/docs/extensions/develop/ui/i18n) under
[`_locales/`](_locales/): [`_locales/en/messages.json`](_locales/en/messages.json) and
[`_locales/he/messages.json`](_locales/he/messages.json). These files are the single source of truth for
both paths below. The locale codes follow Chrome's
[supported list](https://developer.chrome.com/docs/extensions/reference/api/i18n#locales) (`en`, `he`).

**Store listing (browser-driven).** The extension name and description in
[`manifest.json`](manifest.json) use `__MSG_appName__` / `__MSG_appDesc__` placeholders resolved by
`chrome.i18n` against the browser's UI language, with
[`default_locale`](https://developer.chrome.com/docs/extensions/reference/manifest/default-locale) set to
`en` as the fallback. This is what Chrome and the Web Store show.

**In-app UI (user-driven).** `chrome.i18n.getMessage` only ever returns strings in the single browser UI
language and [cannot be switched at runtime](https://developer.chrome.com/docs/extensions/reference/api/i18n#concepts_and_usage),
but the popup and options page offer a **Language** toggle. To honor it, those pages read the very same
`_locales/<lang>/messages.json` files directly with `fetch(chrome.runtime.getURL(...))` and resolve keys
from the chosen language ([`scripts/shared/i18n.ts`](scripts/shared/i18n.ts)). Markup carries `data-i18n`
(text) and `data-i18n-placeholder` (input placeholders) attributes that are filled from the loaded
dictionary. Hebrew is **right-to-left**, so applying it also sets `<html lang="he" dir="rtl">`.

To add a language, drop a new `_locales/<code>/messages.json`, mirror the keys, and add its option to the
Language selector.

## Tech stack

- **Languages:** TypeScript, HTML, CSS
- **Platform:** Chrome Extension API (Manifest V3), including a background service worker (IndexedDB + `chrome.alarms`, plus optional auto-scan via `chrome.tabs` / `chrome.scripting` / `chrome.action` badge + icon tinting)
- **Localization:** `chrome.i18n` with `_locales/` message files (English and Hebrew, RTL-aware)
- **Theming:** shared design tokens in `styles/theme.css` (dark by default, light via a `data-theme` override). The options page follows the brand icon: green accents throughout and a radar rings and sweep backdrop built with CSS [`color-mix()`](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value/color-mix), [`conic-gradient()`](https://developer.mozilla.org/en-US/docs/Web/CSS/gradient/conic-gradient) and [`mask-image`](https://developer.mozilla.org/en-US/docs/Web/CSS/mask-image), with the sweep animation disabled under [`prefers-reduced-motion`](https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion). Its card grid packs masonry style at any window width, including ultrawide: since [CSS masonry](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_grid_layout/Masonry_layout) has not shipped in stable Chrome, each card spans a number of fixed 8px grid rows matching its measured height, kept current by a [`ResizeObserver`](https://developer.mozilla.org/en-US/docs/Web/API/ResizeObserver)
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
The source is **not** loaded directly; it is compiled into a `dist/` folder, which is what Chrome loads.

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
