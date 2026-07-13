// Link analysis. Framework-free helpers used by the popup's "Links" view. Like
// Content Analysis (and unlike URL & Reputation, which only need the host), these
// checks need the page's DOM, so the popup injects extractPageLinks() into the
// active tab via chrome.scripting.executeScript and runs the classification here
// on the small, JSON-safe summary it returns.
//
// Every anchor is sorted into exactly one bucket:
//  - internal:   same registrable domain as the page. Reassuring; marked green.
//  - external:   a different domain with no risk traits. Counted; marked blue.
//  - suspicious: a link whose destination itself looks dangerous (a host on the
//                locally cached Phishing.Database blocklist, an IP-literal host
//                (IPv4 or IPv6), a punycode/IDN homograph, credentials embedded
//                in the URL, a brand look-alike domain, a URL shortener,
//                unusually deep subdomains, stacked phishing keywords, or a
//                plain unencrypted http: destination). Marked red.
//  - redirect:   a link that hides or bounces its real destination (an open
//                redirect parameter carrying an off-site URL, or visible text
//                that claims one destination, a domain or a raw IP, while the
//                href points to another). Marked red.
//  - ignore:     not a real navigation (mailto:/tel:/javascript:, or an in-page
//                "#" anchor on the current document).
//
// Grounding: these are the long-documented phishing URL indicators from
// anti-phishing guidance (CISA, the APWG, OWASP): IP literals, "@" userinfo,
// punycode homographs, look-alike subdomains, link shorteners, open redirects,
// unencrypted plain-http destinations, and the displayed URL not matching the
// actual one. On top of those heuristics,
// every destination host is also checked against the Phishing.Database blocklist
// the background worker keeps on the device: the caller resolves the page's
// hosts against it in one batch (collectLinkHosts) and hands the listed subset
// to classifyLink/analyzeLinks, so checking even thousands of links stays an
// instant, offline set lookup.

import {
  splitDomain,
  IPV4_RE,
  SUSPICIOUS_KEYWORDS,
  type AnalyzedRow,
} from "./url-analysis";
import { BRAND_URL_TOKENS } from "./content-data";

export type LinkVerdict = "internal" | "external" | "suspicious" | "redirect" | "ignore";

// One anchor as seen in the page, captured by extractPageLinks. Kept small and
// JSON-safe because it crosses the executeScript boundary back into the popup.
export interface RawLink {
  // anchor.href, already resolved to an absolute URL by the browser.
  href: string;
  // Trimmed visible text, capped, used to spot displayed-vs-real URL mismatches.
  text: string;
}

export interface PageLinks {
  // location.href, so a same-page "#" anchor can be told from a real link.
  pageUrl: string;
  // Count of every <a href> on the page (may exceed links.length when capped).
  total: number;
  // First MAX_LINKS anchors in document order; classified here and, by the same
  // index order, highlighted on the page by highlightPageLinks.
  links: RawLink[];
}

// The classification of one link: its bucket, a host to show as a chip in the
// popup, and (for suspicious/redirect) an i18n key naming the specific reason.
export interface ClassifiedLink {
  verdict: LinkVerdict;
  host: string;
  reasonKey?: string;
}

// Query parameter names that carry a follow-on destination. Pairing a known
// redirect parameter with a value that is an absolute off-domain URL keeps this
// high-signal, so even generic names ("u", "r", "go") rarely misfire.
const REDIRECT_PARAMS = new Set([
  "url", "uri", "redirect", "redirect_uri", "redirect_url", "redirecturl",
  "redir", "return", "returnurl", "return_url", "returnto", "return_to", "next",
  "dest", "destination", "continue", "goto", "target", "out", "link", "forward",
  "fwd", "jump", "go", "q", "u", "r", "to",
]);

// Link shorteners (matched by registrable domain). A shortened link hides where
// it really goes, so it is surfaced as suspicious.
const URL_SHORTENERS = new Set([
  "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly", "rb.gy", "tiny.cc",
  "lnkd.in", "bit.do", "mcaf.ee", "bl.ink", "shorte.st", "v.gd", "x.co",
  "trib.al", "ift.tt", "adf.ly",
]);

// An IP-literal host, IPv4 or IPv6. The URL parser keeps the brackets on an
// IPv6 hostname (e.g. "[2001:db8::1]"), so the leading "[" is a reliable tell.
function isIpHost(hostname: string): boolean {
  return IPV4_RE.test(hostname) || hostname.startsWith("[");
}

// A whole-label token of `hostname` matches a known brand while the registrable
// label itself is not that brand. That is the brand-in-subdomain look-alike trick
// (paypal.secure-login.com), distinct from being on the brand's own domain.
function isBrandLookalike(hostname: string): boolean {
  const regLabel = splitDomain(hostname).registrable.split(".")[0];
  for (const token of hostname.toLowerCase().split(/[.-]/)) {
    if (token !== regLabel && BRAND_URL_TOKENS.includes(token)) return true;
  }
  return false;
}

// Subdomain nesting far beyond the norm (login.account.secure.verify.evil.tld).
// The threshold is set high so ordinary multi-label CDN hosts don't trip it.
function hasDeepSubdomain(hostname: string): boolean {
  if (isIpHost(hostname)) return false;
  const { sub } = splitDomain(hostname);
  return sub ? sub.split(".").length >= 4 : false;
}

// How many distinct phishing keywords appear in the host. Requiring two or more
// (stacked, as in "secure-account-login.com") keeps a lone "login." subdomain
// on an otherwise normal site from being flagged.
function hostKeywordHits(hostname: string): number {
  const host = hostname.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((kw) => host.includes(kw)).length;
}

// The host named by the visible text when the text is presented as a URL
// (starts with http(s):// or www.), or null when it isn't. Only the text's
// first whitespace-separated token is parsed, so a URL followed by prose still
// yields its host. Parsing with the URL parser (instead of a domain regex)
// handles ports, userinfo, bracketed IPv6 literals, and raw IPv4 hosts, which
// a TLD-shaped pattern would miss.
function textUrlHost(text: string): string | null {
  const t = text.trim().split(/\s+/)[0];
  if (!/^(?:https?:\/\/|www\.)/i.test(t)) return null;
  try {
    return new URL(/^https?:\/\//i.test(t) ? t : `http://${t}`).hostname;
  } catch {
    return null;
  }
}

// Whether the visible text is presented as a URL but names a different
// destination than the href actually opens. That is the displayed-vs-real URL
// spoof. Domains compare by registrable domain (www.mybank.com matches
// mybank.com); an IP literal on either side has no registrable domain, so IPs
// compare as whole hosts. Catching IP-literal display text matters in
// practice: malware URLs are commonly listed as raw-IP links whose href opens
// somewhere else entirely.
function isTextMismatch(text: string, hrefHost: string): boolean {
  const textHost = textUrlHost(text);
  if (!textHost) return false;
  if (isIpHost(textHost) || isIpHost(hrefHost)) return textHost !== hrefHost;
  const reg = splitDomain(textHost).registrable;
  return Boolean(reg) && reg !== splitDomain(hrefHost).registrable;
}

// If a redirect parameter (in the query or fragment) carries an absolute URL to
// a different registrable domain than the link's own, return that destination
// host. That is an open redirect / link-cloaking bounce.
function redirectTargetHost(linkUrl: URL, linkReg: string): string | null {
  const candidates: string[] = [];
  const collect = (params: URLSearchParams): void => {
    for (const [name, value] of params) {
      if (value && REDIRECT_PARAMS.has(name.toLowerCase())) candidates.push(value);
    }
  };
  collect(linkUrl.searchParams);
  if (linkUrl.hash.includes("=")) collect(new URLSearchParams(linkUrl.hash.slice(1)));

  for (const value of candidates) {
    // Only an absolute http(s) (or protocol-relative) value leaves the site; a
    // relative path stays put and is not a redirect.
    if (!/^(?:https?:)?\/\//i.test(value.trim())) continue;
    try {
      const dest = new URL(value, linkUrl);
      if (dest.protocol !== "http:" && dest.protocol !== "https:") continue;
      const destReg = splitDomain(dest.hostname).registrable;
      if (destReg && destReg !== linkReg) return dest.hostname;
    } catch {
      // Not a parseable URL; ignore this candidate.
    }
  }
  return null;
}

// Sort one anchor into its bucket. `pageUrl` is the document the link sits on.
// `listed` is the (optional) set of this page's link hosts found on the local
// Phishing.Database blocklist, resolved by the caller in one batch beforehand.
export function classifyLink(
  raw: RawLink,
  pageUrl: URL,
  listed?: ReadonlySet<string>,
): ClassifiedLink {
  let url: URL;
  try {
    url = new URL(raw.href);
  } catch {
    return { verdict: "ignore", host: "" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { verdict: "ignore", host: "" };
  }
  // A same-document "#" anchor only changes the fragment; it navigates nowhere.
  if (
    url.origin === pageUrl.origin &&
    url.pathname === pageUrl.pathname &&
    url.search === pageUrl.search
  ) {
    return { verdict: "ignore", host: url.hostname };
  }

  const host = url.hostname;
  const linkReg = splitDomain(host).registrable;
  const pageReg = splitDomain(pageUrl.hostname).registrable;

  // A destination on the Phishing.Database blocklist is the one authoritative
  // (non-heuristic) tell, so it wins over every other bucket, including
  // internal: on a listed site, even a same-domain link leads to a known
  // phishing domain.
  if (listed?.has(host)) {
    return { verdict: "suspicious", host, reasonKey: "reason_link_listed" };
  }

  // Deceptive / redirecting links next: an open redirect can sit on the page's
  // own trusted domain, so this has to win over the internal check below.
  if (isTextMismatch(raw.text, host)) {
    return { verdict: "redirect", host, reasonKey: "reason_link_textMismatch" };
  }
  const target = redirectTargetHost(url, linkReg);
  if (target) return { verdict: "redirect", host: target, reasonKey: "reason_link_redirectParam" };

  // Internal link: same registrable domain as the page. An IP-literal host has
  // no registrable domain (splitDomain would fabricate one from the last two
  // octets, making 1.2.3.4 and 9.9.3.4 look related), so an IP on either side
  // counts as internal only when both hosts match exactly.
  const internal =
    isIpHost(host) || isIpHost(pageUrl.hostname)
      ? host === pageUrl.hostname
      : Boolean(linkReg) && linkReg === pageReg;
  if (internal) return { verdict: "internal", host };

  // External: judge how dangerous the destination looks, worst tell first.
  if (url.username) return { verdict: "suspicious", host, reasonKey: "reason_link_credentials" };
  if (isIpHost(host)) return { verdict: "suspicious", host, reasonKey: "reason_link_ip" };
  if (host.includes("xn--")) return { verdict: "suspicious", host, reasonKey: "reason_link_punycode" };
  if (isBrandLookalike(host)) return { verdict: "suspicious", host, reasonKey: "reason_link_lookalike" };
  if (URL_SHORTENERS.has(linkReg)) return { verdict: "suspicious", host, reasonKey: "reason_link_shortener" };
  if (hasDeepSubdomain(host)) return { verdict: "suspicious", host, reasonKey: "reason_link_manySub" };
  if (hostKeywordHits(host) >= 2) return { verdict: "suspicious", host, reasonKey: "reason_link_keyword" };
  // Plain http: the destination is unencrypted, so the traffic can be read or
  // altered in transit. The weakest tell here, checked last so any stronger
  // reason above names the link instead. Internal links are exempt (returned
  // above): on a plain-http site every same-site link is http, and the URL &
  // Domain view already flags the page's own protocol.
  if (url.protocol === "http:") return { verdict: "suspicious", host, reasonKey: "reason_link_http" };

  return { verdict: "external", host };
}

// A synthetic "page" on a domain no real site uses, so classifyLink never treats
// a directly-typed URL as internal to it. It lets the address-bar guard reuse the
// exact same suspicious/redirect judgement the on-page link marks use, even
// though a typed URL sits on no page of its own.
const NO_PAGE = new URL("https://address-bar.riskradar.invalid/");

// Judge a URL entered straight into the address bar, reusing classifyLink. There
// is no anchor text, so the displayed-vs-real spoof never applies; the remaining
// tells (IP host, punycode, embedded credentials, brand look-alike, shortener,
// deep subdomains, stacked keywords, and off-domain redirect parameters) all
// still hold for a raw URL. The blocklist tell is not applied here either: the
// background worker checks the typed host against its cached list itself. The
// plain-http tell is also link-only: as an address-bar guard it would prompt on
// every http site the user deliberately visits, which the browser's own "Not
// secure" chip already covers, so an http-only hit falls back to plain
// external. A non-http(s) URL classifies as "ignore".
export function classifyAddressBarUrl(rawUrl: string): ClassifiedLink {
  const link = classifyLink({ href: rawUrl, text: "" }, NO_PAGE);
  if (link.reasonKey === "reason_link_http") return { verdict: "external", host: link.host };
  return link;
}

// The distinct http(s) hostnames among the page's links, for the batch
// Phishing.Database lookup: the caller resolves these against the local
// blocklist once and passes the listed subset to analyzeLinks below.
export function collectLinkHosts(page: PageLinks): string[] {
  const hosts = new Set<string>();
  for (const { href } of page.links) {
    try {
      const url = new URL(href);
      if (url.protocol === "http:" || url.protocol === "https:") hosts.add(url.hostname);
    } catch {
      // Not a parseable URL; classifyLink will ignore it too.
    }
  }
  return [...hosts];
}

// Classify the page's links and build the four Links rows. `classified` is
// returned alongside (in document order) so the popup can mark the same links on
// the page. `listed` is the subset of the page's link hosts found on the local
// Phishing.Database blocklist (see collectLinkHosts); omitted when the list is
// still downloading, in which case only the heuristic tells apply.
export function analyzeLinks(page: PageLinks, listed?: ReadonlySet<string>): {
  classified: ClassifiedLink[];
  total: AnalyzedRow;
  external: AnalyzedRow;
  suspicious: AnalyzedRow;
  redirects: AnalyzedRow;
} {
  let pageUrl: URL;
  try {
    pageUrl = new URL(page.pageUrl);
  } catch {
    pageUrl = new URL("https://invalid.invalid/");
  }

  const classified = page.links.map((l) => classifyLink(l, pageUrl, listed));
  const external = classified.filter((c) => c.verdict === "external");
  const suspicious = classified.filter((c) => c.verdict === "suspicious");
  const redirects = classified.filter((c) => c.verdict === "redirect");

  // Distinct hosts to list as chips under a row, capped so a link-heavy page
  // can't produce an endless list.
  const hosts = (items: ClassifiedLink[]): string[] => {
    const seen = new Set<string>();
    for (const c of items) if (c.host) seen.add(c.host);
    return [...seen].slice(0, 12);
  };

  const total: AnalyzedRow = { text: String(page.total), status: "neutral" };

  const extHosts = hosts(external);
  const externalRow: AnalyzedRow = {
    text: String(external.length),
    status: "good",
    detail: extHosts.length ? extHosts : undefined,
  };

  // Heuristic tells turn risky only when stacked (3+), but a single link to a
  // blocklisted domain is an authoritative hit, so it is risky on its own.
  // Plain-http links don't join the stack: unencrypted links are common on
  // benign pages, so on their own they cap the row at a warning.
  const hasListed = suspicious.some((c) => c.reasonKey === "reason_link_listed");
  const strongCount = suspicious.filter((c) => c.reasonKey !== "reason_link_http").length;
  const suspiciousRow: AnalyzedRow =
    suspicious.length === 0
      ? { key: "val_none", status: "good" }
      : {
          text: String(suspicious.length),
          status: hasListed || strongCount >= 3 ? "bad" : "warn",
          detail: hosts(suspicious),
        };

  // A displayed-vs-real mismatch is an unambiguous spoof (risky); a parameter
  // bounce alone can occasionally be a legitimate out-link wrapper (warning).
  const hasMismatch = redirects.some((c) => c.reasonKey === "reason_link_textMismatch");
  const redirectsRow: AnalyzedRow =
    redirects.length === 0
      ? { key: "val_none", status: "good" }
      : { text: String(redirects.length), status: hasMismatch ? "bad" : "warn", detail: hosts(redirects) };

  return { classified, total, external: externalRow, suspicious: suspiciousRow, redirects: redirectsRow };
}

// What highlightPageLinks needs per anchor: the colour to use and the hover label
// to show. "skip" leaves the link unmarked. Built in the popup (which has the
// dictionary) so the injected highlighter stays free of i18n.
export interface LinkMark {
  verdict: "internal" | "external" | "suspicious" | "redirect" | "skip";
  title: string;
  // For the red buckets (suspicious / redirect) only: a ready-to-show
  // confirmation message. When present, clicking the link is intercepted and the
  // user must confirm before the browser navigates. Safe links leave this unset.
  warn?: string;
  // For the red buckets only, when the guard action is "block": a ready-to-show
  // blocked notice. When present, clicking the link is always cancelled and this
  // message is shown; there is no way to continue. Takes precedence over `warn`.
  block?: string;
}

// Injected into the active tab to mark the classified links on the page itself:
// internal links get a subtle green outline, plain external links a light-blue
// one, and suspicious links and malicious redirects a red one, each carrying a
// native title so hovering names what it is. It runs in the page's DOM (anchors
// are real elements, so a title is enough; no floating tooltip needed) and must
// be fully self-contained.
// It re-reads the anchors in the same document order extractPageLinks used, so
// marks[i] lines up with the i-th <a href>. Safe to call repeatedly: each run
// first undoes the previous run's marks, so re-scans don't stack and passing
// all-"skip" marks clears the page.
// A red link (suspicious / redirect) whose mark carries a `warn` message is also
// guarded: clicking it pops a confirm() so the user can back out before the
// browser navigates. A mark carrying a `block` message instead cancels the click
// outright and shows the notice, with no way to continue. One capture-phase
// listener on the document drives every guarded link, so re-scans never add a
// second.
export function highlightPageLinks(marks: LinkMark[]): void {
  const ATTR = "data-riskradar-link";
  // Holds the per-link confirmation message; the click guard below reads it.
  const WARN_ATTR = "data-riskradar-warn";
  // Holds the per-link blocked notice; when present the guard cancels the click.
  const BLOCK_ATTR = "data-riskradar-block";
  // Per-verdict outline width, outline colour and tint. Colours mirror the
  // popup's palette: green "good", light blue for plain external links, red
  // "danger". The reassuring buckets (internal, external) get a thin outline;
  // the risky ones (suspicious, redirect) a thicker one.
  const STYLE: Record<
    "internal" | "external" | "suspicious" | "redirect",
    { width: string; color: string; bg: string }
  > = {
    internal: { width: "1.5px", color: "#4ade80", bg: "rgba(74,222,128,.12)" },
    external: { width: "1.5px", color: "#6ea8fe", bg: "rgba(110,168,254,.12)" },
    suspicious: { width: "2px", color: "#f87171", bg: "rgba(248,113,113,.14)" },
    redirect: { width: "2px", color: "#f87171", bg: "rgba(248,113,113,.14)" },
  };

  // Undo a previous run, restoring any inline background / title we borrowed.
  for (const el of document.querySelectorAll<HTMLElement>(`[${ATTR}]`)) {
    el.style.outline = "";
    el.style.outlineOffset = "";
    el.style.backgroundColor = el.dataset.riskradarBgPrev ?? "";
    el.removeAttribute(ATTR);
    el.removeAttribute(WARN_ATTR);
    el.removeAttribute(BLOCK_ATTR);
    delete el.dataset.riskradarBgPrev;
    const prevTitle = el.dataset.riskradarTitlePrev;
    if (prevTitle !== undefined) {
      el.title = prevTitle;
      delete el.dataset.riskradarTitlePrev;
    } else {
      el.removeAttribute("title");
    }
  }

  const anchors = document.querySelectorAll<HTMLAnchorElement>("a[href]");
  const count = Math.min(anchors.length, marks.length);
  for (let i = 0; i < count; i++) {
    const mark = marks[i];
    if (mark.verdict === "skip") continue;
    const el = anchors[i];

    const style = STYLE[mark.verdict];
    // Outline doesn't affect layout, so it's a safe, reversible mark even on
    // inline links that wrap across lines.
    el.style.outline = `${style.width} solid ${style.color}`;
    el.style.outlineOffset = "1px";
    if (el.style.backgroundColor) el.dataset.riskradarBgPrev = el.style.backgroundColor;
    el.style.backgroundColor = style.bg;
    el.setAttribute(ATTR, "");

    // Borrow the title for the hover label, remembering any the page had.
    if (el.title) el.dataset.riskradarTitlePrev = el.title;
    el.title = mark.title;

    // Red links carry a confirmation message or a blocked notice; clicking one
    // is intercepted by the document guard installed below.
    if (mark.block) el.setAttribute(BLOCK_ATTR, mark.block);
    else if (mark.warn) el.setAttribute(WARN_ATTR, mark.warn);
  }

  // Guard clicks on the red links: one capture-phase listener on the document
  // checks whether the clicked target sits inside a link carrying BLOCK_ATTR or
  // WARN_ATTR. A blocked link is cancelled outright and its notice shown; a
  // warned link asks the user to confirm before letting the navigation through.
  // The "already installed" flag is kept on a DOM attribute rather than a closure
  // because each scan re-injects this function fresh, yet the attribute (and the
  // listener) persist with the page, so the guard is wired exactly once.
  const GUARD_FLAG = "data-riskradar-link-guard";
  if (!document.documentElement.hasAttribute(GUARD_FLAG)) {
    document.documentElement.setAttribute(GUARD_FLAG, "");
    const guard = (event: Event): void => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const guarded = target.closest(`[${BLOCK_ATTR}], [${WARN_ATTR}]`);
      if (!guarded) return;
      // Block mode: cancel the click first, then tell the user why. alert()
      // blocks synchronously, and there is no way to continue to the link.
      const notice = guarded.getAttribute(BLOCK_ATTR);
      if (notice) {
        event.preventDefault();
        event.stopPropagation();
        window.alert(notice);
        return;
      }
      const message = guarded.getAttribute(WARN_ATTR);
      if (!message) return;
      // confirm() blocks synchronously, so a declined prompt can still cancel the
      // click before the browser acts on it. Confirming lets the event continue
      // untouched so the page's own handlers and the navigation still run.
      if (!window.confirm(message)) {
        event.preventDefault();
        event.stopPropagation();
      }
    };
    // click covers left- and modifier-clicks; auxclick covers a middle-click
    // (open in new tab), which does not fire a click event.
    document.addEventListener("click", guard, true);
    document.addEventListener("auxclick", guard, true);
  }
}

// Injected into the active tab (chrome.scripting.executeScript) and run in the
// page's context, so it must be fully self-contained: it touches only the DOM.
// Returns the small PageLinks summary the analyzers above consume.
export function extractPageLinks(): PageLinks {
  // Cap the number of links analyzed/marked so a huge page can't bloat the
  // message payload or flood the page with outlines. extractPageLinks and the
  // popup share this implicitly: the highlighter only marks as many links as
  // this returns.
  const MAX_LINKS = 2000;
  const anchors = document.querySelectorAll<HTMLAnchorElement>("a[href]");
  const limit = Math.min(anchors.length, MAX_LINKS);

  const links: { href: string; text: string }[] = [];
  for (let i = 0; i < limit; i++) {
    links.push({ href: anchors[i].href, text: (anchors[i].textContent ?? "").trim().slice(0, 200) });
  }

  return { pageUrl: window.location.href, total: anchors.length, links };
}

// Injected into a tab (chrome.scripting.executeScript) to show a blocking
// confirmation and report the choice. window.confirm halts the page's own
// scripts while it is open, so a URL typed into the address bar can be caught the
// moment it commits and backed out of before the page really runs. Returns true
// to proceed, false to back out. Self-contained: it touches only window.
export function confirmNavigation(message: string): boolean {
  return window.confirm(message);
}

// Injected into a tab (chrome.scripting.executeScript) to tell the user the
// website is blocked, with no way to continue. Like confirmNavigation, the
// window.alert halts the page's own scripts while it is open; the background
// worker backs the tab out once it is dismissed. Self-contained: it touches
// only window.
export function blockNavigation(message: string): void {
  window.alert(message);
}
