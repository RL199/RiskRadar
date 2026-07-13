// Background service worker. Maintains a local, offline copy of the
// Phishing.Database project's active phishing-domain list so the popup can check
// the current host instantly, without downloading ~10 MB on every open. The list
// is cached in IndexedDB, fully refreshed daily, and topped up hourly from the
// project's "new in the last hour" feed. The popup queries it over a message.

import { loadSettings, type Settings } from "../shared/settings";
import { loadMessages, type Dict } from "../shared/i18n";
import {
  analyzeProtocol,
  analyzeSubdomain,
  analyzeUrlLength,
  analyzeSuspiciousKeywords,
  fetchRegistrationDate,
  isLookupableDomain,
  splitDomain,
  type RowStatus,
} from "../shared/url-analysis";
import {
  checkDnsBlacklist,
  checkIpReputation,
  checkSafeBrowsing,
  checkSucuri,
  checkVirusTotal,
} from "../shared/reputation-analysis";
import {
  analyzeBrandImpersonation,
  analyzePhishingIndicators,
  analyzeSuspiciousForms,
  analyzeUrgentLanguage,
  extractPageContent,
  highlightPageMatches,
  type HighlightGroup,
  type PageContent,
} from "../shared/content-analysis";
import {
  analyzeLinks,
  blockNavigation,
  classifyAddressBarUrl,
  collectLinkHosts,
  confirmNavigation,
  extractPageLinks,
  highlightPageLinks,
  type ClassifiedLink,
  type LinkMark,
  type PageLinks,
} from "../shared/link-analysis";
import { setActionIcon } from "../shared/icon";
import { computeTrustScore, type ScoreInput, type SiteCategory } from "../shared/score";
import {
  renderClickScanOverlay,
  type ClickScanPayload,
  type ClickScanRow,
  type ClickScanStatus,
} from "../shared/click-scan";

const ACTIVE_URL =
  "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
const NEW_HOUR_URL =
  "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-last-hour.txt";

const REFRESH_ALARM = "phishingdb-refresh";
const INCREMENT_ALARM = "phishingdb-increment";
const FULL_REFRESH_MS = 24 * 60 * 60 * 1000; // re-download the full list daily

const DB_NAME = "riskradar";
const STORE = "phishingdb";
const RECORD_ID = "domains";

interface CacheRecord {
  id: string;
  domains: string[];
  updatedAt: number;
}

// Rebuilt from IndexedDB on first use after the worker wakes, then kept in memory
// while it stays alive.
let domainSet: Set<string> | null = null;
let lastUpdatedAt = 0;
// Guards against overlapping downloads when several popups wake the worker at once.
let refreshing: Promise<void> | null = null;

// ------------------------------- IndexedDB -------------------------------- //

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "id" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function readCache(): Promise<CacheRecord | null> {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const req = db.transaction(STORE, "readonly").objectStore(STORE).get(RECORD_ID);
      req.onsuccess = () => resolve((req.result as CacheRecord | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

async function writeCache(domains: string[]): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const record: CacheRecord = { id: RECORD_ID, domains, updatedAt: Date.now() };
      tx.objectStore(STORE).put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

// --------------------------- List loading / refresh --------------------------- //

function parseDomains(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim().toLowerCase();
    // Skip blank lines and the file's leading "# ..." comment banner.
    if (line && !line.startsWith("#")) out.push(line);
  }
  return out;
}

// Populate the in-memory set from IndexedDB. Does not hit the network.
async function ensureLoaded(): Promise<void> {
  if (domainSet) return;
  const cache = await readCache();
  if (cache) {
    domainSet = new Set(cache.domains);
    lastUpdatedAt = cache.updatedAt;
  }
}

// Download the full active list and replace the cache.
async function refreshFull(): Promise<void> {
  const res = await fetch(ACTIVE_URL, { cache: "no-cache" });
  if (!res.ok) return;
  const domains = parseDomains(await res.text());
  if (domains.length === 0) return; // never wipe a good cache with an empty/failed body
  await writeCache(domains);
  domainSet = new Set(domains);
  lastUpdatedAt = Date.now();
}

// Merge in the small "new in the last hour" feed so the cache stays current
// between full refreshes.
async function refreshIncrement(): Promise<void> {
  await ensureLoaded();
  if (!domainSet) return; // no base list yet; wait for a full refresh
  const res = await fetch(NEW_HOUR_URL, { cache: "no-cache" });
  if (!res.ok) return;
  const fresh = parseDomains(await res.text());
  if (fresh.length === 0) return;
  for (const d of fresh) domainSet.add(d);
  await writeCache([...domainSet]);
}

// Refresh the full list if it's missing or older than a day. De-duplicated so
// concurrent callers share one download.
function refreshIfStale(): Promise<void> {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    await ensureLoaded();
    if (!domainSet || Date.now() - lastUpdatedAt > FULL_REFRESH_MS) await refreshFull();
  })().finally(() => {
    refreshing = null;
  });
  return refreshing;
}

// --------------------------------- Lookup --------------------------------- //

type LookupStatus = "listed" | "clean" | "loading";

// Which of `hosts` are on the blocklist. Each host costs at most two in-memory
// Set lookups (itself, then its registrable domain, since a listed registrable
// domain covers its subdomains, e.g. login.evil.tld), so even the thousands of
// link hosts a large page yields are answered instantly and offline. Returns
// null while the list is still downloading.
async function listedAmong(hosts: string[]): Promise<Set<string> | null> {
  await ensureLoaded();
  if (!domainSet) {
    void refreshIfStale(); // first use also kicks off the initial download
    return null;
  }
  const listed = new Set<string>();
  for (const host of hosts) {
    const h = host.toLowerCase();
    const { registrable } = splitDomain(h);
    if (domainSet.has(h) || (registrable !== h && domainSet.has(registrable))) listed.add(host);
  }
  return listed;
}

async function isListed(host: string): Promise<LookupStatus> {
  const listed = await listedAmong([host]);
  if (!listed) return "loading";
  return listed.size > 0 ? "listed" : "clean";
}

// ------------------------------- Auto-scan -------------------------------- //
//
// When the user turns on "Scan pages automatically" (settings.autoScan), the
// worker scans each page as it finishes loading in the active tab, without the
// popup ever being opened. It runs the same offline + reputation + page checks
// the popup runs (everything except the paid AI analysis), folds them into the
// same weighted trust score the popup shows, and presents that score's band as a
// colour-coded badge plus a matching tint on the toolbar icon, while applying the
// same in-page highlights the popup would, honouring the user's per-element
// highlight toggles.

const SEVERITY: Record<RowStatus, number> = { neutral: 0, unknown: 0, good: 1, warn: 2, bad: 3 };

// Worst status wins; neutral/unknown (severity 0) never elevate the verdict.
function worst(statuses: RowStatus[]): RowStatus {
  return statuses.reduce<RowStatus>((acc, s) => (SEVERITY[s] > SEVERITY[acc] ? s : acc), "good");
}

// A category's verdict from its rows: the worst determinate finding, or "unknown"
// when nothing could be judged (every row neutral/unknown). Mirrors the popup.
function overallOf(statuses: RowStatus[]): RowStatus {
  const determinate = statuses.filter((s) => s === "good" || s === "warn" || s === "bad");
  return determinate.length ? worst(determinate) : "unknown";
}

// The last URL scanned per tab, so re-activating a tab doesn't re-run every
// network check for a page already scanned. Forgotten when the tab goes away.
const lastScanned = new Map<number, string>();
// Tabs with a scan in flight, so overlapping triggers can't double-scan one tab.
const scanning = new Set<number>();

// URL & Domain category: the synchronous checks plus the RDAP domain-age lookup.
// A raw-IP host or a brand-new domain (< 30 days) is a strong phishing heuristic
// that caps the trust score, mirroring the popup's URL view.
async function scanUrlCategory(url: URL): Promise<ScoreInput> {
  const subdomain = analyzeSubdomain(url.hostname);
  const statuses: RowStatus[] = [
    analyzeProtocol(url).status,
    subdomain.status,
    analyzeUrlLength(url).status,
    analyzeSuspiciousKeywords(url).status,
  ];
  let ageStatus: RowStatus = "neutral";
  if (isLookupableDomain(url.hostname)) {
    const date = await fetchRegistrationDate(splitDomain(url.hostname).registrable);
    if (date) {
      const days = (Date.now() - date.getTime()) / 86_400_000;
      ageStatus = days < 30 ? "bad" : days < 180 ? "warn" : "good";
      statuses.push(ageStatus);
    }
  }
  return {
    status: overallOf(statuses),
    flags: { strong: subdomain.status === "bad" || ageStatus === "bad" },
  };
}

// Reputation category: the same lookups the popup runs. The Phishing.Database
// row reads this worker's own cached list directly (isListed) instead of the
// message round-trip the popup uses, since a worker can't message itself.
async function scanReputationCategory(url: URL, settings: Settings): Promise<ScoreInput> {
  const phishingStatus = async (): Promise<RowStatus> => {
    const s = await isListed(url.hostname);
    return s === "listed" ? "bad" : s === "clean" ? "good" : "unknown";
  };
  const statuses = await Promise.all([
    checkSafeBrowsing(url.href, url.hostname, settings.safeBrowsingApiKey).then((r) => r.status),
    settings.virusTotalApiKey
      ? checkVirusTotal(url.hostname, settings.virusTotalApiKey).then((r) => r.status)
      : Promise.resolve<RowStatus>("unknown"),
    checkSucuri(url.hostname).then((r) => r.status),
    phishingStatus(),
    checkDnsBlacklist(url.hostname).then((r) => r.status),
    checkIpReputation(url.hostname).then((r) => r.status),
  ]);
  // A "bad" reputation only ever comes from an authoritative blocklist/malware
  // hit, so it definitively caps the trust score, mirroring the popup.
  const status = overallOf(statuses);
  return { status, flags: { definitive: status === "bad" } };
}

// Inject the page-content extractor and read back its summary. Returns null on
// any failure (privileged page, navigated away). Mirrors the popup helper.
async function getPageContent(tabId: number): Promise<PageContent | null> {
  try {
    const [injection] = await chrome.scripting.executeScript({ target: { tabId }, func: extractPageContent });
    return (injection?.result as PageContent | undefined) ?? null;
  } catch {
    return null;
  }
}

// Inject the link extractor and read back its summary. Returns null on failure.
async function getPageLinks(tabId: number): Promise<PageLinks | null> {
  try {
    const [injection] = await chrome.scripting.executeScript({ target: { tabId }, func: extractPageLinks });
    return (injection?.result as PageLinks | undefined) ?? null;
  } catch {
    return null;
  }
}

// Content category: read the page, run the four content checks, and mark the
// flagged phrases/forms on the page for the categories the user left enabled.
async function scanContentCategory(
  tabId: number,
  url: URL,
  settings: Settings,
  dict: Dict,
): Promise<ScoreInput> {
  const page = await getPageContent(tabId);
  if (!page) return { status: "unknown" };

  const phishing = analyzePhishingIndicators(page);
  const forms = analyzeSuspiciousForms(page);
  const urgent = analyzeUrgentLanguage(page);
  const brand = analyzeBrandImpersonation(page, url.hostname);

  // Mark the matches on the page, gated by the user's per-element toggles (a
  // disabled category crosses over with no phrases, so it isn't marked). Runs in
  // the MAIN world so the highlighter shares the page's CSS highlight registry.
  const hl = settings.highlights;
  const groups: HighlightGroup[] = [
    { label: dict.lbl_phishingIndicators ?? "Phishing Indicators", phrases: hl.phishingIndicators ? phishing.detail ?? [] : [] },
    { label: dict.lbl_urgentLanguage ?? "Urgent Language", phrases: hl.urgentLanguage ? urgent.detail ?? [] : [] },
    { label: dict.lbl_brandImpersonation ?? "Brand Impersonation", phrases: hl.brandImpersonation ? brand.detail ?? [] : [] },
  ];
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: highlightPageMatches,
      args: [groups, dict.lbl_suspiciousForms ?? "Suspicious Forms", hl.suspiciousForms],
    });
  } catch {
    // Page stopped being scriptable between read and mark; nothing to do.
  }

  // A cleartext credential form definitively caps the score; brand impersonation
  // or heavy phishing wording are strong heuristics. Mirrors the popup.
  return {
    status: overallOf([phishing.status, forms.status, urgent.status, brand.status]),
    flags: {
      definitive: forms.status === "bad",
      strong: brand.status === "bad" || phishing.status === "bad",
    },
  };
}

// The hover label for a flagged link: the bucket name plus its specific reason.
// Mirrors the popup's linkTitle so auto-scan marks read the same.
function linkTitle(link: ClassifiedLink, dict: Dict): string {
  if (link.verdict === "internal") return dict.tip_link_internal ?? "Internal link";
  if (link.verdict === "external") return dict.tip_link_external ?? "External link";
  const head = link.verdict === "redirect" ? dict.tip_link_redirect ?? "Redirect" : dict.tip_link_suspicious ?? "Suspicious link";
  const reason = link.reasonKey ? dict[link.reasonKey] : undefined;
  return reason ? `${head}: ${reason}` : head;
}

// The click-confirmation for a red link, mirroring the popup's linkWarning so
// auto-scan guards read the same. Only the two risky buckets get one.
function linkWarning(link: ClassifiedLink, dict: Dict): string | undefined {
  if (link.verdict !== "suspicious" && link.verdict !== "redirect") return undefined;
  const heading = dict.warn_link_heading ?? "Risk Radar safety warning";
  const destLabel = dict.warn_link_destination ?? "Destination";
  const cont = dict.warn_link_continue ?? "Continue to this link anyway?";
  const dest = link.host ? `${destLabel}: ${link.host}\n\n` : "";
  return `${heading}\n\n${linkTitle(link, dict)}\n\n${dest}${cont}`;
}

// The blocked notice for a red link when the guard action is "block", mirroring
// the popup's linkBlockNotice: the continue prompt becomes a "website is
// blocked" line, since a blocked click cannot be continued.
function linkBlockNotice(link: ClassifiedLink, dict: Dict): string | undefined {
  if (link.verdict !== "suspicious" && link.verdict !== "redirect") return undefined;
  const heading = dict.warn_link_heading ?? "Risk Radar safety warning";
  const destLabel = dict.warn_link_destination ?? "Destination";
  const blocked = dict.block_link_notice ?? "This website is blocked.";
  const dest = link.host ? `${destLabel}: ${link.host}\n\n` : "";
  return `${heading}\n\n${linkTitle(link, dict)}\n\n${dest}${blocked}`;
}

// Links category: read the page, classify its links (each destination host
// checked against the local Phishing.Database blocklist directly, since the
// worker owns the cache), and outline them on the page for the verdict buckets
// the user left enabled.
async function scanLinksCategory(tabId: number, settings: Settings, dict: Dict): Promise<ScoreInput> {
  const page = await getPageLinks(tabId);
  if (!page) return { status: "unknown" };

  const listed = (await listedAmong(collectLinkHosts(page))) ?? undefined;
  const { classified, total, external, suspicious, redirects } = analyzeLinks(page, listed);

  const hl = settings.highlights;
  const enabled: Record<ClassifiedLink["verdict"], boolean> = {
    internal: hl.internalLinks,
    external: hl.externalLinks,
    suspicious: hl.suspiciousLinks,
    redirect: hl.maliciousRedirects,
    ignore: false,
  };
  // The red-link click guard honours the guard action: "warn" attaches the
  // confirmation, "block" the blocked notice, and "none" neither, so a click
  // navigates untouched. Mirrors the popup.
  const marks: LinkMark[] = classified.map((link) =>
    enabled[link.verdict] && link.verdict !== "ignore"
      ? {
          verdict: link.verdict,
          title: linkTitle(link, dict),
          warn: settings.guardAction === "warn" ? linkWarning(link, dict) : undefined,
          block: settings.guardAction === "block" ? linkBlockNotice(link, dict) : undefined,
        }
      : { verdict: "skip", title: "" },
  );
  try {
    await chrome.scripting.executeScript({ target: { tabId }, func: highlightPageLinks, args: [marks] });
  } catch {
    // Page stopped being scriptable between read and mark; nothing to do.
  }

  return { status: overallOf([total.status, external.status, suspicious.status, redirects.status]) };
}

// Toolbar-badge presentation per trust-score band. The colours mirror the popup's
// status palette: a scored band shows its glyph; "unknown" is the popup's muted
// "Can't scan this page" state, shown as a grey "?" beside the icon.
const BADGE: Record<"good" | "warn" | "bad" | "unknown", { text: string; color: string }> = {
  good: { text: "✓", color: "#16a34a" },
  warn: { text: "!", color: "#d97706" },
  bad: { text: "✕", color: "#dc2626" },
  unknown: { text: "?", color: "#6b7280" },
};

// Badge for a page we couldn't produce a verdict for (a privileged page, or one
// where every category came back unknown): the popup's "Can't scan this page".
// The toolbar icon returns to its default green, since there is no verdict colour.
async function markUnscannable(tabId: number): Promise<void> {
  await setBadge(tabId, BADGE.unknown.text, BADGE.unknown.color);
  await setActionIcon(tabId, null);
}

async function clearBadge(tabId: number): Promise<void> {
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
  } catch {
    // Tab closed mid-scan.
  }
  await setActionIcon(tabId, null); // restore the default green icon
}

async function setBadge(tabId: number, text: string, color: string): Promise<void> {
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
    await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
    await chrome.action.setBadgeText({ tabId, text });
  } catch {
    // Tab closed mid-scan.
  }
}

// Run every category for one tab, fold them into a trust score, and paint that
// score's band onto the tab's badge and toolbar icon.
async function scanTab(tab: chrome.tabs.Tab, settings: Settings): Promise<void> {
  const tabId = tab.id;
  if (typeof tabId !== "number") return;

  let url: URL | undefined;
  try {
    if (tab.url) url = new URL(tab.url);
  } catch {
    // Unparseable URL handled below.
  }
  // Privileged / non-web pages (chrome://, the new-tab page, …) have nothing to scan.
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    await markUnscannable(tabId);
    return;
  }
  if (scanning.has(tabId)) return;
  scanning.add(tabId);

  try {
    const dict = await loadMessages(settings.lang);
    await setBadge(tabId, "…", "#6b7280"); // muted "scanning" badge while checks run

    const [urlInput, reputationInput, contentInput, linksInput] = await Promise.all([
      scanUrlCategory(url),
      scanReputationCategory(url, settings),
      scanContentCategory(tabId, url, settings, dict),
      scanLinksCategory(tabId, settings, dict),
    ]);

    // Fold the four categories into the same weighted trust score the popup
    // computes (AI is never run automatically here, so it's left out). The badge
    // and icon take that score's band, so they always agree with the popup's ring.
    const inputs: Partial<Record<SiteCategory, ScoreInput>> = {
      url: urlInput,
      reputation: reputationInput,
      content: contentInput,
      links: linksInput,
    };
    const trust = computeTrustScore(inputs);
    if (trust) {
      await setBadge(tabId, BADGE[trust.band].text, BADGE[trust.band].color);
      await setActionIcon(tabId, trust.band); // tint the toolbar icon to the score
    } else {
      await markUnscannable(tabId); // nothing could be judged — grey "?"
    }
  } catch {
    await markUnscannable(tabId);
  } finally {
    scanning.delete(tabId);
  }
}

// Scan a tab if auto-scan is on and we haven't already scanned this exact URL in
// it — unless forced (a fresh page load, or the user just enabling auto-scan).
async function maybeAutoScan(tab: chrome.tabs.Tab, force = false): Promise<void> {
  if (typeof tab.id !== "number" || !tab.url) return;
  const settings = await loadSettings();
  if (!settings.autoScan) return;
  if (!force && lastScanned.get(tab.id) === tab.url) return;
  lastScanned.set(tab.id, tab.url);
  await scanTab(tab, settings);
}

// Clear the badge on every tab (used when auto-scan is switched off).
async function clearAllBadges(): Promise<void> {
  try {
    const tabs = await chrome.tabs.query({});
    for (const t of tabs) if (typeof t.id === "number") await clearBadge(t.id);
  } catch {
    // ignore
  }
  lastScanned.clear();
}

// ----------------------- Address-bar URL warning -------------------------- //
//
// A URL entered straight into the address bar is judged the moment it commits:
// a host on the phishing blocklist, or a URL carrying strong phishing traits
// (an IP host, punycode, embedded credentials, a brand look-alike, a shortener,
// deep subdomains, stacked keywords, or an off-domain redirect parameter),
// triggers the guard. What the guard does follows settings.guardAction: "warn"
// pops the same style of confirmation the on-page malicious-link guard uses
// (declining backs the tab off the page before it is really shown; confirming
// leaves it untouched); "block" shows a notice that the website is blocked and
// always backs the tab out; "none" lets the navigation through with no
// interruption at all.

// Transition types that mean the user drove the navigation from the omnibox. The
// "from_address_bar" qualifier covers the same ground, so either signal counts; a
// followed link, form submit, or reload never does.
const ADDRESS_BAR_TRANSITIONS = new Set(["typed", "generated", "keyword", "keyword_generated"]);

function isAddressBarNavigation(
  details: chrome.webNavigation.WebNavigationTransitionCallbackDetails,
): boolean {
  return (
    details.transitionQualifiers.includes("from_address_bar") ||
    ADDRESS_BAR_TRANSITIONS.has(details.transitionType)
  );
}

// The heading + reason line for a typed-URL warning. A blocklisted host reads as
// a known phishing site; otherwise it reuses the link tip/reason wording so the
// two guards speak with one voice.
function typedUrlTitle(link: ClassifiedLink, listed: boolean, dict: Dict): string {
  if (listed) return dict.tip_url_listed ?? "Known phishing site";
  return linkTitle(link, dict);
}

// The confirmation shown for a risky typed URL, mirroring linkWarning: the
// heading, the reason, the destination host, and a continue prompt. Returns
// undefined when the URL is neither blocklisted nor classified risky.
function typedUrlWarning(url: URL, link: ClassifiedLink, listed: boolean, dict: Dict): string | undefined {
  if (!listed && link.verdict !== "suspicious" && link.verdict !== "redirect") return undefined;
  const heading = dict.warn_link_heading ?? "Risk Radar safety warning";
  const destLabel = dict.warn_link_destination ?? "Destination";
  const cont = dict.warn_url_continue ?? "Continue to this site anyway?";
  const host = link.host || url.hostname;
  const dest = host ? `${destLabel}: ${host}\n\n` : "";
  return `${heading}\n\n${typedUrlTitle(link, listed, dict)}\n\n${dest}${cont}`;
}

// The blocked notice shown instead when the guard action is "block": the same
// heading, reason, and destination, but a "website is blocked" line in place of
// the continue prompt. Returns undefined for a URL that isn't risky.
function typedUrlBlockNotice(url: URL, link: ClassifiedLink, listed: boolean, dict: Dict): string | undefined {
  if (!listed && link.verdict !== "suspicious" && link.verdict !== "redirect") return undefined;
  const heading = dict.warn_link_heading ?? "Risk Radar safety warning";
  const destLabel = dict.warn_link_destination ?? "Destination";
  const blocked = dict.block_url_notice ?? "This website is blocked.";
  const host = link.host || url.hostname;
  const dest = host ? `${destLabel}: ${host}\n\n` : "";
  return `${heading}\n\n${typedUrlTitle(link, listed, dict)}\n\n${dest}${blocked}`;
}

// Take a tab off a page the user declined to visit: step back to the previous
// page when there is history, otherwise blank the tab.
async function leaveTab(tabId: number): Promise<void> {
  try {
    await chrome.tabs.goBack(tabId);
  } catch {
    try {
      await chrome.tabs.update(tabId, { url: "about:blank" });
    } catch {
      // Tab closed mid-navigation; nothing to do.
    }
  }
}

// Judge a just-committed address-bar navigation and, if the URL is risky, act on
// it per the guard action. "warn" pops a blocking confirmation in the tab
// (confirm() halts the page's scripts while it is open, so declining can back
// the tab out before the page really runs); "block" shows the blocked notice and
// always backs the tab out.
async function warnOnTypedNavigation(
  details: chrome.webNavigation.WebNavigationTransitionCallbackDetails,
): Promise<void> {
  if (details.frameId !== 0 || !isAddressBarNavigation(details)) return;

  let url: URL;
  try {
    url = new URL(details.url);
  } catch {
    return;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return;

  const settings = await loadSettings();
  // The "none" action means a caught navigation is let through untouched, so
  // there is nothing to judge either.
  if (settings.guardAction === "none") return;

  const link = classifyAddressBarUrl(details.url);
  const listed = (await isListed(url.hostname)) === "listed";
  if (!listed && link.verdict !== "suspicious" && link.verdict !== "redirect") return;

  const dict = await loadMessages(settings.lang);

  if (settings.guardAction === "block") {
    const notice = typedUrlBlockNotice(url, link, listed, dict);
    if (!notice) return;
    try {
      // The alert halts the page while it is shown; the tab is backed out once
      // it is dismissed.
      await chrome.scripting.executeScript({
        target: { tabId: details.tabId },
        func: blockNavigation,
        args: [notice],
      });
    } catch {
      // Page stopped being scriptable between commit and notice; still block.
    }
    await leaveTab(details.tabId);
    return;
  }

  const message = typedUrlWarning(url, link, listed, dict);
  if (!message) return;

  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: details.tabId },
      func: confirmNavigation,
      args: [message],
    });
    if (injection?.result === false) await leaveTab(details.tabId);
  } catch {
    // Page stopped being scriptable between commit and prompt; nothing to do.
  }
}

// ----------------------- Link-click reputation scan ----------------------- //
//
// When the user turns on "Check the reputation of links I click" (settings.linkClickScan),
// following a link runs the same reputation checks the popup's Reputation view
// uses on both ends of the click: the URL the click started from (the link's
// href, captured at onBeforeNavigate before any server redirect rewrites it)
// and the URL the navigation finally committed on (shorteners and redirect
// wrappers often land somewhere else).
//
// What happens to the site while the checks run follows settings.linkClickScanMode:
//  - "overlay": the site opens right away; a small overlay in the corner shows
//    a spinner while the checks run, then one colour-coded verdict per URL. It
//    hides itself when everything comes back clean and stays up, with a close
//    button, when a warning or a risky verdict comes back.
//  - "warn" / "block": the tab is parked on the extension's checking page
//    (pages/click-gate.html) instead of loading the site. The gate asks this
//    worker to run the same checks (the clickgate-scan message), then enters
//    the site when it passes; a site that fails is either offered behind a
//    "Continue anyway" confirmation ("warn") or refused outright ("block").
//    Before entering, the gate registers the destination here (the
//    clickgate-approve message) so the resulting navigation is let through
//    instead of being gated again.

// The original URL of each tab's pending main-frame navigation, captured at
// onBeforeNavigate: by onCommitted a server redirect has already rewritten
// details.url, so this is the only record of where the click started.
const navStartUrls = new Map<number, string>();

// The last link click per tab (its start URL and commit time), kept briefly so
// a client-side redirect right after the click (a bouncing interstitial or a
// meta refresh) is scanned as the same click's new destination rather than
// missed.
const clickJourneys = new Map<number, { startUrl: string; at: number }>();
const CLICK_JOURNEY_MS = 30_000;

// Guards against a superseded scan overwriting a newer one's overlay: each
// scan takes a fresh token and only the tab's current holder may draw.
const clickScanTokens = new Map<number, number>();
let nextClickScanToken = 1;

// The URL the click gate approved per tab (the check passed, or the user chose
// to continue). The next commit of exactly that URL in that tab is let through
// instead of being gated again; consumed on first use so it can never cover a
// later navigation.
const approvedClickUrls = new Map<number, string>();

// The reputation category verdict of one URL, reduced to the overlay's states.
function toClickScanStatus(status: RowStatus): ClickScanStatus {
  return status === "good" || status === "warn" || status === "bad" ? status : "unknown";
}

function clickScanRow(label: string, host: string, status: ClickScanStatus, dict: Dict): ClickScanRow {
  const text =
    status === "good"
      ? dict.verdict_safe ?? "Safe"
      : status === "warn"
        ? dict.verdict_caution ?? "Caution"
        : status === "bad"
          ? dict.verdict_danger ?? "Dangerous"
          : status === "unknown"
            ? dict.val_unknown ?? "Unknown"
            : "";
  return { label, host, status, text };
}

// Draw (or update) the overlay in the tab, unless a newer scan for the same
// tab has taken over. Injected immediately so the spinner shows as soon as the
// navigation commits, instead of waiting for the page to finish loading.
async function drawClickScan(tabId: number, token: number, payload: ClickScanPayload): Promise<void> {
  if (clickScanTokens.get(tabId) !== token) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      injectImmediately: true,
      func: renderClickScanOverlay,
      args: [payload],
    });
  } catch {
    // The tab closed or moved on to a page we can't script; nothing to show.
  }
}

// Park the tab on the extension's click-gate page, which runs the checks and
// decides whether the site may open. The gate URL is swapped in with
// location.replace so it takes over the just-committed site's history entry:
// Back from the gate then lands on the page the click started from, not on the
// unchecked site. If the page can't be scripted the tab is pointed at the gate
// with tabs.update instead, which parks it all the same at the cost of one
// extra history entry.
async function holdForClickGate(tabId: number, targetUrl: string, startUrl: string | null): Promise<void> {
  const gate = new URL(chrome.runtime.getURL("pages/click-gate.html"));
  gate.searchParams.set("target", targetUrl);
  if (startUrl) gate.searchParams.set("start", startUrl);
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      injectImmediately: true,
      func: (url: string) => {
        location.replace(url);
      },
      args: [gate.href],
    });
  } catch {
    try {
      await chrome.tabs.update(tabId, { url: gate.href });
    } catch {
      // Tab closed mid-navigation; nothing left to hold.
    }
  }
}

// Judge a just-committed navigation: a link click starts a scan of its start
// and finish URLs; a client redirect shortly after one re-scans the same
// click's new destination; anything else (typed, reload, form submit) ends the
// click's journey.
async function scanClickedLink(
  details: chrome.webNavigation.WebNavigationTransitionCallbackDetails,
): Promise<void> {
  if (details.frameId !== 0) return;
  // The pending start URL is consumed whatever this navigation turns out to
  // be, so a stale entry can never describe a later navigation.
  const navStart = navStartUrls.get(details.tabId);
  navStartUrls.delete(details.tabId);

  // A navigation the click gate just approved (the check passed, or the user
  // confirmed entering anyway) is let through untouched; anything else would
  // send the tab straight back to the gate.
  if (approvedClickUrls.get(details.tabId) === details.url) {
    approvedClickUrls.delete(details.tabId);
    return;
  }

  // Back/forward re-visits keep their original transition type but are not
  // clicks; the "forward_back" qualifier tells them apart.
  if (details.transitionQualifiers.includes("forward_back")) return;

  let startUrl: string;
  const now = Date.now();
  if (details.transitionQualifiers.includes("client_redirect")) {
    const journey = clickJourneys.get(details.tabId);
    if (!journey || now - journey.at > CLICK_JOURNEY_MS) return;
    journey.at = now;
    startUrl = journey.startUrl;
  } else if (details.transitionType === "link" && !isAddressBarNavigation(details)) {
    startUrl = navStart ?? details.url;
    clickJourneys.set(details.tabId, { startUrl, at: now });
  } else {
    clickJourneys.delete(details.tabId);
    return;
  }

  let finish: URL;
  try {
    finish = new URL(details.url);
  } catch {
    return;
  }
  if (finish.protocol !== "http:" && finish.protocol !== "https:") return;

  const settings = await loadSettings();
  if (!settings.linkClickScan) return;

  // The start URL gets its own row only when the click actually moved: with no
  // redirect the two ends are the same URL and one scan covers both.
  let start: URL | null = null;
  try {
    start = new URL(startUrl);
  } catch {
    // Unparseable start; judge the landing URL alone.
  }
  if (start && (start.protocol !== "http:" && start.protocol !== "https:")) start = null;
  if (start && start.href === finish.href) start = null;

  // The wait modes park the tab on the checking page instead of letting the
  // site load; the gate takes over from here (checks, verdict, enter or not).
  // The site may render for a moment before the gate replaces it, since a
  // commit cannot be cancelled, only redirected.
  if (settings.linkClickScanMode !== "overlay") {
    await holdForClickGate(details.tabId, details.url, start ? start.href : null);
    return;
  }

  const token = nextClickScanToken++;
  clickScanTokens.set(details.tabId, token);

  const dict = await loadMessages(settings.lang);
  const dir = settings.lang === "he" ? "rtl" : "ltr";
  const startLabel = dict.linkscan_start ?? "Clicked link";
  const endLabel = dict.linkscan_end ?? "Final destination";
  const close = dict.linkscan_close ?? "Close";

  const loadingRows: ClickScanRow[] = start
    ? [
        clickScanRow(startLabel, start.hostname, "loading", dict),
        clickScanRow(endLabel, finish.hostname, "loading", dict),
      ]
    : [clickScanRow(endLabel, finish.hostname, "loading", dict)];
  await drawClickScan(details.tabId, token, {
    title: dict.linkscan_checking ?? "Checking link reputation…",
    close,
    dir,
    done: false,
    rows: loadingRows,
  });

  const [startInput, finishInput] = await Promise.all([
    start ? scanReputationCategory(start, settings) : Promise.resolve(null),
    scanReputationCategory(finish, settings),
  ]);

  const doneRows: ClickScanRow[] = [];
  if (start && startInput) {
    doneRows.push(clickScanRow(startLabel, start.hostname, toClickScanStatus(startInput.status), dict));
  }
  doneRows.push(clickScanRow(endLabel, finish.hostname, toClickScanStatus(finishInput.status), dict));

  await drawClickScan(details.tabId, token, {
    title: dict.linkscan_done ?? "Link reputation",
    close,
    dir,
    done: true,
    rows: doneRows,
  });
}

// --------------------------------- Wiring --------------------------------- //

chrome.runtime.onInstalled.addListener(() => {
  void refreshIfStale();
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: 24 * 60 });
  chrome.alarms.create(INCREMENT_ALARM, { periodInMinutes: 60 });
});

chrome.runtime.onStartup.addListener(() => {
  void refreshIfStale();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) void refreshFull();
  else if (alarm.name === INCREMENT_ALARM) void refreshIncrement();
});

chrome.runtime.onMessage.addListener(
  (
    msg: { type?: string; host?: string; hosts?: unknown; target?: string; start?: string; url?: string },
    sender,
    sendResponse,
  ) => {
    if (msg?.type === "phishingdb-check" && typeof msg.host === "string") {
      isListed(msg.host).then(
        (status) => sendResponse({ status }),
        () => sendResponse({ status: "error" }),
      );
      return true; // keep the message channel open for the async response
    }
    // Batch lookup for the popup's Links view: which of the page's link hosts
    // are on the blocklist. One message covers the whole page.
    if (msg?.type === "phishingdb-check-batch" && Array.isArray(msg.hosts)) {
      const hosts = (msg.hosts as unknown[]).filter((h): h is string => typeof h === "string");
      listedAmong(hosts).then(
        (listed) =>
          sendResponse(listed ? { status: "ok", listed: [...listed] } : { status: "loading" }),
        () => sendResponse({ status: "error" }),
      );
      return true; // keep the message channel open for the async response
    }
    // The click gate asking for the reputation verdicts of a held click's two
    // ends. Runs the same checks the overlay path runs and answers with the
    // overlay's status per URL.
    if (msg?.type === "clickgate-scan" && typeof msg.target === "string") {
      const startRaw = typeof msg.start === "string" ? msg.start : null;
      (async () => {
        let finish: URL;
        try {
          finish = new URL(msg.target as string);
        } catch {
          return { status: "error" };
        }
        let start: URL | null = null;
        try {
          if (startRaw) start = new URL(startRaw);
        } catch {
          // Unparseable start; judge the destination alone.
        }
        const settings = await loadSettings();
        const [startInput, finishInput] = await Promise.all([
          start ? scanReputationCategory(start, settings) : Promise.resolve(null),
          scanReputationCategory(finish, settings),
        ]);
        return {
          status: "ok",
          start: startInput ? toClickScanStatus(startInput.status) : undefined,
          finish: toClickScanStatus(finishInput.status),
        };
      })().then(sendResponse, () => sendResponse({ status: "error" }));
      return true; // keep the message channel open for the async response
    }
    // The click gate about to enter a destination: remember it so the commit it
    // causes is let through instead of being sent back to the gate.
    if (msg?.type === "clickgate-approve" && typeof msg.url === "string") {
      const tabId = sender.tab?.id;
      if (typeof tabId === "number") approvedClickUrls.set(tabId, msg.url);
      sendResponse({ status: "ok" });
      return undefined; // answered synchronously
    }
    return undefined;
  },
);

// ----------------------------- Auto-scan wiring ---------------------------- //

// Record where each main-frame navigation starts, before any server redirect
// rewrites it; the link-click scan reads it back at commit time.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) navStartUrls.set(details.tabId, details.url);
});

// Warn on a risky URL entered directly in the address bar, the moment it commits
// (before the page's own scripts get to run). Independent of auto-scan.
// The same commit also feeds the opt-in link-click reputation scan.
chrome.webNavigation.onCommitted.addListener((details) => {
  void warnOnTypedNavigation(details);
  void scanClickedLink(details);
});

// Scan the active tab once it finishes loading. A fresh load forces a rescan even
// if the URL is unchanged (e.g. a reload), since the page content may have changed.
chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active) void maybeAutoScan(tab, true);
});

// Scan a tab when the user switches to it, unless its current URL was already scanned.
chrome.tabs.onActivated.addListener(({ tabId }) => {
  void chrome.tabs.get(tabId).then(
    (tab) => maybeAutoScan(tab),
    () => {},
  );
});

// Forget a closed tab's cached URL / in-flight flag / click-scan state.
chrome.tabs.onRemoved.addListener((tabId) => {
  lastScanned.delete(tabId);
  scanning.delete(tabId);
  navStartUrls.delete(tabId);
  clickJourneys.delete(tabId);
  clickScanTokens.delete(tabId);
  approvedClickUrls.delete(tabId);
});

// React to the auto-scan toggle changing in the options page: scan the visible
// tabs when it's turned on, clear every badge when it's turned off.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.settings) return;
  const next = (changes.settings.newValue as Settings | undefined)?.autoScan;
  const prev = (changes.settings.oldValue as Settings | undefined)?.autoScan;
  if (next === prev) return;
  if (next) {
    void chrome.tabs.query({ active: true }).then(
      (tabs) => {
        for (const t of tabs) void maybeAutoScan(t, true);
      },
      () => {},
    );
  } else {
    void clearAllBadges();
  }
});
