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
  extractPageLinks,
  highlightPageLinks,
  type ClassifiedLink,
  type LinkMark,
  type PageLinks,
} from "../shared/link-analysis";

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

async function isListed(host: string): Promise<LookupStatus> {
  await ensureLoaded();
  if (!domainSet) {
    void refreshIfStale(); // first use also kicks off the initial download
    return "loading";
  }
  const h = host.toLowerCase();
  if (domainSet.has(h)) return "listed";
  // A listed registrable domain covers its subdomains (e.g. login.evil.tld).
  const { registrable } = splitDomain(h);
  if (registrable !== h && domainSet.has(registrable)) return "listed";
  return "clean";
}

// ------------------------------- Auto-scan -------------------------------- //
//
// When the user turns on "Scan pages automatically" (settings.autoScan), the
// worker scans each page as it finishes loading in the active tab, without the
// popup ever being opened. It runs the same offline + reputation + page checks
// the popup runs (everything except the paid AI analysis), folds them into one
// overall verdict shown as a colour-coded badge on the toolbar icon, and applies
// the same in-page highlights the popup would, honouring the user's per-element
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
async function scanUrlCategory(url: URL): Promise<RowStatus> {
  const statuses: RowStatus[] = [
    analyzeProtocol(url).status,
    analyzeSubdomain(url.hostname).status,
    analyzeUrlLength(url).status,
    analyzeSuspiciousKeywords(url).status,
  ];
  if (isLookupableDomain(url.hostname)) {
    const date = await fetchRegistrationDate(splitDomain(url.hostname).registrable);
    if (date) {
      const days = (Date.now() - date.getTime()) / 86_400_000;
      statuses.push(days < 30 ? "bad" : days < 180 ? "warn" : "good");
    }
  }
  return overallOf(statuses);
}

// Reputation category: the same lookups the popup runs. The Phishing.Database
// row reads this worker's own cached list directly (isListed) instead of the
// message round-trip the popup uses, since a worker can't message itself.
async function scanReputationCategory(url: URL, settings: Settings): Promise<RowStatus> {
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
  return overallOf(statuses);
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
): Promise<RowStatus> {
  const page = await getPageContent(tabId);
  if (!page) return "unknown";

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

  return overallOf([phishing.status, forms.status, urgent.status, brand.status]);
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

// Links category: read the page, classify its links, and outline them on the
// page for the verdict buckets the user left enabled.
async function scanLinksCategory(tabId: number, settings: Settings, dict: Dict): Promise<RowStatus> {
  const page = await getPageLinks(tabId);
  if (!page) return "unknown";

  const { classified, total, external, suspicious, redirects } = analyzeLinks(page);

  const hl = settings.highlights;
  const enabled: Record<ClassifiedLink["verdict"], boolean> = {
    internal: hl.internalLinks,
    external: hl.externalLinks,
    suspicious: hl.suspiciousLinks,
    redirect: hl.maliciousRedirects,
    ignore: false,
  };
  const marks: LinkMark[] = classified.map((link) =>
    enabled[link.verdict] && link.verdict !== "ignore"
      ? { verdict: link.verdict, title: linkTitle(link, dict) }
      : { verdict: "skip", title: "" },
  );
  try {
    await chrome.scripting.executeScript({ target: { tabId }, func: highlightPageLinks, args: [marks] });
  } catch {
    // Page stopped being scriptable between read and mark; nothing to do.
  }

  return overallOf([total.status, external.status, suspicious.status, redirects.status]);
}

// Toolbar-badge presentation per overall verdict. The colours mirror the popup's
// status palette: a determinate verdict shows its glyph; "unknown" is the popup's
// muted "Can't scan this page" state, shown as a grey "?" beside the icon.
const BADGE: Record<"good" | "warn" | "bad" | "unknown", { text: string; color: string }> = {
  good: { text: "✓", color: "#16a34a" },
  warn: { text: "!", color: "#d97706" },
  bad: { text: "✕", color: "#dc2626" },
  unknown: { text: "?", color: "#6b7280" },
};

// Badge for a page we couldn't produce a verdict for (a privileged page, or one
// where every category came back unknown): the popup's "Can't scan this page".
async function markUnscannable(tabId: number): Promise<void> {
  await setBadge(tabId, BADGE.unknown.text, BADGE.unknown.color);
}

async function clearBadge(tabId: number): Promise<void> {
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
  } catch {
    // Tab closed mid-scan.
  }
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

// Run every category for one tab and paint the overall verdict onto its badge.
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

    const statuses = await Promise.all([
      scanUrlCategory(url),
      scanReputationCategory(url, settings),
      scanContentCategory(tabId, url, settings, dict),
      scanLinksCategory(tabId, settings, dict),
    ]);

    const overall = overallOf(statuses);
    if (overall === "good" || overall === "warn" || overall === "bad") {
      await setBadge(tabId, BADGE[overall].text, BADGE[overall].color);
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

chrome.runtime.onMessage.addListener((msg: { type?: string; host?: string }, _sender, sendResponse) => {
  if (msg?.type === "phishingdb-check" && typeof msg.host === "string") {
    isListed(msg.host).then(
      (status) => sendResponse({ status }),
      () => sendResponse({ status: "error" }),
    );
    return true; // keep the message channel open for the async response
  }
  return undefined;
});

// ----------------------------- Auto-scan wiring ---------------------------- //

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

// Forget a closed tab's cached URL / in-flight flag.
chrome.tabs.onRemoved.addListener((tabId) => {
  lastScanned.delete(tabId);
  scanning.delete(tabId);
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
