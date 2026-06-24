// Background service worker. Maintains a local, offline copy of the
// Phishing.Database project's active phishing-domain list so the popup can check
// the current host instantly, without downloading ~10 MB on every open. The list
// is cached in IndexedDB, fully refreshed daily, and topped up hourly from the
// project's "new in the last hour" feed. The popup queries it over a message.

import { splitDomain } from "../shared/url-analysis";

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
