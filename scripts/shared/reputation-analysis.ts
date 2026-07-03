// Reputation analysis. Framework-free helpers used by the popup's "Reputation"
// view. Two checks query third-party services that need an API key (Google Safe
// Browsing and VirusTotal); two are keyless and resolve the host through
// threat-filtering public DNS (Cloudflare and Quad9) to see whether it has been
// sink-holed as malicious. Every function degrades to an "unknown" row instead
// of throwing, so a failed or skipped lookup never breaks the popup.

import type { AnalyzedRow, RowStatus } from "./url-analysis";

// ----------------------- DNS-over-HTTPS reputation ----------------------- //

// Placeholder addresses a filtering resolver hands back instead of the real IP
// when a host is on its block list. A "resolved" answer must not be one of these.
const SINKHOLE_IPS = new Set(["0.0.0.0", "::", "127.0.0.1"]);

const DOH = {
  // Non-filtering baseline: what the host actually resolves to.
  baseline: "https://dns.google/resolve",
  // Cloudflare's malware/phishing-filtering resolver (1.1.1.2 family).
  cloudflareSecurity: "https://security.cloudflare-dns.com/dns-query",
  // Quad9's threat-intelligence resolver — an independent set of feeds.
  quad9: "https://dns.quad9.net/dns-query",
};

interface DohResult {
  // DNS response code: 0 = NOERROR, 3 = NXDOMAIN, others = SERVFAIL/REFUSED/…
  status: number;
  // True when the resolver returned at least one real A/AAAA address, i.e. it
  // did NOT block or sinkhole the host.
  resolved: boolean;
}

// Query a DoH resolver's JSON API for a host's A record. Returns null on any
// network/parse error so callers can treat it as "unknown".
async function dohResolve(resolverUrl: string, host: string): Promise<DohResult | null> {
  try {
    const url = `${resolverUrl}?name=${encodeURIComponent(host)}&type=A`;
    const res = await fetch(url, { headers: { accept: "application/dns-json" } });
    if (!res.ok) return null;

    const data: { Status?: number; Answer?: { type?: number; data?: string }[] } = await res.json();
    const status = typeof data.Status === "number" ? data.Status : -1;
    const resolved =
      status === 0 &&
      (data.Answer ?? []).some(
        (a) => (a.type === 1 || a.type === 28) && a.data !== undefined && !SINKHOLE_IPS.has(a.data),
      );
    return { status, resolved };
  } catch {
    return null;
  }
}

// Whether a filtering resolver deliberately blocked the host: it returned no
// real address via a sinkhole answer (0.0.0.0) or NXDOMAIN, rather than a
// transient error (which we don't count, so it can't masquerade as a hit).
function isBlocked(filtered: DohResult | null): boolean {
  if (!filtered || filtered.resolved) return false;
  return filtered.status === 3 || filtered.status === 0; // NXDOMAIN or sinkhole answer
}

// Resolve the host through a neutral baseline plus both threat-filtering
// resolvers (Cloudflare + Quad9) and combine them into the "Blacklist Status"
// row: if either filter sinkholes a host that otherwise resolves, it's listed.
export async function checkDnsBlacklist(host: string): Promise<AnalyzedRow> {
  const [baseline, cloudflare, quad9] = await Promise.all([
    dohResolve(DOH.baseline, host),
    dohResolve(DOH.cloudflareSecurity, host),
    dohResolve(DOH.quad9, host),
  ]);

  if (!baseline || !baseline.resolved) return { key: "val_unknown", status: "unknown" };
  if (isBlocked(cloudflare) || isBlocked(quad9)) return { key: "val_blacklisted", status: "bad" };
  if (cloudflare?.resolved || quad9?.resolved) return { key: "val_clean", status: "good" };
  return { key: "val_unknown", status: "unknown" };
}

// ---------------------------- Phishing.Database ---------------------------- //

// Check the host against the locally cached Phishing.Database list, maintained by
// the background service worker (see scripts/background/background.ts). The
// lookup is an instant, offline message round-trip — no per-popup download.
export async function checkPhishingDatabase(host: string): Promise<AnalyzedRow> {
  try {
    const res: { status?: string } = await chrome.runtime.sendMessage({
      type: "phishingdb-check",
      host,
    });
    switch (res?.status) {
      case "listed":
        return { key: "val_listed", status: "bad" };
      case "clean":
        return { key: "val_notListed", status: "good" };
      case "loading":
        return { key: "val_updating", status: "unknown" };
      default:
        return { key: "val_unknown", status: "unknown" };
    }
  } catch {
    return { key: "val_unknown", status: "unknown" };
  }
}

// -------------------------- Google Safe Browsing -------------------------- //

const GSB_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

function humanizeThreat(threatType: string | undefined): string {
  switch (threatType) {
    case "SOCIAL_ENGINEERING":
      return "Phishing";
    case "MALWARE":
      return "Malware";
    case "UNWANTED_SOFTWARE":
      return "Unwanted software";
    case "POTENTIALLY_HARMFUL_APPLICATION":
      return "Harmful app";
    default:
      return "Flagged";
  }
}

// Look up a URL/host in Google Safe Browsing. With an API key it uses the
// official Lookup API v4 (authoritative, supported); without one it falls back
// to Google's public Transparency Report endpoint — the same keyless source that
// powers the "Safe Browsing site status" web page. Either way: "good" when
// clean, "bad" when listed, "unknown" when Google has no data or on error.
export async function checkSafeBrowsing(
  rawUrl: string,
  host: string,
  apiKey: string,
): Promise<AnalyzedRow> {
  return apiKey ? checkSafeBrowsingApi(rawUrl, apiKey) : checkSafeBrowsingPublic(host);
}

async function checkSafeBrowsingApi(rawUrl: string, apiKey: string): Promise<AnalyzedRow> {
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "risk-radar", clientVersion: "0.0.1" },
          threatInfo: {
            threatTypes: GSB_THREAT_TYPES,
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: rawUrl }],
          },
        }),
      },
    );
    if (!res.ok) return { key: "val_unknown", status: "unknown" };

    const data: { matches?: { threatType?: string }[] } = await res.json();
    const match = data.matches?.[0];
    if (!match) return { key: "val_clean", status: "good" };
    return { text: humanizeThreat(match.threatType), status: "bad" };
  } catch {
    return { key: "val_unknown", status: "unknown" };
  }
}

// Google's Transparency Report backend returns a JSON array guarded by an
// anti-XSSI prefix:
//   )]}'\n[["sb.ssr", statusCode, f1,f2,f3,f4,f5, timestamp, "site"]]
// The five booleans flag detected threat categories; a zero timestamp means
// Google holds no data on the host.
async function checkSafeBrowsingPublic(host: string): Promise<AnalyzedRow> {
  try {
    const res = await fetch(
      `https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=${encodeURIComponent(host)}`,
    );
    if (!res.ok) return { key: "val_unknown", status: "unknown" };

    const entry = parseTransparencyEntry(await res.text());
    if (!entry) return { key: "val_unknown", status: "unknown" };

    const flagged = entry.slice(2, 7).some((f) => f === true);
    if (flagged) return { key: "val_unsafe", status: "bad" };

    // A real timestamp means Google has scanned it and found nothing; a zero
    // timestamp means there's simply no data to judge by.
    const timestamp = typeof entry[7] === "number" ? entry[7] : 0;
    return timestamp > 0
      ? { key: "val_clean", status: "good" }
      : { key: "val_unknown", status: "unknown" };
  } catch {
    return { key: "val_unknown", status: "unknown" };
  }
}

function parseTransparencyEntry(body: string): unknown[] | null {
  try {
    const data: unknown = JSON.parse(body.replace(/^\)\]\}'/, "").trim());
    const entry = Array.isArray(data) ? data[0] : undefined;
    return Array.isArray(entry) ? entry : null;
  } catch {
    return null;
  }
}

// ------------------------------- VirusTotal ------------------------------- //

// Look up a domain's VirusTotal report. Needs a (free-tier) API key. The value
// shows how many security vendors flagged the domain out of the total that
// scanned it.
export async function checkVirusTotal(host: string, apiKey: string): Promise<AnalyzedRow> {
  if (!apiKey) return { key: "val_notChecked", status: "unknown" };
  try {
    const res = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(host)}`,
      { headers: { "x-apikey": apiKey } },
    );
    if (!res.ok) return { key: "val_unknown", status: "unknown" };

    const data: { data?: { attributes?: { last_analysis_stats?: Record<string, number> } } } =
      await res.json();
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) return { key: "val_unknown", status: "unknown" };

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total = Object.values(stats).reduce((sum, n) => sum + n, 0);
    const status: RowStatus = malicious > 0 ? "bad" : suspicious > 0 ? "warn" : "good";
    return { text: `${malicious} / ${total}`, status };
  } catch {
    return { key: "val_unknown", status: "unknown" };
  }
}

// ----------------------------- Sucuri SiteCheck ----------------------------- //

function hasEntries(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (value && typeof value === "object") return Object.keys(value).length > 0;
  return false;
}

// Scan a host with Sucuri SiteCheck — a keyless website scanner that aggregates
// several blacklists (Google Safe Browsing, Sucuri Labs, Norton, McAfee, ESET,
// Yandex, PhishTank…) plus its own malware checks. Returns "bad" when the host
// is blacklisted or flagged for malware, "good" when the scan is clean, and
// "unknown" when the scan can't complete or on error.
export async function checkSucuri(host: string): Promise<AnalyzedRow> {
  try {
    const res = await fetch(
      `https://sitecheck.sucuri.net/api/v3/?scan=${encodeURIComponent(host)}`,
    );
    if (!res.ok) return { key: "val_unknown", status: "unknown" };

    const data: {
      scan?: unknown;
      ratings?: unknown;
      blacklists?: unknown;
      warnings?: { security?: unknown; scan_failed?: unknown };
    } = await res.json();

    if (hasEntries(data.blacklists)) return { key: "val_blacklisted", status: "bad" };
    if (hasEntries(data.warnings?.security)) return { key: "val_unsafe", status: "bad" };

    // A failed scan (e.g. the site timed out) leaves us unable to judge.
    if (data.warnings?.scan_failed) return { key: "val_unknown", status: "unknown" };

    return data.scan || data.ratings
      ? { key: "val_clean", status: "good" }
      : { key: "val_unknown", status: "unknown" };
  } catch {
    return { key: "val_unknown", status: "unknown" };
  }
}

// --------------------------- Server IP reputation --------------------------- //

// AS-name fragments that mark an address as shared CDN/cloud infrastructure
// rather than the site's own server. IP reputation is meaningless for these
// (thousands of unrelated sites share the address), so we report N/A instead.
const CDN_AS_KEYWORDS = [
  "CLOUDFLARE", "GOOGLE", "AMAZON", "AKAMAI", "FASTLY", "MICROSOFT", "AZURE",
  "CLOUDFRONT", "INCAPSULA", "IMPERVA", "EDGECAST", "STACKPATH", "LIMELIGHT", "CDN",
];

function isCdnAsn(asname: string | null | undefined): boolean {
  if (!asname) return false;
  const upper = asname.toUpperCase();
  return CDN_AS_KEYWORDS.some((kw) => upper.includes(kw));
}

function toCount(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

// Resolve a host to its first A-record address via the baseline DoH resolver.
async function resolveFirstIp(host: string): Promise<string | null> {
  try {
    const res = await fetch(`${DOH.baseline}?name=${encodeURIComponent(host)}&type=A`, {
      headers: { accept: "application/dns-json" },
    });
    if (!res.ok) return null;
    const data: { Answer?: { type?: number; data?: string }[] } = await res.json();
    return (data.Answer ?? []).find((a) => a.type === 1 && a.data)?.data ?? null;
  } catch {
    return null;
  }
}

// Look up the host's server IP in the SANS ISC / DShield database — a keyless
// feed of addresses reported attacking internet honeypots. Hosts behind a shared
// CDN/cloud IP are reported as N/A (the address isn't the site's own server), so
// a noisy neighbour can't drag the verdict down.
export async function checkIpReputation(host: string): Promise<AnalyzedRow> {
  try {
    const ip = await resolveFirstIp(host);
    if (!ip) return { key: "val_unknown", status: "unknown" };

    const res = await fetch(`https://isc.sans.edu/api/ip/${encodeURIComponent(ip)}?json`);
    if (!res.ok) return { key: "val_unknown", status: "unknown" };

    const data: { ip?: { count?: unknown; attacks?: unknown; asname?: string | null } } =
      await res.json();
    const info = data.ip;
    if (!info) return { key: "val_unknown", status: "unknown" };

    // A shared CDN/cloud address isn't the site's own server — don't judge it.
    if (isCdnAsn(info.asname)) return { key: "val_sharedCdn", status: "unknown" };

    const reports = Math.max(toCount(info.count), toCount(info.attacks));
    return reports > 0
      ? { key: "val_reported", status: "warn" }
      : { key: "val_clean", status: "good" };
  } catch {
    return { key: "val_unknown", status: "unknown" };
  }
}
