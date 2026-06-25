// URL & Domain analysis. Pure, framework-free helpers used by the popup's
// "URL & Domain" view. Each synchronous check returns an AnalyzedRow describing
// what to show and how risky it is; the domain-age check is async because it
// queries a registry over the network (RDAP).

export type RowStatus = "good" | "warn" | "bad" | "neutral" | "unknown";

export interface AnalyzedRow {
  // Either a literal value (e.g. "HTTPS", a hostname) or an i18n message key
  // the caller resolves against the active dictionary (e.g. "val_short").
  text?: string;
  key?: string;
  status: RowStatus;
  // Optional list of the specific risky items behind this verdict, shown under
  // the row. `detail` holds literal text found verbatim on the page (e.g. the
  // matched phrases) and is rendered as-is; `detailKeys` holds i18n message keys
  // for described findings (e.g. the kind of suspicious form) the caller resolves.
  detail?: string[];
  detailKeys?: string[];
}

// Second-level suffixes where the registrable domain is the last THREE labels
// (e.g. bbc.co.uk), so we don't mistake "co" / "com" for a subdomain. This is a
// pragmatic subset of the Public Suffix List — enough for common ccTLDs without
// bundling the full ~10k-entry list into the popup.
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.nz", "co.za",
  "com.au", "net.au", "org.au", "com.br", "com.cn", "com.mx", "com.tr",
  "co.il", "org.il", "ac.il", "gov.il",
]);

// Tokens that show up far more often in phishing URLs than in the paths of the
// sites they impersonate. Kept deliberately high-signal to limit false
// positives (a stated project goal); tune this list as needed. Shared with the
// Links view, which reuses it to spot stacked phishing words in a link's host.
export const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "verification", "secure", "account",
  "update", "confirm", "password", "banking", "webscr", "ebayisapi", "wallet",
  "suspended", "unlock", "recover", "billing", "invoice", "appleid",
];

export const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Split a hostname into its subdomain prefix and registrable domain. */
export function splitDomain(hostname: string): { sub: string; registrable: string } {
  const labels = hostname.split(".");
  if (labels.length <= 2) return { sub: "", registrable: hostname };

  const lastTwo = labels.slice(-2).join(".");
  const registrableCount = MULTI_PART_SUFFIXES.has(lastTwo) ? 3 : 2;
  if (labels.length <= registrableCount) return { sub: "", registrable: hostname };

  return {
    sub: labels.slice(0, labels.length - registrableCount).join("."),
    registrable: labels.slice(-registrableCount).join("."),
  };
}

export function analyzeProtocol(url: URL): AnalyzedRow {
  if (url.protocol === "https:") return { text: "HTTPS", status: "good" };
  if (url.protocol === "http:") return { text: "HTTP", status: "bad" };
  return { text: url.protocol.replace(":", "").toUpperCase() || "—", status: "neutral" };
}

export function analyzeSubdomain(hostname: string): AnalyzedRow {
  // A raw IP address as the host is a classic phishing tell.
  if (IPV4_RE.test(hostname)) return { text: hostname, status: "bad" };

  const { sub } = splitDomain(hostname);
  if (!sub) return { key: "val_none", status: "good" };

  // "www" is benign; a single custom subdomain is normal; deep nesting
  // (login.secure.example.com.evil.tld style) is suspicious.
  const depth = sub.split(".").length;
  const status: RowStatus = sub === "www" || depth === 1 ? "good" : "warn";
  return { text: sub, status };
}

export function analyzeUrlLength(url: URL): AnalyzedRow {
  const len = url.href.length;
  if (len < 54) return { key: "val_short", status: "good" };
  if (len <= 100) return { key: "val_medium", status: "good" };
  return { key: "val_long", status: "warn" };
}

export function analyzeSuspiciousKeywords(url: URL): AnalyzedRow {
  const haystack = `${url.hostname}${url.pathname}${url.search}`.toLowerCase();
  const hits = SUSPICIOUS_KEYWORDS.filter((kw) => haystack.includes(kw));
  if (hits.length === 0) return { key: "val_noneFound", status: "good" };

  const shown = hits.slice(0, 3).join(", ");
  const text = hits.length > 3 ? `${shown} +${hits.length - 3}` : shown;
  return { text, status: hits.length >= 3 ? "bad" : "warn" };
}

// Look up a domain's registration date via RDAP (the JSON successor to WHOIS).
// rdap.org is the IANA bootstrap that 302-redirects to the authoritative
// registry for the TLD; fetch follows the redirect automatically. Returns null
// when the registry has no RDAP service (some ccTLDs) or the request fails.
export async function fetchRegistrationDate(registrableDomain: string): Promise<Date | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`, {
      redirect: "follow",
      headers: { accept: "application/rdap+json" },
    });
    if (!res.ok) return null;

    const data: { events?: { eventAction?: string; eventDate?: string }[] } = await res.json();
    const registration = data.events?.find((e) => e.eventAction === "registration");
    if (!registration?.eventDate) return null;

    const date = new Date(registration.eventDate);
    return Number.isNaN(date.getTime()) ? null : date;
  } catch {
    // Network error, CORS, or malformed JSON — treat as "unknown".
    return null;
  }
}

/** Whether a host is one RDAP can't resolve (IP literal, localhost, single label). */
export function isLookupableDomain(hostname: string): boolean {
  return hostname.includes(".") && !IPV4_RE.test(hostname) && hostname !== "localhost";
}
