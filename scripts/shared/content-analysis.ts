// Content analysis. Framework-free helpers used by the popup's "Content Analysis"
// view. Unlike URL & Reputation (which only need the host), these checks need the
// page's DOM, so the popup injects extractPageContent() into the active tab via
// chrome.scripting.executeScript and runs the risk logic here on the small,
// JSON-safe summary it returns. Every check is purely textual/structural and
// offline, and kept deliberately high-signal to limit false positives.

import { splitDomain, type AnalyzedRow } from "./url-analysis";
import { BRANDS, PHISHING_PHRASES, URGENCY_PHRASES } from "./content-data";

// The serializable summary the in-page extractor returns. Kept small and JSON-safe
// because it crosses the executeScript boundary back into the popup.
export interface FormSummary {
  // The form contains at least one <input type="password">.
  hasPassword: boolean;
  // A password form whose action posts to a different registrable domain
  // (a classic credential-exfiltration tell).
  crossOrigin: boolean;
  // A password form that submits over plain HTTP (credentials sent in clear).
  insecure: boolean;
}

export interface PageContent {
  title: string;
  // Visible page text (document.body.innerText), capped so a huge page can't
  // bloat the message payload.
  text: string;
  // Total <input type="password"> on the page, including any outside a <form>.
  passwordFields: number;
  forms: FormSummary[];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Normalize page text for matching: lowercase, fold smart quotes to ASCII, and
// collapse runs of whitespace so a multi-word phrase still matches when it spans
// a line break or uses typographic punctuation.
function normalize(text: string): string {
  return text
    .toLowerCase()
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/\s+/g, " ");
}

// Whether a lowercase term occurs in `haystack` as a whole word/phrase, so short
// tokens (e.g. "ups") don't fire inside unrelated words ("backups").
function hasTerm(haystack: string, term: string): boolean {
  return new RegExp(`\\b${escapeRegExp(term)}\\b`).test(haystack);
}

// Terms from `list` present in the (already normalized) haystack, with any match
// that is merely a substring of a longer match dropped — so a broad term and a
// more specific one covering the same text count once, not twice.
function matchTerms(haystack: string, list: string[]): string[] {
  const hits = list.filter((t) => hasTerm(haystack, t));
  return hits.filter((t) => !hits.some((o) => o !== t && o.includes(t)));
}

// Count credential-bait phrases in the page text/title. None → good; a couple →
// warning; three or more → risky.
export function analyzePhishingIndicators(page: PageContent): AnalyzedRow {
  const hits = matchTerms(normalize(`${page.title}\n${page.text}`), PHISHING_PHRASES);
  if (hits.length === 0) return { text: "0", status: "good" };
  return { text: String(hits.length), status: hits.length >= 3 ? "bad" : "warn" };
}

// Count time-pressure / fear phrases. None → good; a couple → warning; three or
// more → risky.
export function analyzeUrgentLanguage(page: PageContent): AnalyzedRow {
  const hits = matchTerms(normalize(`${page.title}\n${page.text}`), URGENCY_PHRASES);
  if (hits.length === 0) return { key: "val_none", status: "good" };
  return { text: String(hits.length), status: hits.length >= 3 ? "bad" : "warn" };
}

// Count password forms that leak credentials — either across origins or over
// plain HTTP. A cleartext (HTTP) submission is unambiguous → risky; a cross-origin
// HTTPS submission is suspicious but can be legitimate (federated login) → warning.
export function analyzeSuspiciousForms(page: PageContent): AnalyzedRow {
  const suspicious = page.forms.filter((f) => f.hasPassword && (f.crossOrigin || f.insecure));
  if (suspicious.length === 0) return { key: "val_none", status: "good" };
  const insecure = suspicious.some((f) => f.insecure);
  return { text: String(suspicious.length), status: insecure ? "bad" : "warn" };
}

// Flag a page that names a well-known brand while sitting on a domain that isn't
// that brand's. Gated on the page actually asking for a password, since that's
// where impersonation does harm — and gating on it sharply cuts false positives
// from share buttons, ads, and footer mentions on ordinary sites.
export function analyzeBrandImpersonation(page: PageContent, host: string): AnalyzedRow {
  if (page.passwordFields === 0) return { key: "val_none", status: "good" };

  const haystack = normalize(`${page.title}\n${page.text}`);
  const label = (splitDomain(host).registrable.split(".")[0] ?? "").toLowerCase();

  for (const brand of BRANDS) {
    if (brand.labels.includes(label)) continue; // we're on the brand's own domain
    if (brand.keywords.some((kw) => hasTerm(haystack, kw))) return { text: brand.name, status: "bad" };
  }
  return { key: "val_none", status: "good" };
}

// Injected into the active tab by the popup (chrome.scripting.executeScript) and
// run in the page's context, so it must be fully self-contained: it references no
// module-scope identifiers or imports, only the page's DOM. It returns the small
// PageContent summary the analyzers above consume.
export function extractPageContent(): PageContent {
  // Registrable domain as the last two labels — a deliberately simple in-page
  // approximation (the popup-side splitDomain handles multi-part ccTLDs); it's
  // only used to compare a form's action host against the page's own host.
  const reg = (h: string): string => {
    const parts = h.toLowerCase().split(".");
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
  };

  const pageReg = reg(window.location.hostname);
  const pageInsecure = window.location.protocol === "http:";

  const forms: FormSummary[] = Array.from(document.querySelectorAll("form")).map((form) => {
    const hasPassword = form.querySelector('input[type="password"]') !== null;
    let crossOrigin = false;
    let insecure = false;
    if (hasPassword) {
      try {
        // form.action resolves to an absolute URL (the page URL when unset).
        const action = new URL(form.action || window.location.href, window.location.href);
        crossOrigin = action.hostname !== "" && reg(action.hostname) !== pageReg;
        insecure = action.protocol === "http:" || pageInsecure;
      } catch {
        // Non-navigable action (javascript:, mailto:, …): judge by page protocol only.
        insecure = pageInsecure;
      }
    }
    return { hasPassword, crossOrigin, insecure };
  });

  return {
    title: document.title ?? "",
    text: (document.body?.innerText ?? "").slice(0, 20000),
    passwordFields: document.querySelectorAll('input[type="password"]').length,
    forms,
  };
}
