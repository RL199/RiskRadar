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

// Count credential-bait phrases in the page text/title, and list which ones were
// found. None → good; a couple → warning; three or more → risky.
export function analyzePhishingIndicators(page: PageContent): AnalyzedRow {
  const hits = matchTerms(normalize(`${page.title}\n${page.text}`), PHISHING_PHRASES);
  if (hits.length === 0) return { text: "0", status: "good" };
  return { text: String(hits.length), status: hits.length >= 3 ? "bad" : "warn", detail: hits };
}

// Count time-pressure / fear phrases and list which ones were found. None → good;
// a couple → warning; three or more → risky.
export function analyzeUrgentLanguage(page: PageContent): AnalyzedRow {
  const hits = matchTerms(normalize(`${page.title}\n${page.text}`), URGENCY_PHRASES);
  if (hits.length === 0) return { key: "val_none", status: "good" };
  return { text: String(hits.length), status: hits.length >= 3 ? "bad" : "warn", detail: hits };
}

// Count password forms that leak credentials — either across origins or over
// plain HTTP — and name which kind of leak. A cleartext (HTTP) submission is
// unambiguous → risky; a cross-origin HTTPS submission is suspicious but can be
// legitimate (federated login) → warning.
export function analyzeSuspiciousForms(page: PageContent): AnalyzedRow {
  const suspicious = page.forms.filter((f) => f.hasPassword && (f.crossOrigin || f.insecure));
  if (suspicious.length === 0) return { key: "val_none", status: "good" };
  const insecure = suspicious.some((f) => f.insecure);
  // Describe the distinct problems found (i18n keys the popup resolves), worst first.
  const detailKeys: string[] = [];
  if (insecure) detailKeys.push("det_form_insecure");
  if (suspicious.some((f) => f.crossOrigin)) detailKeys.push("det_form_crossOrigin");
  return { text: String(suspicious.length), status: insecure ? "bad" : "warn", detailKeys };
}

// Flag a page that names a well-known brand while sitting on a domain that isn't
// that brand's. Gated on the page actually asking for a password, since that's
// where impersonation does harm — and gating on it sharply cuts false positives
// from share buttons, ads, and footer mentions on ordinary sites. The matched
// brand wording is surfaced so the user can see what gave it away.
export function analyzeBrandImpersonation(page: PageContent, host: string): AnalyzedRow {
  if (page.passwordFields === 0) return { key: "val_none", status: "good" };

  const haystack = normalize(`${page.title}\n${page.text}`);
  const label = (splitDomain(host).registrable.split(".")[0] ?? "").toLowerCase();

  for (const brand of BRANDS) {
    if (brand.labels.includes(label)) continue; // we're on the brand's own domain
    const matched = brand.keywords.filter((kw) => hasTerm(haystack, kw));
    if (matched.length > 0) return { text: brand.name, status: "bad", detail: matched };
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

// One category of risky matches to mark on the page. `label` is the localized
// text shown on hover (e.g. "Phishing Indicators"); `phrases` are the matched
// terms in that category.
export interface HighlightGroup {
  label: string;
  phrases: string[];
}

// Injected into the active tab to visually mark the risky matches the Content
// Analysis view found: the flagged phrases get a non-destructive highlight that
// names its category on hover, and password forms that leak credentials get a red
// outline (whose category shows on hover via a native title). Like
// extractPageContent it must be fully self-contained — it runs in the page via
// chrome.scripting.executeScript (in the MAIN world, so it shares the page's CSS
// highlight registry). Safe to call repeatedly: each run tears down the previous
// run's marks and hover handler first, so re-scans don't stack and a now-clean
// page is un-marked when called with empty groups.
export function highlightPageMatches(groups: HighlightGroup[], formLabel: string): void {
  const HIGHLIGHT = "riskradar-risk";
  const STYLE_ID = "riskradar-highlight-style";
  const TOOLTIP_ID = "riskradar-tooltip";
  const OUTLINE_ATTR = "data-riskradar-outline";
  const ACCENT = "#f87171"; // matches the popup's danger red

  // The mousemove handler and tooltip leave no findable DOM trace, so stash a
  // teardown on window and run the previous scan's before starting a new one.
  const w = window as unknown as { __riskradarCleanup?: () => void };
  w.__riskradarCleanup?.();
  w.__riskradarCleanup = undefined;

  // Clear marks from a previous run so re-scans don't accumulate.
  CSS.highlights?.delete(HIGHLIGHT);
  document.getElementById(STYLE_ID)?.remove();
  document.getElementById(TOOLTIP_ID)?.remove();
  for (const el of document.querySelectorAll<HTMLElement>(`[${OUTLINE_ATTR}]`)) {
    el.style.outline = "";
    el.style.outlineOffset = "";
    el.removeAttribute(OUTLINE_ATTR);
    // Restore any title the page had before we borrowed it for the hover label.
    const prev = el.dataset.riskradarTitlePrev;
    if (prev !== undefined) {
      el.title = prev;
      delete el.dataset.riskradarTitlePrev;
    } else {
      el.removeAttribute("title");
    }
  }

  // Outline password forms that leak credentials (cross-domain or cleartext
  // action). Mirrors the form check in extractPageContent; the outline doesn't
  // affect layout, so it's a safe, reversible mark. A form is a real element, so
  // its native title gives the hover label for free.
  const reg = (h: string): string => {
    const parts = h.toLowerCase().split(".");
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
  };
  const pageReg = reg(location.hostname);
  const pageInsecure = location.protocol === "http:";
  for (const form of document.querySelectorAll("form")) {
    if (form.querySelector('input[type="password"]') === null) continue;
    let suspicious: boolean;
    try {
      const action = new URL(form.action || location.href, location.href);
      suspicious =
        action.protocol === "http:" ||
        pageInsecure ||
        (action.hostname !== "" && reg(action.hostname) !== pageReg);
    } catch {
      suspicious = pageInsecure;
    }
    if (suspicious) {
      form.style.outline = `2px solid ${ACCENT}`;
      form.style.outlineOffset = "2px";
      form.setAttribute(OUTLINE_ATTR, "");
      if (form.title) form.dataset.riskradarTitlePrev = form.title;
      form.title = formLabel;
    }
  }

  // Highlight the flagged phrases. The CSS Custom Highlight API marks text ranges
  // without mutating the DOM (no wrapper elements to break the page or clean up).
  if (typeof Highlight === "undefined" || !CSS.highlights || !document.body) return;

  // Build a tolerant regex per phrase, tagged with its category label: whole-word
  // (as the analyzers matched), case-insensitive, flexible whitespace so a phrase
  // still matches across a line break, and apostrophes matching typographic ones.
  const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const tagged = groups
    .filter((g) => g.phrases.length > 0)
    .map((g) => ({
      label: g.label,
      regexes: g.phrases.map(
        (p) => new RegExp(`\\b${esc(p).replace(/ /g, "\\s+").replace(/'/g, "['‘’]")}\\b`, "gi"),
      ),
    }));
  if (tagged.length === 0) return;

  // Walk visible text nodes and collect a Range (tagged with its category) for
  // every match.
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const tag = node.parentElement?.tagName;
      if (!tag || tag === "SCRIPT" || tag === "STYLE" || tag === "NOSCRIPT") return NodeFilter.FILTER_REJECT;
      return node.nodeValue?.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });

  const marks: { range: Range; label: string }[] = [];
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = node.nodeValue ?? "";
    for (const { label, regexes } of tagged) {
      for (const re of regexes) {
        re.lastIndex = 0;
        for (let m = re.exec(text); m; m = re.exec(text)) {
          const range = document.createRange();
          range.setStart(node, m.index);
          range.setEnd(node, m.index + m[0].length);
          marks.push({ range, label });
          if (re.lastIndex === m.index) re.lastIndex++; // guard against zero-length loops
        }
      }
    }
  }
  if (marks.length === 0) return;

  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `::highlight(${HIGHLIGHT}){background-color:rgba(248,113,113,.30);}`;
  (document.head ?? document.documentElement).append(style);
  CSS.highlights.set(HIGHLIGHT, new Highlight(...marks.map((m) => m.range)));

  // Hover tooltip naming the category. A highlight is painted, not a real element,
  // so it can't receive a title or hover events; instead we hit-test the cursor
  // against the marked ranges on mousemove and show our own floating tooltip.
  const tooltip = document.createElement("div");
  tooltip.id = TOOLTIP_ID;
  tooltip.style.cssText =
    "position:fixed!important;z-index:2147483647!important;pointer-events:none!important;" +
    "max-width:260px!important;padding:4px 8px!important;border-radius:6px!important;" +
    "background:#1f2937!important;color:#fff!important;box-shadow:0 2px 8px rgba(0,0,0,.35)!important;" +
    "font:500 12px/1.4 system-ui,-apple-system,sans-serif!important;white-space:nowrap!important;";
  tooltip.style.setProperty("display", "none", "important");
  document.documentElement.append(tooltip);

  // caretPositionFromPoint is the standard (newer Chrome); caretRangeFromPoint is
  // the long-standing WebKit/Blink fallback. Cast through unknown so this stays
  // compilable whatever the lib's exact typings are.
  const cpp = (document as unknown as {
    caretPositionFromPoint?: (x: number, y: number) => { offsetNode: Node; offset: number } | null;
  }).caretPositionFromPoint?.bind(document);
  const crp = (document as unknown as {
    caretRangeFromPoint?: (x: number, y: number) => Range | null;
  }).caretRangeFromPoint?.bind(document);

  const caretFromPoint = (x: number, y: number): { node: Node; offset: number } | null => {
    const p = cpp?.(x, y);
    if (p) return { node: p.offsetNode, offset: p.offset };
    const r = crp?.(x, y);
    if (r) return { node: r.startContainer, offset: r.startOffset };
    return null;
  };

  const onMove = (e: MouseEvent): void => {
    const hit = caretFromPoint(e.clientX, e.clientY);
    let label: string | null = null;
    if (hit) {
      for (const m of marks) {
        try {
          if (m.range.isPointInRange(hit.node, hit.offset)) {
            label = m.label;
            break;
          }
        } catch {
          // Caret node isn't comparable to this range — skip it.
        }
      }
    }
    if (!label) {
      tooltip.style.setProperty("display", "none", "important");
      return;
    }
    tooltip.textContent = label;
    tooltip.style.setProperty("display", "block", "important");
    // Offset from the cursor, flipping to stay inside the viewport.
    let x = e.clientX + 14;
    let y = e.clientY + 16;
    if (x + tooltip.offsetWidth + 8 > window.innerWidth) x = e.clientX - 14 - tooltip.offsetWidth;
    if (y + tooltip.offsetHeight + 8 > window.innerHeight) y = e.clientY - 14 - tooltip.offsetHeight;
    tooltip.style.setProperty("left", `${Math.max(4, x)}px`, "important");
    tooltip.style.setProperty("top", `${Math.max(4, y)}px`, "important");
  };

  document.addEventListener("mousemove", onMove, { passive: true });
  w.__riskradarCleanup = () => {
    document.removeEventListener("mousemove", onMove);
    tooltip.remove();
  };
}
