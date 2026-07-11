// Popup entry point. Compiled to popup.js by esbuild and loaded from popup.html.
// Applies the user's theme/language, then handles view navigation.

import { loadSettings, saveSettings, type AiProvider, type LangPref, type Settings } from "../scripts/shared/settings";
import { applyTheme } from "../scripts/shared/theme";
import { applyI18n, loadMessages, type Dict } from "../scripts/shared/i18n";
import {
  analyzeProtocol,
  analyzeSubdomain,
  analyzeUrlLength,
  analyzeSuspiciousKeywords,
  fetchRegistrationDate,
  splitDomain,
  isLookupableDomain,
  isRestrictedPage,
  type AnalyzedRow,
  type RowStatus,
} from "../scripts/shared/url-analysis";
import {
  checkDnsBlacklist,
  checkIpReputation,
  checkPhishingDatabase,
  checkSafeBrowsing,
  checkSucuri,
  checkVirusTotal,
} from "../scripts/shared/reputation-analysis";
import {
  analyzeBrandImpersonation,
  analyzePhishingIndicators,
  analyzeSuspiciousForms,
  analyzeUrgentLanguage,
  extractPageContent,
  highlightPageMatches,
  type HighlightGroup,
  type PageContent,
} from "../scripts/shared/content-analysis";
import {
  analyzeLinks,
  extractPageLinks,
  highlightPageLinks,
  type ClassifiedLink,
  type LinkMark,
  type PageLinks,
} from "../scripts/shared/link-analysis";
import {
  analyzeWithAi,
  type AiVerdict,
  type SocialEngineeringLevel,
} from "../scripts/shared/ai-analysis";
import {
  computeTrustScore,
  type ScoreBand,
  type ScoreFlags,
  type ScoreInput,
  type SiteCategory,
} from "../scripts/shared/score";
import { setActionIcon, type IconBand } from "../scripts/shared/icon";

const MAIN_VIEW = "view-main";

// Status → presentation. The icon span gets a state class; the value text is
// tinted with the matching status colour.
const ICON_CLASS: Record<RowStatus, string> = {
  good: "row__icon ico-good",
  warn: "row__icon ico-warn",
  bad: "row__icon ico-bad",
  unknown: "row__icon ico-unknown",
  neutral: "row__icon",
};
const TONE_CLASS: Record<RowStatus, string> = {
  good: "status--good",
  warn: "status--warning",
  bad: "status--danger",
  unknown: "status--muted",
  neutral: "",
};
const SEVERITY: Record<RowStatus, number> = { neutral: 0, unknown: 0, good: 1, warn: 2, bad: 3 };

// Each category reports its overall verdict (and any tiered score flags) here;
// the header trust score is computed from them. The four heuristic/reputation
// categories scan automatically on open, so they're always expected. AI only
// runs on demand, so it joins `expected` (via expectAiInSiteStatus) only when a
// scan actually starts — auto mode on open or the user pressing Analyze — and
// otherwise the header completes without it.
const BASE_CATEGORIES: SiteCategory[] = ["url", "reputation", "content", "links"];
const expectedCategories = new Set<SiteCategory>(BASE_CATEGORIES);
const siteStatuses: Partial<Record<SiteCategory, RowStatus>> = {};
const siteFlags: Partial<Record<SiteCategory, ScoreFlags>> = {};

// The tab the popup is inspecting, captured in init(). Its toolbar icon is tinted
// to match the trust score (see paintActionIcon).
let activeTabId: number | undefined;
// The band last painted onto the toolbar icon, so the repeated header repaints
// during a scan don't re-issue an identical setIcon.
let paintedIconBand: IconBand | null | undefined;

// Tint the active tab's toolbar icon to match the header verdict: amber for a
// caution score, red for danger, and the packaged green icon for a good score or
// while scanning / when the page can't be scored (band null). Deduped so a scan
// only repaints when the band changes.
function paintActionIcon(band: IconBand | null): void {
  if (typeof activeTabId !== "number" || band === paintedIconBand) return;
  paintedIconBand = band;
  void setActionIcon(activeTabId, band);
}

// Fold the AI scan into the header status: mark it pending and repaint the score
// back to "scanning". Called when an AI analysis is about to run so the header
// waits for its verdict alongside the automatic categories.
function expectAiInSiteStatus(): void {
  delete siteStatuses.ai;
  delete siteFlags.ai;
  expectedCategories.add("ai");
  refreshSiteStatus();
}

// The SVG ring's circumference (r=52), used to turn a 0-100 score into the arc
// length of the filled portion. The band classes recolour the arc per verdict.
const RING_CIRCUMFERENCE = 2 * Math.PI * 52;
const RING_BAND_CLASSES = [
  "score__value--good",
  "score__value--warn",
  "score__value--bad",
  "score__value--muted",
];
const RING_BAND_CLASS: Record<ScoreBand, string> = {
  good: "score__value--good",
  warn: "score__value--warn",
  bad: "score__value--bad",
};

// Paint the score ring: the headline number, the arc fill (0-1), the arc colour
// class, and the verdict word with its tone.
function paintScoreRing(opts: {
  num: string;
  fraction: number;
  ringClass: string;
  verdictText: string;
  verdictTone: string;
}): void {
  const ring = document.querySelector<SVGCircleElement>(".score__value");
  if (ring) {
    ring.classList.remove(...RING_BAND_CLASSES);
    ring.classList.add(opts.ringClass);
    const filled = RING_CIRCUMFERENCE * Math.max(0, Math.min(1, opts.fraction));
    ring.style.strokeDasharray = `${filled.toFixed(1)} ${RING_CIRCUMFERENCE.toFixed(1)}`;
  }
  const num = document.querySelector<HTMLElement>(".score__num");
  if (num) num.textContent = opts.num;
  const verdict = document.querySelector<HTMLElement>(".score__verdict");
  if (verdict) {
    verdict.className = `score__verdict ${opts.verdictTone}`;
    verdict.textContent = opts.verdictText;
  }
}

// The UI language, captured in init(), used to format the scan time in the
// header caption to match the rest of the popup's locale.
let lang: LangPref = "en";

// The current local time as a short "Scanned just now · 14:32" suffix.
function formatScanTime(): string {
  return new Date().toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" });
}

// Repaint the header (score ring + dot + caption) from whatever categories have
// reported so far: a pulsing dot while scanning, then the computed trust score
// and its band colour once every category is in (or a muted "can't scan" state
// when nothing was scannable). The dot shows only during the scan; settled
// states replace it with the time the scan finished.
function refreshSiteStatus(): void {
  const dot = document.getElementById("site-dot");
  const caption = document.getElementById("site-caption");
  // The pulsing dot only marks an in-flight scan; settled states show no dot,
  // just the caption.
  const showScanningDot = (): void => {
    if (dot) {
      dot.className = "dot dot--scanning";
      dot.hidden = false;
    }
  };
  const hideDot = (): void => {
    if (dot) dot.hidden = true;
  };
  const paintCaption = (text: string): void => {
    if (caption) caption.textContent = text;
  };

  const expected = [...expectedCategories];
  const reportedCats = expected.filter((c) => siteStatuses[c] !== undefined);

  // Still scanning until every expected category has reported.
  if (reportedCats.length < expected.length) {
    showScanningDot();
    paintCaption(dict.scanning);
    paintScoreRing({
      num: "…",
      fraction: 0,
      ringClass: "score__value--muted",
      // The caption above the ring already reads "Scanning…", so the ring's
      // verdict word stays blank rather than repeating it inside the dial.
      verdictText: "",
      verdictTone: "status--muted",
    });
    paintActionIcon(null);
    return;
  }

  const inputs: Partial<Record<SiteCategory, ScoreInput>> = {};
  for (const c of reportedCats) inputs[c] = { status: siteStatuses[c]!, flags: siteFlags[c] };
  const trust = computeTrustScore(inputs);

  // Nothing determinate to score (every category came back unknown) — the
  // popup's muted "can't scan this page" state.
  if (!trust) {
    hideDot();
    paintCaption(dict.cantScan);
    paintScoreRing({
      num: "—",
      fraction: 0,
      ringClass: "score__value--muted",
      verdictText: dict.val_unknown,
      verdictTone: "status--muted",
    });
    paintActionIcon(null);
    return;
  }

  const verdictText =
    trust.band === "bad" ? dict.verdict_danger : trust.band === "warn" ? dict.verdict_caution : dict.verdict_safe;
  hideDot();
  paintCaption(`${dict.scannedJustNow} · ${formatScanTime()}`);
  paintScoreRing({
    num: String(trust.score),
    fraction: trust.score / 100,
    ringClass: RING_BAND_CLASS[trust.band],
    verdictText,
    verdictTone: TONE_CLASS[trust.band],
  });
  paintActionIcon(trust.band);
}

// Record one category's overall verdict (and any tiered score flags), then
// repaint the header. Passing no flags clears any flags a prior scan left for
// that category, so a re-run that comes back clean drops its old cap.
function reportSiteStatus(category: SiteCategory, status: RowStatus, flags?: ScoreFlags): void {
  siteStatuses[category] = status;
  if (flags) siteFlags[category] = flags;
  else delete siteFlags[category];
  refreshSiteStatus();
}

// Paint a category's main-list chip as a muted "Loading" while its scan is in
// flight, so the chip never shows a stale or default verdict (e.g. the markup's
// "Good") until the real status lands. The data-target maps to view-<category>.
function setCategoryLoading(category: SiteCategory): void {
  const chip = document.querySelector<HTMLElement>(`.cat[data-target="view-${category}"] .cat__status`);
  if (!chip) return;
  chip.className = "cat__status status--muted";
  chip.textContent = dict.status_loading;
}

function showView(id: string): void {
  for (const view of document.querySelectorAll<HTMLElement>(".view")) {
    view.classList.toggle("is-active", view.id === id);
  }
}

function setupNavigation(): void {
  // Open a detail view when a category row is clicked.
  for (const cat of document.querySelectorAll<HTMLButtonElement>(".cat[data-target]")) {
    cat.addEventListener("click", () => {
      const target = cat.dataset.target;
      if (target) showView(target);
    });
  }

  // Back arrows return to the main view.
  for (const back of document.querySelectorAll<HTMLButtonElement>("[data-back]")) {
    back.addEventListener("click", () => showView(MAIN_VIEW));
  }

  // The gear opens the settings (options) page.
  document
    .getElementById("btn-settings")
    ?.addEventListener("click", () => chrome.runtime.openOptionsPage());
}

async function getActiveTab(): Promise<chrome.tabs.Tab | undefined> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tab ?? undefined;
  } catch {
    // The active tab can't be read (e.g. a privileged page).
    return undefined;
  }
}

function showActiveHost(url: string | undefined): void {
  const host = document.getElementById("site-host");
  if (!host || !url) return;
  try {
    host.textContent = new URL(url).hostname;
  } catch {
    // Keep the placeholder host if the URL can't be parsed.
  }
}

// VirusTotal identifies a URL report by the SHA-256 of the URL string, so the
// GUI page can be linked without an API call.
async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function setupVirusTotal(url: string | undefined): void {
  const btn = document.getElementById("btn-details");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    if (!url) return;
    const id = await sha256Hex(url);
    await chrome.tabs.create({ url: `https://www.virustotal.com/gui/url/${id}` });
  });
}

// ----------------------- API key modal ----------------------- //

// The loaded message dictionary for the user's language, filled by init() before
// any view renders so the synchronous render helpers below can read from it.
let dict: Dict = {};
let modalOnSave: ((key: string) => void | Promise<void>) | null = null;

function closeKeyModal(): void {
  const modal = document.getElementById("key-modal");
  const input = document.getElementById("key-modal-input") as HTMLInputElement | null;
  if (modal) modal.hidden = true;
  if (input) {
    input.value = "";
    input.type = "password";
  }
  modalOnSave = null;
}

function openKeyModal(opts: {
  title: string;
  help: string;
  placeholder: string;
  onSave: (key: string) => void | Promise<void>;
}): void {
  const modal = document.getElementById("key-modal");
  const input = document.getElementById("key-modal-input") as HTMLInputElement | null;
  if (!modal || !input) return;

  const title = document.getElementById("key-modal-title");
  const help = document.getElementById("key-modal-help");
  const toggle = document.getElementById("key-modal-toggle");
  if (title) title.textContent = opts.title;
  if (help) help.textContent = opts.help;
  if (toggle) toggle.textContent = dict.set_show;
  input.placeholder = opts.placeholder;
  input.value = "";
  input.type = "password";
  modalOnSave = opts.onSave;
  modal.hidden = false;
  input.focus();
}

// Wire the modal's static controls once. The save button delegates to whatever
// callback the opener registered.
function setupKeyModal(): void {
  const input = document.getElementById("key-modal-input") as HTMLInputElement | null;
  const toggle = document.getElementById("key-modal-toggle");
  const cancel = document.getElementById("key-modal-cancel");
  const save = document.getElementById("key-modal-save");

  if (toggle && input) {
    toggle.addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
      toggle.textContent = input.type === "text" ? dict.set_hide : dict.set_show;
    });
  }
  if (cancel) cancel.textContent = dict.btn_cancel;
  for (const el of document.querySelectorAll("[data-key-close]")) {
    el.addEventListener("click", closeKeyModal);
  }
  if (save && input) {
    save.textContent = dict.set_save;
    save.addEventListener("click", () => {
      const key = input.value.trim();
      const cb = modalOnSave;
      closeKeyModal();
      if (key && cb) void cb(key);
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const modal = document.getElementById("key-modal");
    if (modal && !modal.hidden) closeKeyModal();
  });
}

// ----------------------- URL & Domain analysis ----------------------- //

const URL_FIELDS = ["protocol", "domainAge", "subdomain", "urlLength", "suspiciousKeywords"] as const;

function resolveText(row: AnalyzedRow, dict: Dict): string {
  if (row.key) return dict[row.key] ?? row.key;
  return row.text ?? "—";
}

// Render the list of specific risky items behind a row (the matched phrases /
// described findings) as chips on a line under it, or clear it when there are
// none. Literal `detail` strings are shown verbatim; `detailKeys` are resolved
// against the dictionary. Chips are tinted with the row's status colour.
function renderRowDetail(li: HTMLElement, row: AnalyzedRow, dict: Dict): void {
  const items = [...(row.detailKeys ?? []).map((k) => dict[k] ?? k), ...(row.detail ?? [])];

  let detail = li.querySelector<HTMLElement>(".row__detail");
  if (items.length === 0) {
    detail?.remove();
    return;
  }
  if (!detail) {
    detail = document.createElement("ul");
    detail.className = "row__detail";
    li.append(detail);
  }
  const tone = TONE_CLASS[row.status];
  detail.replaceChildren(
    ...items.map((item) => {
      const chip = document.createElement("li");
      chip.className = tone ? `row__chip ${tone}` : "row__chip";
      chip.textContent = item;
      return chip;
    }),
  );
}

// Fill one row of a detail view: its value text (optionally tinted), its trailing
// status icon, and the chip list of specific findings underneath (when present).
function renderRow(field: string, row: AnalyzedRow, dict: Dict, colorValue: boolean): void {
  const li = document.querySelector<HTMLElement>(`.row[data-field="${field}"]`);
  if (!li) return;

  const value = li.querySelector<HTMLElement>(".row__value");
  if (value) {
    value.textContent = resolveText(row, dict);
    value.classList.remove("status--good", "status--warning", "status--danger", "status--muted");
    const tone = TONE_CLASS[row.status];
    if (colorValue && tone) value.classList.add(tone);
  }

  const icon = li.querySelector<HTMLElement>(".row__icon");
  if (icon) icon.className = ICON_CLASS[row.status];

  renderRowDetail(li, row, dict);
}

function worst(statuses: RowStatus[]): RowStatus {
  return statuses.reduce<RowStatus>((acc, s) => (SEVERITY[s] > SEVERITY[acc] ? s : acc), "good");
}

// Turn a registration date into a human-readable age plus a risk verdict:
// very young domains are a strong phishing signal.
function formatAge(date: Date, dict: Dict): AnalyzedRow {
  const days = (Date.now() - date.getTime()) / 86_400_000;
  const years = days / 365.25;

  let text: string;
  if (years >= 1) text = `${years.toFixed(1)} ${dict.unit_years}`;
  else if (days >= 60) text = `${Math.round(days / 30)} ${dict.unit_months}`;
  else text = `${Math.max(0, Math.round(days))} ${dict.unit_days}`;

  const status: RowStatus = days < 30 ? "bad" : days < 180 ? "warn" : "good";
  return { text, status };
}

// Set the view's summary verdict + subtitle and the matching chip on the main
// list, all from the overall (worst) status. `flags` carries any strong-heuristic
// signal (raw-IP host, brand-new domain) on to the header trust score.
function setVerdict(status: RowStatus, ageUnknown: boolean, dict: Dict, flags: ScoreFlags = {}): void {
  const tone = TONE_CLASS[status] || "status--good";
  const vKey = status === "bad" ? "status_danger" : status === "warn" ? "status_warning" : "status_good";
  const sKey =
    status === "bad" ? "sum_url_bad" : status === "warn" ? "sum_url_warn" : ageUnknown ? "sum_url_unknown" : "sum_url";

  const verdict = document.getElementById("url-verdict");
  if (verdict) {
    verdict.className = `summary__verdict ${tone}`;
    verdict.textContent = dict[vKey];
  }
  const summary = document.getElementById("url-summary");
  if (summary) summary.textContent = dict[sKey];

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-url"] .cat__status');
  if (chip) {
    chip.className = `cat__status ${tone}`;
    chip.textContent = dict[vKey];
  }

  reportSiteStatus("url", status, flags);
}

function setUnsupported(dict: Dict): void {
  for (const field of URL_FIELDS) renderRow(field, { key: "val_unknown", status: "neutral" }, dict, false);

  const verdict = document.getElementById("url-verdict");
  if (verdict) {
    verdict.className = "summary__verdict status--muted";
    verdict.textContent = dict.val_unknown;
  }
  const summary = document.getElementById("url-summary");
  if (summary) summary.textContent = dict.sum_url_unknown;

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-url"] .cat__status');
  if (chip) {
    chip.className = "cat__status status--muted";
    chip.textContent = dict.val_unknown;
  }

  reportSiteStatus("url", "unknown");
}

async function analyzeUrlView(rawUrl: string | undefined): Promise<void> {
  let url: URL | undefined;
  try {
    if (rawUrl) url = new URL(rawUrl);
  } catch {
    // Leave url undefined; handled below.
  }

  // Privileged pages (chrome://, the new-tab page, etc.) have nothing to scan.
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    setUnsupported(dict);
    return;
  }

  // Synchronous, offline checks.
  const protocol = analyzeProtocol(url);
  const subdomain = analyzeSubdomain(url.hostname);
  const length = analyzeUrlLength(url);
  const keywords = analyzeSuspiciousKeywords(url);

  renderRow("protocol", protocol, dict, true);
  renderRow("subdomain", subdomain, dict, subdomain.status !== "good");
  renderRow("urlLength", length, dict, length.status !== "good");
  renderRow("suspiciousKeywords", keywords, dict, keywords.status !== "good");

  // A raw-IP host is a strong phishing heuristic (analyzeSubdomain only ever
  // returns "bad" for an IP literal), so it caps the header trust score.
  const ipHost = subdomain.status === "bad";

  // Show a provisional verdict immediately, then refine once the domain age
  // (a network lookup) resolves.
  const syncWorst = worst([protocol.status, subdomain.status, length.status, keywords.status]);
  setVerdict(syncWorst, true, dict, { strong: ipHost });

  // Domain age via RDAP. Show a placeholder while the request is in flight.
  renderRow("domainAge", { text: "…", status: "neutral" }, dict, false);

  let ageStatus: RowStatus = "neutral";
  let ageUnknown = true;
  if (isLookupableDomain(url.hostname)) {
    const date = await fetchRegistrationDate(splitDomain(url.hostname).registrable);
    if (date) {
      const age = formatAge(date, dict);
      renderRow("domainAge", age, dict, age.status !== "good");
      ageStatus = age.status;
      ageUnknown = false;
    } else {
      renderRow("domainAge", { key: "val_unknown", status: "unknown" }, dict, true);
    }
  } else {
    renderRow("domainAge", { key: "val_unknown", status: "neutral" }, dict, false);
  }

  // A brand-new domain (< 30 days, "bad") is the other strong URL heuristic.
  setVerdict(
    worst([protocol.status, subdomain.status, length.status, keywords.status, ageStatus]),
    ageUnknown,
    dict,
    { strong: ipHost || ageStatus === "bad" },
  );
}

// ----------------------- Reputation analysis ----------------------- //

const REPUTATION_FIELDS = [
  "safeBrowsing",
  "virusTotal",
  "sucuri",
  "phishingDb",
  "blacklist",
  "ipReputation",
] as const;

// The category's verdict from its rows: the worst *determinate* finding, or
// "unknown" when nothing could be checked (no keys + DNS lookups all failed).
function reputationOverall(statuses: RowStatus[]): RowStatus {
  const determinate = statuses.filter((s) => s === "good" || s === "warn" || s === "bad");
  return determinate.length ? worst(determinate) : "unknown";
}

// Set the Reputation view's summary verdict + subtitle and the matching chip on
// the main list, all from the overall status.
function setReputationVerdict(status: RowStatus, dict: Dict): void {
  const tone = status === "unknown" ? "status--muted" : TONE_CLASS[status] || "status--good";
  const vKey =
    status === "bad"
      ? "status_danger"
      : status === "warn"
        ? "status_warning"
        : status === "unknown"
          ? "val_unknown"
          : "status_good";
  const sKey =
    status === "bad"
      ? "sum_reputation_bad"
      : status === "warn"
        ? "sum_reputation_warn"
        : status === "unknown"
          ? "sum_reputation_unknown"
          : "sum_reputation";

  const verdict = document.getElementById("rep-verdict");
  if (verdict) {
    verdict.className = `summary__verdict ${tone}`;
    verdict.textContent = dict[vKey];
  }
  const summary = document.getElementById("rep-summary");
  if (summary) summary.textContent = dict[sKey];

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-reputation"] .cat__status');
  if (chip) {
    chip.className = `cat__status ${tone}`;
    chip.textContent = dict[vKey];
  }

  // A "bad" reputation only ever comes from an authoritative blocklist/malware
  // hit (Safe Browsing, VirusTotal malicious, Sucuri, Phishing Database, a DNS
  // sinkhole) — the soft signals top out at "warn" — so it's a definitive cap.
  reportSiteStatus("reputation", status, { definitive: status === "bad" });
}

// Last computed status of each reputation row, plus the page context — kept so a
// single row (e.g. VirusTotal after a key is added) can be re-run and the overall
// verdict recomputed without re-doing every lookup.
const repStatuses: Partial<Record<(typeof REPUTATION_FIELDS)[number], RowStatus>> = {};
let repContext: { host: string; settings: Settings } | null = null;

function repVerdict(dict: Dict): void {
  const statuses = Object.values(repStatuses).filter((s): s is RowStatus => s !== undefined);
  setReputationVerdict(reputationOverall(statuses), dict);
}

// Render a row that can't run until the user supplies an API key: a "Key needed"
// note plus an "Add key" button that opens the key modal.
function renderKeyNeeded(field: string, dict: Dict, onAdd: () => void): void {
  const li = document.querySelector<HTMLElement>(`.row[data-field="${field}"]`);
  if (!li) return;

  const icon = li.querySelector<HTMLElement>(".row__icon");
  if (icon) icon.className = ICON_CLASS.unknown;

  const value = li.querySelector<HTMLElement>(".row__value");
  if (!value) return;
  value.className = "row__value status--warning";
  value.textContent = "";

  const label = document.createElement("span");
  label.textContent = dict.val_keyNeeded;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "row__keybtn";
  btn.textContent = dict.btn_addKey;
  btn.addEventListener("click", onAdd);
  value.append(label, " ", btn);
}

// Prompt for the VirusTotal key, then persist it and re-run just that row.
function openVirusTotalKeyModal(): void {
  if (!repContext) return;
  const { host, settings } = repContext;

  openKeyModal({
    title: dict.set_virustotal_apikey,
    help: dict.set_virustotal_apikey_help,
    placeholder: dict.set_virustotal_apikey_placeholder,
    onSave: async (key) => {
      settings.virusTotalApiKey = key;
      await saveSettings(settings);
      renderRow("virusTotal", { text: "…", status: "neutral" }, dict, false);
      const vt = await checkVirusTotal(host, key);
      renderRow("virusTotal", vt, dict, true);
      repStatuses.virusTotal = vt.status;
      repVerdict(dict);
    },
  });
}

async function analyzeReputationView(rawUrl: string | undefined, settings: Settings): Promise<void> {
  let url: URL | undefined;
  try {
    if (rawUrl) url = new URL(rawUrl);
  } catch {
    // Leave url undefined; handled below.
  }

  // Privileged pages (chrome://, the new-tab page, etc.) have nothing to check.
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    repContext = null;
    for (const field of REPUTATION_FIELDS) renderRow(field, { key: "val_unknown", status: "neutral" }, dict, false);
    setReputationVerdict("unknown", dict);
    return;
  }

  repContext = { host: url.hostname, settings };

  // Show placeholders while the lookups (all network) are in flight.
  for (const field of REPUTATION_FIELDS) renderRow(field, { text: "…", status: "neutral" }, dict, false);

  // VirusTotal needs a key; without one show a "Key needed" prompt instead.
  const hasVtKey = Boolean(settings.virusTotalApiKey);
  const [safeBrowsing, virusTotal, sucuri, phishingDb, blacklist, ipReputation] = await Promise.all([
    checkSafeBrowsing(url.href, url.hostname, settings.safeBrowsingApiKey),
    hasVtKey
      ? checkVirusTotal(url.hostname, settings.virusTotalApiKey)
      : Promise.resolve<AnalyzedRow>({ status: "unknown" }),
    checkSucuri(url.hostname),
    checkPhishingDatabase(url.hostname),
    checkDnsBlacklist(url.hostname),
    checkIpReputation(url.hostname),
  ]);

  renderRow("safeBrowsing", safeBrowsing, dict, true);
  if (hasVtKey) renderRow("virusTotal", virusTotal, dict, true);
  else renderKeyNeeded("virusTotal", dict, openVirusTotalKeyModal);
  renderRow("sucuri", sucuri, dict, true);
  renderRow("phishingDb", phishingDb, dict, true);
  renderRow("blacklist", blacklist, dict, true);
  renderRow("ipReputation", ipReputation, dict, true);

  repStatuses.safeBrowsing = safeBrowsing.status;
  repStatuses.virusTotal = virusTotal.status;
  repStatuses.sucuri = sucuri.status;
  repStatuses.phishingDb = phishingDb.status;
  repStatuses.blacklist = blacklist.status;
  repStatuses.ipReputation = ipReputation.status;
  repVerdict(dict);
}

// ----------------------- Content analysis ----------------------- //

const CONTENT_FIELDS = [
  "phishingIndicators",
  "suspiciousForms",
  "urgentLanguage",
  "brandImpersonation",
] as const;

// Set the Content view's summary verdict + subtitle and the matching chip on the
// main list, all from the overall (worst) status. `flags` carries a cleartext
// credential form (definitive) or brand impersonation / heavy phishing wording
// (strong) on to the header trust score. `restricted` swaps the unknown wording
// for the explicit "Chrome blocks extensions on this page" note.
function setContentVerdict(status: RowStatus, dict: Dict, flags: ScoreFlags = {}, restricted = false): void {
  const tone = status === "unknown" ? "status--muted" : TONE_CLASS[status] || "status--good";
  const vKey = restricted
    ? "val_restricted"
    : status === "bad"
      ? "status_danger"
      : status === "warn"
        ? "status_warning"
        : status === "unknown"
          ? "val_unknown"
          : "status_good";
  const sKey = restricted
    ? "sum_restricted"
    : status === "bad"
      ? "sum_content_bad"
      : status === "warn"
        ? "sum_content_warn"
        : status === "unknown"
          ? "sum_content_unknown"
          : "sum_content";

  const verdict = document.getElementById("content-verdict");
  if (verdict) {
    verdict.className = `summary__verdict ${tone}`;
    verdict.textContent = dict[vKey];
  }
  const summary = document.getElementById("content-summary");
  if (summary) summary.textContent = dict[sKey];

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-content"] .cat__status');
  if (chip) {
    chip.className = `cat__status ${tone}`;
    chip.textContent = dict[vKey];
  }

  reportSiteStatus("content", status, flags);
}

// Inject the self-contained extractor into the active tab and read back its
// page summary. Returns null on any failure (privileged page, no host access).
async function getPageContent(tabId: number): Promise<PageContent | null> {
  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      func: extractPageContent,
    });
    return (injection?.result as PageContent | undefined) ?? null;
  } catch {
    return null;
  }
}

// Mark the flagged phrases (and, when enabled, outline leaky password forms) on
// the page itself, each labelled with its category for the in-page hover tooltip.
// Runs in the MAIN world so the highlighter shares the page's CSS highlight
// registry. Passing empty groups with outlineForms=false clears any marks from a
// prior scan.
async function markPageMatches(
  tabId: number,
  groups: HighlightGroup[],
  formLabel: string,
  outlineForms: boolean,
): Promise<void> {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: highlightPageMatches,
      args: [groups, formLabel, outlineForms],
    });
  } catch {
    // Page isn't scriptable (privileged page, no host access) — nothing to mark.
  }
}

async function analyzeContentView(tab: chrome.tabs.Tab | undefined, settings: Settings): Promise<void> {
  let url: URL | undefined;
  try {
    if (tab?.url) url = new URL(tab.url);
  } catch {
    // Leave url undefined; handled below.
  }

  // Privileged pages (chrome://, the new-tab page, etc.) have no DOM to scan.
  if (!tab?.id || !url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    for (const field of CONTENT_FIELDS) renderRow(field, { key: "val_unknown", status: "neutral" }, dict, false);
    setContentVerdict("unknown", dict);
    return;
  }

  // Chrome forbids extensions from scripting its extension store, so the
  // extractor can never run there. Say so explicitly instead of leaving the
  // generic Unknown a transient failure gets.
  if (isRestrictedPage(url)) {
    for (const field of CONTENT_FIELDS) renderRow(field, { key: "val_unknown", status: "unknown" }, dict, true);
    setContentVerdict("unknown", dict, {}, true);
    return;
  }

  // Show placeholders while the page is being read.
  for (const field of CONTENT_FIELDS) renderRow(field, { text: "…", status: "neutral" }, dict, false);

  const page = await getPageContent(tab.id);
  if (!page) {
    for (const field of CONTENT_FIELDS) renderRow(field, { key: "val_unknown", status: "unknown" }, dict, true);
    setContentVerdict("unknown", dict);
    return;
  }

  const phishing = analyzePhishingIndicators(page);
  const forms = analyzeSuspiciousForms(page);
  const urgent = analyzeUrgentLanguage(page);
  const brand = analyzeBrandImpersonation(page, url.hostname);

  renderRow("phishingIndicators", phishing, dict, phishing.status !== "good");
  renderRow("suspiciousForms", forms, dict, forms.status !== "good");
  renderRow("urgentLanguage", urgent, dict, urgent.status !== "good");
  renderRow("brandImpersonation", brand, dict, brand.status !== "good");

  // A cleartext credential form ("bad" from a leaking password form) is a
  // confirmed-malicious cap; brand impersonation or 3+ phishing phrases are
  // strong heuristics. Cross-origin-only forms and urgent wording stay soft, so
  // they only nudge the averaged score rather than capping it.
  setContentVerdict(worst([phishing.status, forms.status, urgent.status, brand.status]), dict, {
    definitive: forms.status === "bad",
    strong: brand.status === "bad" || phishing.status === "bad",
  });

  // Mark those same matches on the page, each tagged with its category so the
  // in-page hover tooltip can name it, but only for the categories the user left
  // enabled (a disabled one crosses over with no phrases, so it isn't marked).
  // The form outlines are re-detected in the page, so only the matched phrases
  // need to cross over.
  const hl = settings.highlights;
  const groups: HighlightGroup[] = [
    { label: dict.lbl_phishingIndicators, phrases: hl.phishingIndicators ? phishing.detail ?? [] : [] },
    { label: dict.lbl_urgentLanguage, phrases: hl.urgentLanguage ? urgent.detail ?? [] : [] },
    { label: dict.lbl_brandImpersonation, phrases: hl.brandImpersonation ? brand.detail ?? [] : [] },
  ];
  void markPageMatches(tab.id, groups, dict.lbl_suspiciousForms, hl.suspiciousForms);
}

// ----------------------- Links analysis ----------------------- //

const LINK_FIELDS = ["totalLinks", "externalLinks", "suspiciousLinks", "maliciousRedirects"] as const;

// Set the Links view's summary verdict + subtitle and the matching chip on the
// main list, all from the overall (worst) status. `restricted` swaps the unknown
// wording for the explicit "Chrome blocks extensions on this page" note.
function setLinksVerdict(status: RowStatus, dict: Dict, restricted = false): void {
  const tone = status === "unknown" ? "status--muted" : TONE_CLASS[status] || "status--good";
  const vKey = restricted
    ? "val_restricted"
    : status === "bad"
      ? "status_danger"
      : status === "warn"
        ? "status_warning"
        : status === "unknown"
          ? "val_unknown"
          : "status_good";
  const sKey = restricted
    ? "sum_restricted"
    : status === "bad"
      ? "sum_links_bad"
      : status === "warn"
        ? "sum_links_warn"
        : status === "unknown"
          ? "sum_links_unknown"
          : "sum_links";

  const verdict = document.getElementById("links-verdict");
  if (verdict) {
    verdict.className = `summary__verdict ${tone}`;
    verdict.textContent = dict[vKey];
  }
  const summary = document.getElementById("links-summary");
  if (summary) summary.textContent = dict[sKey];

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-links"] .cat__status');
  if (chip) {
    chip.className = `cat__status ${tone}`;
    chip.textContent = dict[vKey];
  }

  reportSiteStatus("links", status);
}

// Inject the self-contained link extractor into the active tab and read back its
// summary. Returns null on any failure (privileged page, no host access).
async function getPageLinks(tabId: number): Promise<PageLinks | null> {
  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      func: extractPageLinks,
    });
    return (injection?.result as PageLinks | undefined) ?? null;
  } catch {
    return null;
  }
}

// Outline the classified links on the page itself, each carrying its hover label.
// Passing all-"skip" marks clears any marks from a prior scan.
async function markPageLinks(tabId: number, marks: LinkMark[]): Promise<void> {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: highlightPageLinks,
      args: [marks],
    });
  } catch {
    // Page isn't scriptable (privileged page, no host access), nothing to mark.
  }
}

// The hover label for a flagged link: the bucket name plus its specific reason.
function linkTitle(link: ClassifiedLink, dict: Dict): string {
  if (link.verdict === "internal") return dict.tip_link_internal;
  if (link.verdict === "external") return dict.tip_link_external;
  const head = link.verdict === "redirect" ? dict.tip_link_redirect : dict.tip_link_suspicious;
  const reason = link.reasonKey ? dict[link.reasonKey] : undefined;
  return reason ? `${head}: ${reason}` : head;
}

// The confirmation shown when the user clicks a red link on the page: the bucket
// name and reason (the same wording as the hover label), the destination host,
// and a continue prompt. Only the two risky buckets get one; safe links navigate
// without interruption.
function linkWarning(link: ClassifiedLink, dict: Dict): string | undefined {
  if (link.verdict !== "suspicious" && link.verdict !== "redirect") return undefined;
  const dest = link.host ? `${dict.warn_link_destination}: ${link.host}\n\n` : "";
  return `${dict.warn_link_heading}\n\n${linkTitle(link, dict)}\n\n${dest}${dict.warn_link_continue}`;
}

// The blocked notice shown instead when the guard action is "block": the same
// heading, reason, and destination, but a "website is blocked" line in place of
// the continue prompt, since a blocked click cannot be continued.
function linkBlockNotice(link: ClassifiedLink, dict: Dict): string | undefined {
  if (link.verdict !== "suspicious" && link.verdict !== "redirect") return undefined;
  const dest = link.host ? `${dict.warn_link_destination}: ${link.host}\n\n` : "";
  return `${dict.warn_link_heading}\n\n${linkTitle(link, dict)}\n\n${dest}${dict.block_link_notice}`;
}

async function analyzeLinksView(tab: chrome.tabs.Tab | undefined, settings: Settings): Promise<void> {
  let url: URL | undefined;
  try {
    if (tab?.url) url = new URL(tab.url);
  } catch {
    // Leave url undefined; handled below.
  }

  // Privileged pages (chrome://, the new-tab page, etc.) have no DOM to scan.
  if (!tab?.id || !url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    for (const field of LINK_FIELDS) renderRow(field, { key: "val_unknown", status: "neutral" }, dict, false);
    setLinksVerdict("unknown", dict);
    return;
  }

  // Chrome forbids extensions from scripting its extension store, so the
  // extractor can never run there. Say so explicitly instead of leaving the
  // generic Unknown a transient failure gets.
  if (isRestrictedPage(url)) {
    for (const field of LINK_FIELDS) renderRow(field, { key: "val_unknown", status: "unknown" }, dict, true);
    setLinksVerdict("unknown", dict, true);
    return;
  }

  // Show placeholders while the page is being read.
  for (const field of LINK_FIELDS) renderRow(field, { text: "…", status: "neutral" }, dict, false);

  const page = await getPageLinks(tab.id);
  if (!page) {
    for (const field of LINK_FIELDS) renderRow(field, { key: "val_unknown", status: "unknown" }, dict, true);
    setLinksVerdict("unknown", dict);
    return;
  }

  const { classified, total, external, suspicious, redirects } = analyzeLinks(page);

  renderRow("totalLinks", total, dict, false);
  renderRow("externalLinks", external, dict, false);
  renderRow("suspiciousLinks", suspicious, dict, suspicious.status !== "good");
  renderRow("maliciousRedirects", redirects, dict, redirects.status !== "good");

  setLinksVerdict(worst([total.status, external.status, suspicious.status, redirects.status]), dict);

  // Mark the same links on the page (greens and blues included), each tagged
  // with its hover label. marks line up with the page's anchors by document
  // order; the "ignore" bucket and any verdict the user disabled stay unmarked.
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
  // navigates untouched.
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
  void markPageLinks(tab.id, marks);
}

// ----------------------- AI analysis ----------------------- //

const AI_FIELDS = ["phishingProbability", "socialEngineering", "contentRiskScore"] as const;

// Map a model 0–100 risk score to a row status, using the same warn/bad cutoffs
// the other categories use for their thirds.
function scoreStatus(n: number): RowStatus {
  return n >= 67 ? "bad" : n >= 34 ? "warn" : "good";
}

function levelStatus(level: SocialEngineeringLevel): RowStatus {
  return level === "high" ? "bad" : level === "medium" ? "warn" : "good";
}

const LEVEL_KEY: Record<SocialEngineeringLevel, string> = {
  low: "val_low",
  medium: "val_medium",
  high: "val_high",
};

// Set the AI view's summary verdict + subtitle and the main-list chip, all from a
// tone class and the verdict/subtitle keys to show.
function setAiSummary(tone: string, vKey: string, sKey: string, dict: Dict): void {
  const verdict = document.getElementById("ai-verdict");
  if (verdict) {
    verdict.className = `summary__verdict ${tone}`;
    verdict.textContent = dict[vKey];
  }
  const summary = document.getElementById("ai-summary");
  if (summary) summary.textContent = dict[sKey];

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-ai"] .cat__status');
  if (chip) {
    chip.className = `cat__status ${tone}`;
    chip.textContent = dict[vKey];
  }
}

// A scannable page is an http(s) tab we can inject into; privileged pages
// (chrome://, the new-tab page, …) aren't.
function aiScannable(
  tab: chrome.tabs.Tab | undefined,
): tab is chrome.tabs.Tab & { id: number; url: string } {
  if (!tab?.id || !tab.url) return false;
  try {
    const u = new URL(tab.url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// Render a finished verdict into the three rows + summary + note.
function renderAiVerdict(verdict: AiVerdict): void {
  const pStatus = scoreStatus(verdict.phishingProbability);
  const sStatus = levelStatus(verdict.socialEngineering);
  const cStatus = scoreStatus(verdict.contentRiskScore);

  renderRow("phishingProbability", { text: `${verdict.phishingProbability}%`, status: pStatus }, dict, true);
  renderRow("socialEngineering", { key: LEVEL_KEY[verdict.socialEngineering], status: sStatus }, dict, true);
  renderRow("contentRiskScore", { text: `${verdict.contentRiskScore} / 100`, status: cStatus }, dict, true);

  const overall = worst([pStatus, sStatus, cStatus]);
  const tone = TONE_CLASS[overall] || "status--good";
  const vKey = overall === "bad" ? "status_danger" : overall === "warn" ? "status_warning" : "status_good";
  const sKey = overall === "bad" ? "sum_ai_bad" : overall === "warn" ? "sum_ai_warn" : "sum_ai";
  setAiSummary(tone, vKey, sKey, dict);

  const note = document.getElementById("ai-note-body");
  if (note) note.textContent = verdict.summary || dict[sKey];

  // The model rating the page high-risk is a strong heuristic (it caps the score
  // at the warning band) but not a definitive blocklist hit.
  reportSiteStatus("ai", overall, { strong: overall === "bad" });
}

// Run the analysis with the chosen provider's key. Shows progress, then renders
// the verdict or an error. Re-entrant: the key modal's save handler calls back
// in once a key is supplied.
async function runAiAnalysis(
  tab: chrome.tabs.Tab & { id: number; url: string },
  settings: Settings,
): Promise<void> {
  const provider = settings.aiProvider;
  const key = provider === "deepseek" ? settings.deepseekApiKey : settings.apiKey;
  const model = provider === "deepseek" ? settings.deepseekModel : settings.claudeModel;

  const button = document.getElementById("ai-analyze") as HTMLButtonElement | null;
  const note = document.getElementById("ai-note-body");

  // No key for the chosen provider — prompt for it inline, then continue.
  if (!key) {
    openAiKeyModal(provider, tab, settings);
    return;
  }

  // The scan is now actually going to run, so the header status should wait for
  // and reflect its verdict too.
  expectAiInSiteStatus();

  // Progress state: disable the button, blank the rows, swap the subtitle, and
  // show the main-list chip as "Loading" instead of its prior verdict.
  if (button) {
    button.disabled = true;
    button.textContent = dict.ai_analyzing;
  }
  setCategoryLoading("ai");
  for (const field of AI_FIELDS) renderRow(field, { text: "…", status: "neutral" }, dict, false);
  const summaryEl = document.getElementById("ai-summary");
  if (summaryEl) summaryEl.textContent = dict.ai_analyzing;

  const page = await getPageContent(tab.id);

  const finish = (): void => {
    if (button) {
      button.disabled = false;
      button.textContent = dict.btn_reanalyze;
    }
  };

  // Page became unscriptable between popup open and the click.
  if (!page) {
    for (const field of AI_FIELDS) renderRow(field, { key: "val_unknown", status: "unknown" }, dict, true);
    setAiSummary("status--muted", "val_unknown", "sum_ai_unknown", dict);
    if (note) note.textContent = dict.sum_ai_unknown;
    reportSiteStatus("ai", "unknown");
    finish();
    return;
  }

  const result = await analyzeWithAi(provider, key, model, {
    url: tab.url,
    host: new URL(tab.url).hostname,
    page,
  });
  finish();

  if (!result.ok) {
    for (const field of AI_FIELDS) renderRow(field, { key: "val_unknown", status: "unknown" }, dict, true);
    setAiSummary("status--muted", "val_unknown", "sum_ai_error", dict);
    if (note) note.textContent = dict[result.error] ?? dict.sum_ai_error;
    reportSiteStatus("ai", "unknown");
    return;
  }

  renderAiVerdict(result.verdict);
}

// Prompt for the chosen provider's API key (reusing the shared modal), persist
// it, then run the analysis.
function openAiKeyModal(
  provider: AiProvider,
  tab: chrome.tabs.Tab & { id: number; url: string },
  settings: Settings,
): void {
  const isClaude = provider === "claude";
  openKeyModal({
    title: isClaude ? dict.set_apikey : dict.set_deepseek_apikey,
    help: isClaude ? dict.set_apikey_help : dict.set_deepseek_apikey_help,
    placeholder: isClaude ? dict.set_apikey_placeholder : dict.set_deepseek_apikey_placeholder,
    onSave: async (value) => {
      if (isClaude) settings.apiKey = value;
      else settings.deepseekApiKey = value;
      await saveSettings(settings);
      await runAiAnalysis(tab, settings);
    },
  });
}

// Bind the AI view's persistent controls once: the provider selector and the
// on-demand Analyze button. Kept separate from scanAiView so a rescan re-renders
// the view without stacking a second listener on each control. Binding alone
// never calls the API, so opening the popup never bills the user.
function setupAiView(tab: chrome.tabs.Tab | undefined, settings: Settings): void {
  const select = document.getElementById("ai-provider") as HTMLSelectElement | null;
  if (select) {
    select.value = settings.aiProvider;
    select.addEventListener("change", async () => {
      settings.aiProvider = select.value as AiProvider;
      await saveSettings(settings);
    });
  }

  // The Analyze button only makes sense on a scannable page; on privileged and
  // store pages scanAiView leaves it disabled, so there's nothing to run.
  if (!aiScannable(tab) || isRestrictedPage(tab.url)) return;
  const button = document.getElementById("ai-analyze") as HTMLButtonElement | null;
  button?.addEventListener("click", () => void runAiAnalysis(tab, settings));
}

// Render the AI view's pre-scan state and, when the user opted to scan on open,
// kick the analysis off. Called on initial open and on every rescan, so it owns
// only render/run state, never listener binding.
function scanAiView(tab: chrome.tabs.Tab | undefined, settings: Settings): void {
  const button = document.getElementById("ai-analyze") as HTMLButtonElement | null;
  const note = document.getElementById("ai-note-body");

  // Privileged pages can't be scanned, and neither can the browser's extension
  // store, which Chrome forbids extensions from scripting. Both get a muted,
  // disabled state; the store names the reason instead of the generic unknown.
  const restricted = isRestrictedPage(tab?.url);
  if (!aiScannable(tab) || restricted) {
    for (const field of AI_FIELDS) renderRow(field, { key: "val_unknown", status: "neutral" }, dict, false);
    setAiSummary(
      "status--muted",
      restricted ? "val_restricted" : "val_unknown",
      restricted ? "sum_restricted" : "sum_ai_unknown",
      dict,
    );
    if (note) note.textContent = restricted ? dict.sum_restricted : dict.sum_ai_unknown;
    if (button) {
      button.disabled = true;
      button.textContent = dict.btn_analyze;
    }
    return;
  }

  // Idle, ready-to-run state.
  for (const field of AI_FIELDS) renderRow(field, { text: "—", status: "neutral" }, dict, false);
  setAiSummary("status--muted", "ai_idle", "sum_ai_idle", dict);
  if (note) note.textContent = dict.ai_note_idle;
  if (button) {
    button.disabled = false;
    button.textContent = dict.btn_analyze;
  }

  // When the user chose to scan on open, run it now — but only if a key for the
  // chosen provider is already set, so a (re)scan never pops the key modal
  // unprompted. Without a key it stays idle until the user clicks Analyze.
  if (settings.aiScanMode === "auto") {
    const key = settings.aiProvider === "deepseek" ? settings.deepseekApiKey : settings.apiKey;
    if (key) void runAiAnalysis(tab, settings);
  }
}

// Run every category's scan from a clean slate: the four automatic checks plus,
// when configured, the on-demand AI scan. Used for the initial open and again
// each time the user presses Rescan.
function runAllScans(tab: chrome.tabs.Tab | undefined, settings: Settings): void {
  // Reset the header accumulator so the dot returns to "scanning" and recomputes
  // from scratch, and stop expecting AI until a scan actually starts again.
  for (const category of Object.keys(siteStatuses) as SiteCategory[]) delete siteStatuses[category];
  expectedCategories.clear();
  for (const category of BASE_CATEGORIES) expectedCategories.add(category);
  refreshSiteStatus();

  // Show each automatic category as "Loading" until its scan reports a verdict.
  for (const category of BASE_CATEGORIES) setCategoryLoading(category);

  const url = tab?.url ?? undefined;
  void analyzeUrlView(url);
  void analyzeReputationView(url, settings);
  void analyzeContentView(tab, settings);
  void analyzeLinksView(tab, settings);
  scanAiView(tab, settings);
}

// Wire the footer's Rescan button to re-run every category against the same tab.
function setupRescan(tab: chrome.tabs.Tab | undefined, settings: Settings): void {
  document
    .getElementById("btn-rescan")
    ?.addEventListener("click", () => runAllScans(tab, settings));
}

async function init(): Promise<void> {
  const settings = await loadSettings();
  lang = settings.lang;
  dict = await loadMessages(settings.lang);
  applyTheme(settings.theme);
  applyI18n(settings.lang, dict);
  setupNavigation();
  setupKeyModal();
  const tab = await getActiveTab();
  activeTabId = tab?.id;
  const url = tab?.url ?? undefined;
  showActiveHost(url);
  setupVirusTotal(url);
  setupAiView(tab, settings);
  setupRescan(tab, settings);
  runAllScans(tab, settings);
}

void init();
