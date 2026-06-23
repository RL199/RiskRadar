// Popup entry point. Compiled to popup.js by esbuild and loaded from popup.html.
// Applies the user's theme/language, then handles view navigation.

import { loadSettings, type LangPref } from "../scripts/shared/settings";
import { applyTheme } from "../scripts/shared/theme";
import { applyI18n, messages } from "../scripts/shared/i18n";
import {
  analyzeProtocol,
  analyzeSubdomain,
  analyzeUrlLength,
  analyzeSuspiciousKeywords,
  fetchRegistrationDate,
  splitDomain,
  isLookupableDomain,
  type AnalyzedRow,
  type RowStatus,
} from "../scripts/shared/url-analysis";

const MAIN_VIEW = "view-main";

type Dict = Record<string, string>;

// Status → presentation. The icon span gets a state class; the value text is
// tinted with the matching status colour.
const ICON_CLASS: Record<RowStatus, string> = {
  good: "row__icon ico-good",
  warn: "row__icon ico-warn",
  bad: "row__icon ico-bad",
  neutral: "row__icon",
};
const TONE_CLASS: Record<RowStatus, string> = {
  good: "status--good",
  warn: "status--warning",
  bad: "status--danger",
  neutral: "",
};
const SEVERITY: Record<RowStatus, number> = { neutral: 0, good: 1, warn: 2, bad: 3 };

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

async function getActiveTabUrl(): Promise<string | undefined> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tab?.url ?? undefined;
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

// ----------------------- URL & Domain analysis ----------------------- //

function resolveText(row: AnalyzedRow, dict: Dict): string {
  if (row.key) return dict[row.key] ?? row.key;
  return row.text ?? "—";
}

// Fill one row of the URL view: its value text (optionally tinted) and its
// trailing status icon.
function renderRow(field: string, row: AnalyzedRow, dict: Dict, colorValue: boolean): void {
  const li = document.querySelector<HTMLElement>(`.row[data-field="${field}"]`);
  if (!li) return;

  const value = li.querySelector<HTMLElement>(".row__value");
  if (value) {
    value.textContent = resolveText(row, dict);
    value.classList.remove("status--good", "status--warning", "status--danger");
    const tone = TONE_CLASS[row.status];
    if (colorValue && tone) value.classList.add(tone);
  }

  const icon = li.querySelector<HTMLElement>(".row__icon");
  if (icon) icon.className = ICON_CLASS[row.status];
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
// list, all from the overall (worst) status.
function setVerdict(status: RowStatus, ageUnknown: boolean, dict: Dict): void {
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
}

function setUnsupported(dict: Dict): void {
  const verdict = document.getElementById("url-verdict");
  if (verdict) {
    verdict.className = "summary__verdict";
    verdict.textContent = "—";
  }
  const summary = document.getElementById("url-summary");
  if (summary) summary.textContent = dict.sum_url_unknown;

  const chip = document.querySelector<HTMLElement>('.cat[data-target="view-url"] .cat__status');
  if (chip) {
    chip.className = "cat__status";
    chip.textContent = "—";
  }
}

async function analyzeUrlView(rawUrl: string | undefined, lang: LangPref): Promise<void> {
  const dict = messages[lang];

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

  // Show a provisional verdict immediately, then refine once the domain age
  // (a network lookup) resolves.
  const syncWorst = worst([protocol.status, subdomain.status, length.status, keywords.status]);
  setVerdict(syncWorst, true, dict);

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
      renderRow("domainAge", { key: "val_unknown", status: "neutral" }, dict, false);
    }
  } else {
    renderRow("domainAge", { key: "val_unknown", status: "neutral" }, dict, false);
  }

  setVerdict(
    worst([protocol.status, subdomain.status, length.status, keywords.status, ageStatus]),
    ageUnknown,
    dict,
  );
}

async function init(): Promise<void> {
  const settings = await loadSettings();
  applyTheme(settings.theme);
  applyI18n(settings.lang);
  setupNavigation();
  const url = await getActiveTabUrl();
  showActiveHost(url);
  setupVirusTotal(url);
  void analyzeUrlView(url, settings.lang);
}

void init();
