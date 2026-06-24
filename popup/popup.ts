// Popup entry point. Compiled to popup.js by esbuild and loaded from popup.html.
// Applies the user's theme/language, then handles view navigation.

import { loadSettings, saveSettings, type LangPref, type Settings } from "../scripts/shared/settings";
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
import {
  checkDnsBlacklist,
  checkIpReputation,
  checkPhishingDatabase,
  checkSafeBrowsing,
  checkSucuri,
  checkVirusTotal,
} from "../scripts/shared/reputation-analysis";

const MAIN_VIEW = "view-main";

type Dict = Record<string, string>;

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

// ----------------------- API key modal ----------------------- //

let currentLang: LangPref = "en";
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
  if (toggle) toggle.textContent = messages[currentLang].set_show;
  input.placeholder = opts.placeholder;
  input.value = "";
  input.type = "password";
  modalOnSave = opts.onSave;
  modal.hidden = false;
  input.focus();
}

// Wire the modal's static controls once. The save button delegates to whatever
// callback the opener registered.
function setupKeyModal(lang: LangPref): void {
  const dict = messages[lang];
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
    value.classList.remove("status--good", "status--warning", "status--danger", "status--muted");
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
      renderRow("domainAge", { key: "val_unknown", status: "unknown" }, dict, true);
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
  const dict = messages[settings.lang];

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
  const dict = messages[settings.lang];

  let url: URL | undefined;
  try {
    if (rawUrl) url = new URL(rawUrl);
  } catch {
    // Leave url undefined; handled below.
  }

  // Privileged pages (chrome://, the new-tab page, etc.) have nothing to check.
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    repContext = null;
    for (const field of REPUTATION_FIELDS) renderRow(field, { text: "—", status: "neutral" }, dict, false);
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

async function init(): Promise<void> {
  const settings = await loadSettings();
  currentLang = settings.lang;
  applyTheme(settings.theme);
  applyI18n(settings.lang);
  setupNavigation();
  setupKeyModal(settings.lang);
  const url = await getActiveTabUrl();
  showActiveHost(url);
  setupVirusTotal(url);
  void analyzeUrlView(url, settings.lang);
  void analyzeReputationView(url, settings);
}

void init();
