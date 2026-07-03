// Options page logic: load settings into the controls, persist changes, and
// apply theme/language live (including to this page itself).

import {
  loadSettings,
  saveSettings,
  type AiScanMode,
  type HighlightSettings,
  type LangPref,
  type Settings,
  type ThemePref,
} from "../scripts/shared/settings";
import { applyTheme } from "../scripts/shared/theme";
import { applyI18n, loadMessages, type Dict } from "../scripts/shared/i18n";
import {
  CLAUDE_MODELS,
  DEEPSEEK_MODELS,
  type AiModelOption,
} from "../scripts/shared/ai-analysis";

const themeSelect = document.getElementById("theme") as HTMLSelectElement;
const langSelect = document.getElementById("lang") as HTMLSelectElement;
const autoScanInput = document.getElementById("autoscan") as HTMLInputElement;
const warnLinksInput = document.getElementById("warn-malicious-links") as HTMLInputElement;
const warnTypedInput = document.getElementById("warn-typed-url") as HTMLInputElement;
const aiScanModeSelect = document.getElementById("ai-scan-mode") as HTMLSelectElement;
const apiKeyInput = document.getElementById("apikey") as HTMLInputElement;
const toggleKeyBtn = document.getElementById("toggle-key") as HTMLButtonElement;
const claudeModelSelect = document.getElementById("claude-model") as HTMLSelectElement;
const deepseekKeyInput = document.getElementById("deepseek-apikey") as HTMLInputElement;
const toggleDeepseekKeyBtn = document.getElementById("toggle-deepseek-key") as HTMLButtonElement;
const deepseekModelSelect = document.getElementById("deepseek-model") as HTMLSelectElement;
const safeBrowsingKeyInput = document.getElementById("safebrowsing-apikey") as HTMLInputElement;
const toggleSafeBrowsingKeyBtn = document.getElementById("toggle-safebrowsing-key") as HTMLButtonElement;
const virusTotalKeyInput = document.getElementById("virustotal-apikey") as HTMLInputElement;
const toggleVirusTotalKeyBtn = document.getElementById("toggle-virustotal-key") as HTMLButtonElement;
const saveBtn = document.getElementById("save") as HTMLButtonElement;
const statusEl = document.getElementById("status") as HTMLElement;

// Each on-page highlight toggle, paired with the checkbox that drives it. The id
// is `hl-<key>`, matching the keys of HighlightSettings.
const HIGHLIGHT_KEYS: (keyof HighlightSettings)[] = [
  "phishingIndicators",
  "urgentLanguage",
  "brandImpersonation",
  "suspiciousForms",
  "internalLinks",
  "externalLinks",
  "suspiciousLinks",
  "maliciousRedirects",
];

let settings: Settings;
// The loaded message dictionary for the user's language, filled by init().
let dict: Dict = {};
let statusTimer: number | undefined;

function flashSaved(): void {
  statusEl.textContent = dict.set_saved;
  if (statusTimer) clearTimeout(statusTimer);
  statusTimer = window.setTimeout(() => (statusEl.textContent = ""), 1500);
}

// The Show/Hide label is state-dependent, so it's managed here rather than
// through a static data-i18n attribute.
function updateToggleLabel(): void {
  const label = (input: HTMLInputElement): string =>
    input.type === "text" ? dict.set_hide : dict.set_show;
  toggleKeyBtn.textContent = label(apiKeyInput);
  toggleDeepseekKeyBtn.textContent = label(deepseekKeyInput);
  toggleSafeBrowsingKeyBtn.textContent = label(safeBrowsingKeyInput);
  toggleVirusTotalKeyBtn.textContent = label(virusTotalKeyInput);
}

// Flip a password field between masked and revealed, then refresh its label.
function toggleVisibility(input: HTMLInputElement): void {
  input.type = input.type === "password" ? "text" : "password";
  updateToggleLabel();
}

// Fill a model dropdown from the provider's option list and select the saved
// value. The labels are brand names, so they're not run through i18n.
function fillModelOptions(
  select: HTMLSelectElement,
  models: readonly AiModelOption[],
  selected: string,
): void {
  select.replaceChildren();
  for (const model of models) {
    const option = document.createElement("option");
    option.value = model.id;
    option.textContent = model.label;
    select.append(option);
  }
  select.value = selected;
}

// Masonry packing for the card grid. CSS grid sizes every row to its tallest
// card, which leaves tall empty bands under short cards that share a row with
// a tall one. Instead, rows become a small fixed unit (.settings__grid.masonry)
// and each card spans enough of them to cover its own height plus one gap, so
// each card slots in right below the card above it. Spans are refreshed
// whenever a card's size changes (window resizes, language switches).
const MASONRY_ROW_PX = 8;
const MASONRY_GAP_PX = 16;

function initMasonry(): void {
  const grid = document.querySelector<HTMLElement>(".settings__grid");
  if (!grid) return;
  const cards = Array.from(grid.children).filter((el): el is HTMLElement => {
    return el instanceof HTMLElement;
  });
  const relayout = (): void => {
    for (const card of cards) {
      const span = Math.ceil((card.offsetHeight + MASONRY_GAP_PX) / MASONRY_ROW_PX);
      card.style.gridRowEnd = `span ${span}`;
    }
  };
  grid.classList.add("masonry");
  relayout();
  const observer = new ResizeObserver(relayout);
  for (const card of cards) observer.observe(card);
}

async function init(): Promise<void> {
  initMasonry();
  settings = await loadSettings();
  dict = await loadMessages(settings.lang);

  themeSelect.value = settings.theme;
  langSelect.value = settings.lang;
  autoScanInput.checked = settings.autoScan;
  warnLinksInput.checked = settings.warnMaliciousLinks;
  warnTypedInput.checked = settings.warnTypedUrl;
  aiScanModeSelect.value = settings.aiScanMode;
  apiKeyInput.value = settings.apiKey;
  deepseekKeyInput.value = settings.deepseekApiKey;
  safeBrowsingKeyInput.value = settings.safeBrowsingApiKey;
  virusTotalKeyInput.value = settings.virusTotalApiKey;

  fillModelOptions(claudeModelSelect, CLAUDE_MODELS, settings.claudeModel);
  fillModelOptions(deepseekModelSelect, DEEPSEEK_MODELS, settings.deepseekModel);

  // The highlight toggles save immediately (like theme/language) so the choice
  // is in storage before the popup next reads it.
  for (const key of HIGHLIGHT_KEYS) {
    const input = document.getElementById(`hl-${key}`) as HTMLInputElement | null;
    if (!input) continue;
    input.checked = settings.highlights[key];
    input.addEventListener("change", async () => {
      settings = { ...settings, highlights: { ...settings.highlights, [key]: input.checked } };
      await saveSettings(settings);
      flashSaved();
    });
  }

  applyTheme(settings.theme);
  applyI18n(settings.lang, dict);
  updateToggleLabel();

  themeSelect.addEventListener("change", async () => {
    settings = { ...settings, theme: themeSelect.value as ThemePref };
    applyTheme(settings.theme);
    await saveSettings(settings);
    flashSaved();
  });

  langSelect.addEventListener("change", async () => {
    settings = { ...settings, lang: langSelect.value as LangPref };
    dict = await loadMessages(settings.lang);
    applyI18n(settings.lang, dict);
    updateToggleLabel();
    await saveSettings(settings);
    flashSaved();
  });

  // Model choices save immediately (like theme/language) so the popup reads the
  // latest selection the next time it runs an analysis.
  claudeModelSelect.addEventListener("change", async () => {
    settings = { ...settings, claudeModel: claudeModelSelect.value };
    await saveSettings(settings);
    flashSaved();
  });

  deepseekModelSelect.addEventListener("change", async () => {
    settings = { ...settings, deepseekModel: deepseekModelSelect.value };
    await saveSettings(settings);
    flashSaved();
  });

  // Auto-scan saves immediately (like the highlight toggles) so the background
  // worker, which watches storage, picks the change up right away.
  autoScanInput.addEventListener("change", async () => {
    settings = { ...settings, autoScan: autoScanInput.checked };
    await saveSettings(settings);
    flashSaved();
  });

  // The two safety-warning toggles save immediately so the next scan (for the
  // link prompt) and the next address-bar navigation (read live by the worker)
  // honour the choice.
  warnLinksInput.addEventListener("change", async () => {
    settings = { ...settings, warnMaliciousLinks: warnLinksInput.checked };
    await saveSettings(settings);
    flashSaved();
  });

  warnTypedInput.addEventListener("change", async () => {
    settings = { ...settings, warnTypedUrl: warnTypedInput.checked };
    await saveSettings(settings);
    flashSaved();
  });

  // Scan timing saves immediately so the popup honours it the next time it opens.
  aiScanModeSelect.addEventListener("change", async () => {
    settings = { ...settings, aiScanMode: aiScanModeSelect.value as AiScanMode };
    await saveSettings(settings);
    flashSaved();
  });

  toggleKeyBtn.addEventListener("click", () => toggleVisibility(apiKeyInput));
  toggleDeepseekKeyBtn.addEventListener("click", () => toggleVisibility(deepseekKeyInput));
  toggleSafeBrowsingKeyBtn.addEventListener("click", () => toggleVisibility(safeBrowsingKeyInput));
  toggleVirusTotalKeyBtn.addEventListener("click", () => toggleVisibility(virusTotalKeyInput));

  saveBtn.addEventListener("click", async () => {
    settings = {
      ...settings,
      apiKey: apiKeyInput.value.trim(),
      deepseekApiKey: deepseekKeyInput.value.trim(),
      safeBrowsingApiKey: safeBrowsingKeyInput.value.trim(),
      virusTotalApiKey: virusTotalKeyInput.value.trim(),
    };
    await saveSettings(settings);
    flashSaved();
  });
}

void init();
