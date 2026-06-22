// Options page logic: load settings into the controls, persist changes, and
// apply theme/language live (including to this page itself).

import {
  loadSettings,
  saveSettings,
  type LangPref,
  type Settings,
  type ThemePref,
} from "../scripts/shared/settings";
import { applyTheme } from "../scripts/shared/theme";
import { applyI18n, messages } from "../scripts/shared/i18n";

const themeSelect = document.getElementById("theme") as HTMLSelectElement;
const langSelect = document.getElementById("lang") as HTMLSelectElement;
const apiKeyInput = document.getElementById("apikey") as HTMLInputElement;
const toggleKeyBtn = document.getElementById("toggle-key") as HTMLButtonElement;
const saveBtn = document.getElementById("save") as HTMLButtonElement;
const statusEl = document.getElementById("status") as HTMLElement;

let settings: Settings;
let statusTimer: number | undefined;

function flashSaved(): void {
  statusEl.textContent = messages[settings.lang].set_saved;
  if (statusTimer) clearTimeout(statusTimer);
  statusTimer = window.setTimeout(() => (statusEl.textContent = ""), 1500);
}

// The Show/Hide label is state-dependent, so it's managed here rather than
// through a static data-i18n attribute.
function updateToggleLabel(): void {
  const dict = messages[settings.lang];
  toggleKeyBtn.textContent = apiKeyInput.type === "text" ? dict.set_hide : dict.set_show;
}

async function init(): Promise<void> {
  settings = await loadSettings();

  themeSelect.value = settings.theme;
  langSelect.value = settings.lang;
  apiKeyInput.value = settings.apiKey;

  applyTheme(settings.theme);
  applyI18n(settings.lang);
  updateToggleLabel();

  themeSelect.addEventListener("change", async () => {
    settings = { ...settings, theme: themeSelect.value as ThemePref };
    applyTheme(settings.theme);
    await saveSettings(settings);
    flashSaved();
  });

  langSelect.addEventListener("change", async () => {
    settings = { ...settings, lang: langSelect.value as LangPref };
    applyI18n(settings.lang);
    updateToggleLabel();
    await saveSettings(settings);
    flashSaved();
  });

  toggleKeyBtn.addEventListener("click", () => {
    apiKeyInput.type = apiKeyInput.type === "password" ? "text" : "password";
    updateToggleLabel();
  });

  saveBtn.addEventListener("click", async () => {
    settings = { ...settings, apiKey: apiKeyInput.value.trim() };
    await saveSettings(settings);
    flashSaved();
  });
}

void init();
