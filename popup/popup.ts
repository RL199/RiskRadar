// Popup entry point. Compiled to popup.js by esbuild and loaded from popup.html.
// Applies the user's theme/language, then handles view navigation.

import { loadSettings } from "../scripts/shared/settings";
import { applyTheme } from "../scripts/shared/theme";
import { applyI18n } from "../scripts/shared/i18n";

const MAIN_VIEW = "view-main";

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

async function init(): Promise<void> {
  const settings = await loadSettings();
  applyTheme(settings.theme);
  applyI18n(settings.lang);
  setupNavigation();
  const url = await getActiveTabUrl();
  showActiveHost(url);
  setupVirusTotal(url);
}

void init();
