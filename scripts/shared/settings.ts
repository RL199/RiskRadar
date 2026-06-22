// Shared settings model + storage helpers used by both the popup and the
// options page. Stored in chrome.storage.local so the API key stays on-device.

export type ThemePref = "system" | "light" | "dark";
export type LangPref = "en" | "he";

export interface Settings {
  theme: ThemePref;
  lang: LangPref;
  apiKey: string;
}

export const DEFAULT_SETTINGS: Settings = {
  theme: "dark",
  lang: "en",
  apiKey: "",
};

const STORAGE_KEY = "settings";

export async function loadSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return { ...DEFAULT_SETTINGS, ...(stored[STORAGE_KEY] as Partial<Settings> | undefined) };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: settings });
}
