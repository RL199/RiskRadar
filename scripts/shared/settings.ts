// Shared settings model + storage helpers used by both the popup and the
// options page. Stored in chrome.storage.local so the API key stays on-device.

export type ThemePref = "system" | "light" | "dark";
export type LangPref = "en" | "he";
// Which provider the AI Analysis view calls. Mirrors AiProvider in
// ai-analysis.ts; kept inline so this leaf module stays dependency-free.
export type AiProvider = "claude" | "deepseek";

// Per-element toggles for the marks the popup draws on the page. Each flag gates
// one kind of highlight so the user can turn any of them off individually from
// the options page; the popup reads these when it (re)scans a tab.
export interface HighlightSettings {
  // Content Analysis marks (highlightPageMatches).
  phishingIndicators: boolean;
  urgentLanguage: boolean;
  brandImpersonation: boolean;
  suspiciousForms: boolean;
  // Links marks (highlightPageLinks), one per verdict bucket.
  internalLinks: boolean;
  externalLinks: boolean;
  suspiciousLinks: boolean;
  maliciousRedirects: boolean;
}

export interface Settings {
  theme: ThemePref;
  lang: LangPref;
  apiKey: string;
  deepseekApiKey: string;
  safeBrowsingApiKey: string;
  virusTotalApiKey: string;
  // Which provider AI Analysis uses when the user runs it.
  aiProvider: AiProvider;
  highlights: HighlightSettings;
}

// Every highlight is on by default — the marks are the extension's main signal,
// so the user opts out rather than in.
export const DEFAULT_HIGHLIGHTS: HighlightSettings = {
  phishingIndicators: true,
  urgentLanguage: true,
  brandImpersonation: true,
  suspiciousForms: true,
  internalLinks: true,
  externalLinks: true,
  suspiciousLinks: true,
  maliciousRedirects: true,
};

export const DEFAULT_SETTINGS: Settings = {
  theme: "dark",
  lang: "en",
  apiKey: "",
  deepseekApiKey: "",
  safeBrowsingApiKey: "",
  virusTotalApiKey: "",
  aiProvider: "claude",
  highlights: DEFAULT_HIGHLIGHTS,
};

const STORAGE_KEY = "settings";

export async function loadSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const saved = stored[STORAGE_KEY] as Partial<Settings> | undefined;
  // Merge highlights one level deep so a flag added in a later version still
  // falls back to its default rather than being dropped by the shallow spread.
  return {
    ...DEFAULT_SETTINGS,
    ...saved,
    highlights: { ...DEFAULT_HIGHLIGHTS, ...saved?.highlights },
  };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: settings });
}
