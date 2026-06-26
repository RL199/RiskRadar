// Shared settings model + storage helpers used by both the popup and the
// options page. Stored in chrome.storage.local so the API key stays on-device.

export type ThemePref = "system" | "light" | "dark";
export type LangPref = "en" | "he";
// Which provider the AI Analysis view calls. Mirrors AiProvider in
// ai-analysis.ts; kept inline so this leaf module stays dependency-free.
export type AiProvider = "claude" | "deepseek";
// When the popup runs the AI Analysis. "manual" waits for the Analyze button
// (the default, so opening the popup never bills the user); "auto" runs it as
// soon as the popup opens on a scannable page.
export type AiScanMode = "auto" | "manual";

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
  // When on, the background worker scans each page as you browse, without you
  // opening the popup: it sets a colour-coded risk badge on the toolbar icon and
  // applies the in-page highlights. The AI scan never runs automatically here
  // (it bills the user); it stays governed by aiScanMode in the popup.
  autoScan: boolean;
  apiKey: string;
  deepseekApiKey: string;
  safeBrowsingApiKey: string;
  virusTotalApiKey: string;
  // Which provider AI Analysis uses when the user runs it.
  aiProvider: AiProvider;
  // When the AI Analysis runs: on popup open ("auto") or on the Analyze button
  // ("manual").
  aiScanMode: AiScanMode;
  // Which model each provider uses. Values match the option ids in
  // ai-analysis.ts (CLAUDE_MODELS / DEEPSEEK_MODELS); the defaults below pick the
  // balanced/cheap option from each list, kept inline so this leaf module stays
  // dependency-free.
  claudeModel: string;
  deepseekModel: string;
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
  autoScan: false,
  apiKey: "",
  deepseekApiKey: "",
  safeBrowsingApiKey: "",
  virusTotalApiKey: "",
  aiProvider: "claude",
  aiScanMode: "manual",
  claudeModel: "claude-sonnet-4-6",
  deepseekModel: "deepseek-v4-flash",
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
