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
// What the safety guards do when they catch a risky navigation (a click on a
// flagged link, or a risky address entered in the URL bar). "warn" asks for
// confirmation and lets the user continue; "block" cancels the navigation and
// shows a message that the website is blocked; "none" lets the navigation
// through with no interruption at all (flagged links stay outlined).
export type GuardAction = "warn" | "block" | "none";
// How the link-click reputation scan handles the destination while its checks
// run (only meaningful when linkClickScan is on). "overlay" opens the site
// right away and reports the verdicts in the corner overlay; "warn" holds the
// navigation on the extension's checking page until the verdicts arrive, then
// asks before entering a site that failed the check; "block" holds it the same
// way but refuses to enter a failed site.
export type LinkClickScanMode = "overlay" | "warn" | "block";

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
  // What both safety guards do when they fire: clicking a link a scan flagged
  // as a suspicious link or a malicious redirect, or entering a risky address
  // directly in the URL bar (a known phishing host, or a URL with strong
  // phishing traits; handled by the background worker via webNavigation).
  // "warn" (the default) shows a confirmation the user can accept to continue;
  // "block" cancels the navigation outright and tells the user the website is
  // blocked; "none" does nothing. Flagged links are outlined red regardless.
  guardAction: GuardAction;
  // When on, following a link runs the reputation checks on both ends of the
  // click: the URL the click started from and the URL the navigation finally
  // landed on (redirects can change it along the way), with the verdicts shown
  // in a small overlay on the page. Off by default: every click then costs
  // network lookups (and VirusTotal quota when a key is set), so the user opts
  // in.
  linkClickScan: boolean;
  // What happens to the destination while those checks run: open it right away
  // with the overlay, or hold it on a checking page and warn about or block a
  // site that fails the check. See LinkClickScanMode above.
  linkClickScanMode: LinkClickScanMode;
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

// The warning marks are on by default (they are the extension's main signal,
// so the user opts out rather than in). The benign link buckets (internal and
// external) are informational rather than warnings, so they start off and the
// user opts in.
export const DEFAULT_HIGHLIGHTS: HighlightSettings = {
  phishingIndicators: true,
  urgentLanguage: true,
  brandImpersonation: true,
  suspiciousForms: true,
  internalLinks: false,
  externalLinks: false,
  suspiciousLinks: true,
  maliciousRedirects: true,
};

export const DEFAULT_SETTINGS: Settings = {
  theme: "dark",
  lang: "en",
  autoScan: false,
  guardAction: "warn",
  linkClickScan: false,
  linkClickScanMode: "overlay",
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
