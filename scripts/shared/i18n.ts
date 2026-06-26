// Runtime i18n backed by the official Chrome _locales/ message files.
//
// The Web Store listing (extension name/description in manifest.json) is
// localized the standard way, via __MSG_*__ placeholders resolved by chrome.i18n
// against the browser's UI language. chrome.i18n.getMessage, however, only ever
// returns strings in that single UI language and cannot be switched at runtime,
// which the in-app Language toggle needs. So for the popup/options UI we read the
// very same _locales/<lang>/messages.json files ourselves with fetch and resolve
// keys from the chosen language. The _locales files stay the single source of
// truth for both paths.
// See https://developer.chrome.com/docs/extensions/reference/api/i18n

import type { LangPref } from "./settings";

export type Dict = Record<string, string>;

// The on-disk format: { key: { message, description? } }. We only need message.
type RawMessages = Record<string, { message: string }>;

// Loaded dictionaries are cached so reopening a view or re-resolving a key never
// refetches the same file.
const cache = new Map<LangPref, Dict>();

async function fetchDict(lang: LangPref): Promise<Dict> {
  const url = chrome.runtime.getURL(`_locales/${lang}/messages.json`);
  const raw = (await (await fetch(url)).json()) as RawMessages;
  const dict: Dict = {};
  for (const [key, entry] of Object.entries(raw)) dict[key] = entry.message;
  return dict;
}

// Load (and cache) the message dictionary for a language. Falls back to English
// if the requested file can't be read, and to an empty dict if even that fails,
// in which case the HTML's built-in English text is left in place.
export async function loadMessages(lang: LangPref): Promise<Dict> {
  const cached = cache.get(lang);
  if (cached) return cached;

  try {
    const dict = await fetchDict(lang);
    cache.set(lang, dict);
    return dict;
  } catch {
    if (lang !== "en") return loadMessages("en");
    return {};
  }
}

// Apply a loaded dictionary to the current document: set <html lang/dir> and fill
// any element carrying a data-i18n (textContent) or data-i18n-placeholder
// (placeholder) attribute.
export function applyI18n(lang: LangPref, dict: Dict): void {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "he" ? "rtl" : "ltr";

  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const value = el.dataset.i18n ? dict[el.dataset.i18n] : undefined;
    if (value !== undefined) el.textContent = value;
  }

  for (const el of document.querySelectorAll<HTMLInputElement>("[data-i18n-placeholder]")) {
    const value = el.dataset.i18nPlaceholder ? dict[el.dataset.i18nPlaceholder] : undefined;
    if (value !== undefined) el.placeholder = value;
  }
}
