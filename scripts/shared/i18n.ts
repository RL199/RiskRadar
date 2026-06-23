import type { LangPref } from "./settings";

type Messages = Record<string, string>;

export const messages: Record<LangPref, Messages> = {
  en: {
    // Popup chrome
    scannedJustNow: "Scanned just now",
    verdict_safe: "Safe",
    rescan: "Rescan",
    virustotal: "VirusTotal",
    // Categories
    cat_url: "URL & Domain",
    cat_reputation: "Reputation",
    cat_content: "Content Analysis",
    cat_links: "Links",
    cat_ai: "AI Analysis",
    // Statuses
    status_good: "Good",
    status_warning: "Warning",
    status_danger: "Risky",
    // Detail summaries
    sum_url: "This URL looks safe.",
    sum_url_warn: "This URL has some warning signs.",
    sum_url_bad: "This URL looks risky.",
    sum_url_unknown: "Couldn't fully analyze this URL.",
    sum_reputation: "This site has a good reputation.",
    sum_content: "Some content may be suspicious.",
    sum_links: "No suspicious links found.",
    sum_ai: "AI model did not find threats.",
    // Row labels
    lbl_protocol: "Protocol",
    lbl_domainAge: "Domain Age",
    lbl_subdomain: "Subdomain",
    lbl_urlLength: "URL Length",
    lbl_suspiciousKeywords: "Suspicious Keywords",
    lbl_phishingDb: "Phishing Database",
    lbl_blacklist: "Blacklist Status",
    lbl_phishingIndicators: "Phishing Indicators",
    lbl_suspiciousForms: "Suspicious Forms",
    lbl_urgentLanguage: "Urgent Language",
    lbl_brandImpersonation: "Brand Impersonation",
    lbl_totalLinks: "Total Links",
    lbl_externalLinks: "External Links",
    lbl_suspiciousLinks: "Suspicious Links",
    lbl_maliciousRedirects: "Malicious Redirects",
    lbl_phishingProbability: "Phishing Probability",
    lbl_socialEngineering: "Social Engineering",
    lbl_contentRiskScore: "Content Risk Score",
    lbl_summary: "Summary",
    // Row values
    val_short: "Short",
    val_medium: "Medium",
    val_long: "Long",
    val_noneFound: "None found",
    val_clean: "Clean",
    val_notListed: "Not listed",
    val_none: "None",
    val_low: "Low",
    val_unknown: "Unknown",
    // Domain-age units
    unit_years: "years",
    unit_months: "months",
    unit_days: "days",
    ai_summary_body: "The content appears to be legitimate and safe.",
    // Settings page
    set_title: "Settings",
    set_subtitle: "Configure Risk Radar.",
    set_appearance: "Appearance",
    set_theme: "Theme",
    set_theme_system: "System",
    set_theme_light: "Light",
    set_theme_dark: "Dark",
    set_language: "Language",
    set_ai: "AI",
    set_apikey: "Claude API key",
    set_apikey_help: "Used for AI-based content analysis. Stored locally on your device.",
    set_apikey_placeholder: "sk-ant-...",
    set_deepseek_apikey: "DeepSeek API key",
    set_deepseek_apikey_help: "Used for AI-based content analysis. Stored locally on your device.",
    set_deepseek_apikey_placeholder: "sk-...",
    set_show: "Show",
    set_hide: "Hide",
    set_save: "Save",
    set_saved: "Saved",
  },
  he: {
    // Popup chrome
    scannedJustNow: "נסרק זה עתה",
    verdict_safe: "בטוח",
    rescan: "סריקה מחדש",
    virustotal: "VirusTotal",
    // Categories
    cat_url: "כתובת ודומיין",
    cat_reputation: "מוניטין",
    cat_content: "ניתוח תוכן",
    cat_links: "קישורים",
    cat_ai: "ניתוח AI",
    // Statuses
    status_good: "תקין",
    status_warning: "אזהרה",
    status_danger: "מסוכן",
    // Detail summaries
    sum_url: "הכתובת נראית בטוחה.",
    sum_url_warn: "בכתובת יש סימני אזהרה מסוימים.",
    sum_url_bad: "הכתובת נראית מסוכנת.",
    sum_url_unknown: "לא ניתן היה לנתח את הכתובת במלואה.",
    sum_reputation: "לאתר יש מוניטין טוב.",
    sum_content: "ייתכן שחלק מהתוכן חשוד.",
    sum_links: "לא נמצאו קישורים חשודים.",
    sum_ai: "מודל ה-AI לא מצא איומים.",
    // Row labels
    lbl_protocol: "פרוטוקול",
    lbl_domainAge: "גיל הדומיין",
    lbl_subdomain: "תת-דומיין",
    lbl_urlLength: "אורך הכתובת",
    lbl_suspiciousKeywords: "מילות מפתח חשודות",
    lbl_phishingDb: "מאגר פישינג",
    lbl_blacklist: "סטטוס רשימה שחורה",
    lbl_phishingIndicators: "אינדיקטורים לפישינג",
    lbl_suspiciousForms: "טפסים חשודים",
    lbl_urgentLanguage: "שפה דחופה",
    lbl_brandImpersonation: "התחזות למותג",
    lbl_totalLinks: "סך הקישורים",
    lbl_externalLinks: "קישורים חיצוניים",
    lbl_suspiciousLinks: "קישורים חשודים",
    lbl_maliciousRedirects: "הפניות זדוניות",
    lbl_phishingProbability: "הסתברות לפישינג",
    lbl_socialEngineering: "הנדסה חברתית",
    lbl_contentRiskScore: "ציון סיכון תוכן",
    lbl_summary: "סיכום",
    // Row values
    val_short: "קצרה",
    val_medium: "בינונית",
    val_long: "ארוכה",
    val_noneFound: "לא נמצאו",
    val_clean: "נקי",
    val_notListed: "לא רשום",
    val_none: "אין",
    val_low: "נמוכה",
    val_unknown: "לא ידוע",
    // Domain-age units
    unit_years: "שנים",
    unit_months: "חודשים",
    unit_days: "ימים",
    ai_summary_body: "התוכן נראה לגיטימי ובטוח.",
    // Settings page
    set_title: "הגדרות",
    set_subtitle: "הגדרת Risk Radar.",
    set_appearance: "מראה",
    set_theme: "ערכת נושא",
    set_theme_system: "מערכת",
    set_theme_light: "בהיר",
    set_theme_dark: "כהה",
    set_language: "שפה",
    set_ai: "בינה מלאכותית",
    set_apikey: "מפתח API של Claude",
    set_apikey_help: "משמש לניתוח תוכן מבוסס AI. נשמר מקומית במכשיר שלך.",
    set_apikey_placeholder: "sk-ant-...",
    set_deepseek_apikey: "מפתח API של DeepSeek",
    set_deepseek_apikey_help: "משמש לניתוח תוכן מבוסס AI. נשמר מקומית במכשיר שלך.",
    set_deepseek_apikey_placeholder: "sk-...",
    set_show: "הצג",
    set_hide: "הסתר",
    set_save: "שמור",
    set_saved: "נשמר",
  },
};

// Applies the language: sets <html lang/dir> and fills any element carrying a
// data-i18n (textContent) or data-i18n-placeholder (placeholder) attribute.
export function applyI18n(lang: LangPref): void {
  const dict = messages[lang];
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
