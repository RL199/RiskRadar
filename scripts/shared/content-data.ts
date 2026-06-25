// Content-analysis "database": the wordlists and brand table the Content Analysis
// checks match page text against. Kept separate from the logic in
// content-analysis.ts so the lists can grow/be tuned without touching the
// algorithms. All match terms are lowercase; matching is whole-word /
// whole-phrase (see content-analysis.ts), so short tokens here won't fire inside
// unrelated words. The whole-word boundary is Unicode-aware, so the Hebrew terms
// below match exactly the same way the English ones do.
//
// Grounding:
//  - Phishing/urgency wording follows common phishing-email keyword studies
//    (e.g. Expel, KnowBe4, MetaCompliance round-ups of subject-line / body terms).
//  - The brand list follows the quarterly "most impersonated brands" phishing
//    reports — Check Point Research Q4 2025 had Microsoft, Google, Amazon, Apple,
//    Facebook/Meta, PayPal, Adobe, Booking, DHL and LinkedIn in the top ten —
//    extended with the shipping, banking, crypto and gaming brands phishing kits
//    routinely clone.
//  - Hebrew coverage: the same checks in the wording Israeli phishing SMS, emails
//    and pages actually use, plus the local bodies most impersonated in Israel.
//    Per Israeli round-ups (mako/Ynet, the National Cyber Directorate, ISOC-IL)
//    the leading lures are Highway 6 (כביש 6) tolls, the banks and credit-card
//    issuers, Israel Post (דואר ישראל) parcels, the Tax Authority, El Al, the
//    Electric Company and National Insurance.

export interface Brand {
  // Display name shown in the popup when impersonation is detected.
  name: string;
  // Brand-owned phrases/tokens to look for in the page text. Prefer two-word,
  // brand-specific phrases over bare names for words that also occur in ordinary
  // English (e.g. "apple", "chase", "ups"), to keep false positives down.
  keywords: string[];
  // The brand's own registrable primary labels (the part before the public
  // suffix). When the visited host's label is one of these we're on a genuine
  // brand domain, so it is never flagged — this covers a brand's many domains and
  // ccTLDs (google.com, google.co.uk, microsoftonline.com, …).
  labels: string[];
}

// Credential-bait / account-pretext wording: the "there is a problem with your
// account, re-confirm it" framing phishing pages lean on.
export const PHISHING_PHRASES: string[] = [
  "verify your account",
  "verify your identity",
  "verify your information",
  "verify your billing",
  "verify your payment",
  "verify it's you",
  "confirm your identity",
  "confirm your account",
  "confirm your password",
  "confirm your billing",
  "confirm your payment",
  "confirm your personal information",
  "confirm your details",
  "confirm it's you",
  "update your payment",
  "update your billing",
  "update your payment details",
  "update your account information",
  "update your security information",
  "update your security details",
  "validate your account",
  "reactivate your account",
  "restore your account",
  "unlock your account",
  "recover your account",
  "your account has been suspended",
  "your account has been locked",
  "your account has been limited",
  "your account has been disabled",
  "your account has been compromised",
  "your account will be suspended",
  "your account will be closed",
  "your account will be terminated",
  "your account will be deactivated",
  "unusual activity",
  "unusual sign-in activity",
  "unusual login activity",
  "suspicious activity",
  "suspicious sign-in",
  "suspicious login",
  "unauthorized login",
  "unauthorized sign-in",
  "unauthorized access",
  "security alert",
  "account security notice",
  "log in to verify",
  "sign in to verify",
  "re-enter your password",
  "to avoid suspension",
  "to avoid account closure",
  "to avoid deactivation",
  "failure to verify",
  "we were unable to verify",
  "your password will expire",
  "your access has been limited",

  // Hebrew (Israel): the same credential-bait / account-pretext framing in the
  // wording local phishing SMS and pages use ("there is a problem with your
  // account, re-confirm it" / "a parcel is waiting, pay to release it").
  "אמת את החשבון",
  "אמת את חשבונך",
  "אימות חשבון",
  "אמת את זהותך",
  "אימות זהות",
  "אמת את פרטיך",
  "אמת את הפרטים שלך",
  "אמת את פרטי החשבון",
  "עדכן את פרטיך",
  "עדכון פרטים",
  "עדכון פרטים אישיים",
  "עדכן את פרטי התשלום",
  "עדכון אמצעי תשלום",
  "אשר את החשבון",
  "אשר את זהותך",
  "אישור פרטים",
  "החשבון שלך נחסם",
  "חשבונך נחסם",
  "החשבון שלך הושעה",
  "החשבון שלך הוגבל",
  "החשבון שלך ננעל",
  "החשבון שלך ייחסם",
  "חשבונך ייחסם",
  "החשבון שלך נפרץ",
  "חשבונך נפרץ",
  "פעילות חשודה",
  "פעילות חשודה בחשבון",
  "זוהתה פעילות חשודה",
  "פעילות לא תקינה",
  "פעילות חריגה",
  "כניסה חשודה",
  "ניסיון התחברות חשוד",
  "חסימת כרטיס האשראי",
  "כרטיס האשראי שלך נחסם",
  "לאימות מיידי",
  "הזן את הסיסמה",
  "הזן את פרטי האשראי",
  "פרטי כרטיס אשראי",
  "התחבר כדי לאמת",
  "כדי למנוע חסימה",
  "כדי למנוע את חסימת החשבון",
  "שחזר את החשבון",
  "שחזור חשבון",
  "התראת אבטחה",
  "הודעת אבטחה",
  // The same lure verbs in the ל-infinitive form ("you must verify / update…"),
  // which is how the formal version is usually phrased. The bare-imperative forms
  // above won't match it on their own, because the ל- prefix attaches to the verb
  // and the matcher is whole-word.
  "לאמת את החשבון",
  "לאמת את חשבונך",
  "לאמת את זהותך",
  "לאמת את פרטיך",
  "לאמת את הפרטים שלך",
  "לאמת את פרטי החשבון",
  "לעדכן את פרטיך",
  "לעדכן את פרטי התשלום",
  "לאשר את החשבון",
  "לאשר את זהותך",
  "להזין את הסיסמה",
  "להזין את פרטי האשראי",
  "לשחזר את החשבון",
];

// Time-pressure / fear / scarcity wording: the urgency that pushes a visitor to
// act before thinking.
export const URGENCY_PHRASES: string[] = [
  "act now",
  "act immediately",
  "act fast",
  "action required",
  "action is required",
  "immediate action required",
  "immediate attention required",
  "requires your immediate attention",
  "urgent",
  "urgent action required",
  "response required",
  "respond immediately",
  "respond now",
  "respond within",
  "immediately",
  "as soon as possible",
  "right away",
  "without delay",
  "do not delay",
  "don't delay",
  "before it's too late",
  "within 24 hours",
  "within 48 hours",
  "within 72 hours",
  "in the next 24 hours",
  "expires today",
  "expires soon",
  "expires in 24 hours",
  "will expire",
  "expiring soon",
  "last chance",
  "last warning",
  "final notice",
  "final warning",
  "final reminder",
  "limited time",
  "limited time offer",
  "offer expires",
  "time sensitive",
  "time-sensitive",
  "hurry",
  "failure to respond",
  "failure to act",
  "click here now",
  "verify now",
  "update now",
  "confirm now",
  "take action now",
  "suspended immediately",
  "deactivated immediately",

  // Hebrew (Israel): time-pressure / fear / scarcity wording, including the
  // "act today / spots are limited" framing local marketing-style scams lean on.
  "דחוף",
  "מיידי",
  "מיידית",
  "באופן מיידי",
  "פעולה נדרשת",
  "נדרשת פעולה",
  "נדרשת פעולה מיידית",
  "נדרשת התייחסות מיידית",
  "דרישה דחופה",
  "תוך 24 שעות",
  "תוך 48 שעות",
  "בתוך 24 שעות",
  "עד 24 שעות",
  "ללא דיחוי",
  "בהקדם",
  "בהקדם האפשרי",
  "פג תוקף",
  "התוקף יפוג",
  "יפוג בקרוב",
  "זמן מוגבל",
  "הצעה לזמן מוגבל",
  "מקומות מוגבלים",
  "היום בלבד",
  "עד סוף השבוע",
  "הזדמנות אחרונה",
  "התראה אחרונה",
  "אזהרה אחרונה",
  "הודעה אחרונה",
  "תזכורת אחרונה",
  "פעל עכשיו",
  "פעל מיד",
  "לחץ כאן",
  "לחצו כאן",
  "לחץ כאן עכשיו",
  "ללחוץ כאן",
  "לחץ על הקישור",
  "לחצו על הקישור",
  "ללחוץ על הקישור",
  "אמת עכשיו",
  "עדכן עכשיו",
  "אשר עכשיו",
  "תשלום מיידי",
  "שלם עכשיו",
];

// Distinctive brand tokens the Links view watches for in a link's hostname. A
// link whose host contains one of these as a whole label/token (split on "." and
// "-") while its registrable domain is NOT that brand's is a classic look-alike
// (e.g. "paypal.secure-login.com" or "login-microsoft.account-verify.com").
// Kept to long, unambiguous brand words so ordinary domains don't trip it: short
// or dictionary-ish labels ("ups", "live", "me", "office", "chase") are left out
// on purpose to keep false positives low.
export const BRAND_URL_TOKENS: string[] = [
  "paypal", "microsoft", "outlook", "office365", "onedrive", "sharepoint",
  "google", "gmail", "googlemail", "amazon", "apple", "icloud", "appleid",
  "itunes", "facebook", "instagram", "whatsapp", "messenger", "netflix",
  "linkedin", "dropbox", "docusign", "wetransfer", "coinbase", "binance",
  "roblox", "spotify", "wellsfargo", "bankofamerica", "americanexpress",
  "capitalone", "mastercard", "barclays", "citibank", "fedex", "usps",
  // Israeli brands' distinctive domain labels (same "long, unambiguous word"
  // rule — short/dictionary-ish labels like "iec", "btl", "max", "cal" are left
  // out on purpose).
  "bankhapoalim", "poalim", "leumi", "discountbank", "isracard",
  "israelpost", "kvish6", "elal",
];

// Brands phishing kits most often impersonate, with their legitimate domain
// labels. Brand impersonation is only flagged on credential-entry pages whose
// host isn't one of these labels (see analyzeBrandImpersonation).
export const BRANDS: Brand[] = [
  {
    name: "Microsoft",
    keywords: [
      "microsoft account", "microsoft 365", "office 365", "office365", "outlook account",
      "outlook.com", "onedrive", "sharepoint online", "windows account", "your microsoft account",
      "חשבון מיקרוסופט",
    ],
    labels: [
      "microsoft", "microsoftonline", "microsoft365", "live", "outlook", "office", "office365",
      "msn", "hotmail", "skype", "azure", "sharepoint", "windows", "bing", "xbox",
    ],
  },
  {
    name: "Google",
    keywords: ["google account", "gmail", "google drive", "google workspace", "your google account", "חשבון גוגל"],
    labels: ["google", "gmail", "googlemail", "youtube", "googleapis", "withgoogle", "gstatic"],
  },
  {
    name: "Amazon",
    keywords: ["amazon account", "amazon prime", "amazon login", "your amazon account", "aws account", "amazon", "חשבון אמזון"],
    labels: ["amazon", "amazonaws", "aws", "primevideo", "audible"],
  },
  {
    name: "Apple",
    keywords: ["apple id", "appleid", "icloud", "apple account", "itunes", "find my iphone", "מזהה אפל", "חשבון אפל"],
    labels: ["apple", "icloud", "me", "mac", "itunes"],
  },
  {
    name: "Facebook",
    keywords: ["facebook account", "log in to facebook", "facebook password", "your facebook account", "meta business", "חשבון פייסבוק"],
    labels: ["facebook", "fb", "meta", "messenger", "fbcdn"],
  },
  {
    name: "Instagram",
    keywords: ["instagram account", "instagram", "your instagram account", "חשבון אינסטגרם"],
    labels: ["instagram", "cdninstagram"],
  },
  {
    name: "WhatsApp",
    keywords: ["whatsapp account", "verify your whatsapp", "whatsapp", "חשבון וואטסאפ", "אמת את הוואטסאפ"],
    labels: ["whatsapp"],
  },
  {
    name: "PayPal",
    keywords: ["paypal account", "log in to paypal", "your paypal account", "paypal login", "paypal", "חשבון פייפאל"],
    labels: ["paypal", "paypalobjects"],
  },
  {
    name: "Netflix",
    keywords: ["netflix account", "netflix membership", "your netflix account", "netflix", "חשבון נטפליקס"],
    labels: ["netflix", "nflxext"],
  },
  {
    name: "LinkedIn",
    keywords: ["linkedin account", "your linkedin account", "linkedin"],
    labels: ["linkedin", "licdn"],
  },
  {
    name: "Adobe",
    keywords: ["adobe account", "adobe id", "adobe sign", "adobe document cloud"],
    labels: ["adobe", "adobelogin"],
  },
  {
    name: "Dropbox",
    keywords: ["dropbox account", "your dropbox", "dropbox"],
    labels: ["dropbox", "dropboxusercontent"],
  },
  {
    name: "DocuSign",
    keywords: ["docusign", "sign with docusign", "via docusign"],
    labels: ["docusign"],
  },
  {
    name: "WeTransfer",
    keywords: ["wetransfer", "files via wetransfer"],
    labels: ["wetransfer"],
  },
  {
    name: "DHL",
    keywords: ["dhl express", "your dhl shipment", "dhl tracking"],
    labels: ["dhl"],
  },
  {
    name: "FedEx",
    keywords: ["fedex shipment", "fedex delivery", "fedex tracking", "your fedex"],
    labels: ["fedex"],
  },
  {
    name: "UPS",
    keywords: ["ups package", "ups delivery", "ups my choice", "ups tracking"],
    labels: ["ups"],
  },
  {
    name: "USPS",
    keywords: ["usps tracking", "usps delivery", "united states postal"],
    labels: ["usps"],
  },
  {
    name: "Booking.com",
    keywords: ["booking.com", "your booking confirmation", "booking account"],
    labels: ["booking"],
  },
  {
    name: "Roblox",
    keywords: ["roblox account", "your roblox", "robux", "roblox"],
    labels: ["roblox", "rbxcdn"],
  },
  {
    name: "Steam",
    keywords: ["steam account", "steam guard", "steam community"],
    labels: ["steampowered", "steamcommunity", "valvesoftware"],
  },
  {
    name: "eBay",
    keywords: ["ebay account", "your ebay account", "ebay"],
    labels: ["ebay", "ebayimg"],
  },
  {
    name: "Spotify",
    keywords: ["spotify account", "spotify premium", "spotify"],
    labels: ["spotify"],
  },
  {
    name: "Coinbase",
    keywords: ["coinbase account", "coinbase"],
    labels: ["coinbase"],
  },
  {
    name: "Binance",
    keywords: ["binance account", "binance"],
    labels: ["binance"],
  },
  {
    name: "Chase",
    keywords: ["chase bank", "chase online", "jpmorgan chase", "chase account"],
    labels: ["chase", "jpmorganchase", "jpmorgan"],
  },
  {
    name: "Wells Fargo",
    keywords: ["wells fargo"],
    labels: ["wellsfargo"],
  },
  {
    name: "Bank of America",
    keywords: ["bank of america"],
    labels: ["bankofamerica", "bofa"],
  },
  {
    name: "Citibank",
    keywords: ["citibank", "citi account"],
    labels: ["citi", "citibank", "citigroup"],
  },
  {
    name: "Capital One",
    keywords: ["capital one"],
    labels: ["capitalone"],
  },
  {
    name: "American Express",
    keywords: ["american express", "amex account"],
    labels: ["americanexpress", "amex", "aexp"],
  },
  {
    name: "Mastercard",
    keywords: ["mastercard", "secure mastercard"],
    labels: ["mastercard"],
  },
  {
    name: "HSBC",
    keywords: ["hsbc"],
    labels: ["hsbc"],
  },
  {
    name: "Barclays",
    keywords: ["barclays"],
    labels: ["barclays"],
  },

  // Israeli bodies most impersonated in phishing aimed at Israelis. Keywords are
  // the Hebrew names/lures as they appear on the page (kept brand-specific to keep
  // false positives down — e.g. bare "לאומי"/"מזרחי"/"דרך ארץ" are ordinary words,
  // so the two-word bank names are used instead); labels are each body's real
  // registrable label, so its own site is never flagged.
  {
    name: "כביש 6",
    keywords: ["כביש 6", "כביש שש", "אגרת כביש 6", "חוב אגרה"],
    labels: ["kvish6"],
  },
  {
    name: "דואר ישראל",
    keywords: ["דואר ישראל", "חבילה ממתינה", "החבילה שלך ממתינה", "החבילה מחכה במכס", "דמי מכס", "דמי משלוח"],
    labels: ["israelpost"],
  },
  {
    name: "בנק הפועלים",
    keywords: ["בנק הפועלים"],
    labels: ["bankhapoalim", "poalim"],
  },
  {
    name: "בנק לאומי",
    keywords: ["בנק לאומי"],
    labels: ["leumi"],
  },
  {
    name: "בנק דיסקונט",
    keywords: ["בנק דיסקונט", "דיסקונט"],
    labels: ["discountbank"],
  },
  {
    name: "מזרחי טפחות",
    keywords: ["מזרחי טפחות", "בנק מזרחי"],
    labels: ["mizrahi-tefahot"],
  },
  {
    name: "ישראכרט",
    keywords: ["ישראכרט"],
    labels: ["isracard"],
  },
  {
    name: "כאל",
    keywords: ["ויזה כאל", "כאל אונליין"],
    labels: ["cal-online", "cal"],
  },
  {
    name: "מקס",
    keywords: ["כרטיס מקס", "מקס איט"],
    labels: ["max"],
  },
  {
    name: "חברת החשמל",
    keywords: ["חברת החשמל", "חשבון חשמל", "חיוב כפול"],
    labels: ["iec"],
  },
  {
    name: "ביטוח לאומי",
    keywords: ["ביטוח לאומי", "המוסד לביטוח לאומי"],
    labels: ["btl"],
  },
  {
    name: "רשות המסים",
    keywords: ["רשות המסים", "מס הכנסה", "החזר מס"],
    labels: ["taxes", "gov"],
  },
  {
    name: "אל על",
    keywords: ["אל על", "טיסות אל על", "מועדון הנוסע המתמיד"],
    labels: ["elal"],
  },
];
