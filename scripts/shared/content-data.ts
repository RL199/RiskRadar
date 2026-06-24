// Content-analysis "database": the wordlists and brand table the Content Analysis
// checks match page text against. Kept separate from the logic in
// content-analysis.ts so the lists can grow/be tuned without touching the
// algorithms. All match terms are lowercase; matching is whole-word /
// whole-phrase (see content-analysis.ts), so short tokens here won't fire inside
// unrelated words.
//
// Grounding:
//  - Phishing/urgency wording follows common phishing-email keyword studies
//    (e.g. Expel, KnowBe4, MetaCompliance round-ups of subject-line / body terms).
//  - The brand list follows the quarterly "most impersonated brands" phishing
//    reports — Check Point Research Q4 2025 had Microsoft, Google, Amazon, Apple,
//    Facebook/Meta, PayPal, Adobe, Booking, DHL and LinkedIn in the top ten —
//    extended with the shipping, banking, crypto and gaming brands phishing kits
//    routinely clone.

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
    ],
    labels: [
      "microsoft", "microsoftonline", "microsoft365", "live", "outlook", "office", "office365",
      "msn", "hotmail", "skype", "azure", "sharepoint", "windows", "bing", "xbox",
    ],
  },
  {
    name: "Google",
    keywords: ["google account", "gmail", "google drive", "google workspace", "your google account"],
    labels: ["google", "gmail", "googlemail", "youtube", "googleapis", "withgoogle", "gstatic"],
  },
  {
    name: "Amazon",
    keywords: ["amazon account", "amazon prime", "amazon login", "your amazon account", "aws account", "amazon"],
    labels: ["amazon", "amazonaws", "aws", "primevideo", "audible"],
  },
  {
    name: "Apple",
    keywords: ["apple id", "appleid", "icloud", "apple account", "itunes", "find my iphone"],
    labels: ["apple", "icloud", "me", "mac", "itunes"],
  },
  {
    name: "Facebook",
    keywords: ["facebook account", "log in to facebook", "facebook password", "your facebook account", "meta business"],
    labels: ["facebook", "fb", "meta", "messenger", "fbcdn"],
  },
  {
    name: "Instagram",
    keywords: ["instagram account", "instagram", "your instagram account"],
    labels: ["instagram", "cdninstagram"],
  },
  {
    name: "WhatsApp",
    keywords: ["whatsapp account", "verify your whatsapp", "whatsapp"],
    labels: ["whatsapp"],
  },
  {
    name: "PayPal",
    keywords: ["paypal account", "log in to paypal", "your paypal account", "paypal login", "paypal"],
    labels: ["paypal", "paypalobjects"],
  },
  {
    name: "Netflix",
    keywords: ["netflix account", "netflix membership", "your netflix account", "netflix"],
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
];
