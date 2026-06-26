// AI analysis. Framework-free helpers used by the popup's "AI Analysis" view.
// Unlike the other categories (heuristic/offline or keyless reputation lookups),
// this one sends the page to a large language model and asks it to judge
// phishing / social-engineering risk, returning a small structured verdict.
//
// Two providers are supported and the user picks which to use:
//  - Claude (Anthropic Messages API) — https://docs.claude.com/en/api/messages
//  - DeepSeek (OpenAI-compatible chat completions) — https://api-docs.deepseek.com
// Both are called directly with fetch (no SDK), matching every other API call in
// this project. The view is on-demand: the model is only called when the user
// asks for it, so the popup never bills the user just by being opened.
//
// Like the other modules, nothing here throws: any network/parse failure is
// caught and returned as a failed AiResult, so a bad key or offline model never
// breaks the popup.

import type { PageContent } from "./content-analysis";

// The models the user can pick per provider. The options page renders these as
// dropdowns; the `id` is the exact string each API expects and the `label` is
// what the dropdown shows. Order the list with the most capable model first.
export interface AiModelOption {
  id: string;
  label: string;
}

// Anthropic's current tiers: Opus (most capable), Sonnet (balanced), Haiku
// (fastest and cheapest). https://docs.claude.com/en/docs/about-claude/models/overview
export const CLAUDE_MODELS: readonly AiModelOption[] = [
  { id: "claude-opus-4-8", label: "Claude Opus 4.8" },
  { id: "claude-sonnet-4-6", label: "Claude Sonnet 4.6" },
  { id: "claude-haiku-4-5", label: "Claude Haiku 4.5" },
];

// DeepSeek V4: Flash (fast and cheap) and Pro (most capable). These replace the
// legacy `deepseek-chat` / `deepseek-reasoner` aliases, which DeepSeek
// deprecates on 2026-07-24. https://api-docs.deepseek.com/quick_start/pricing
export const DEEPSEEK_MODELS: readonly AiModelOption[] = [
  { id: "deepseek-v4-flash", label: "DeepSeek V4 Flash" },
  { id: "deepseek-v4-pro", label: "DeepSeek V4 Pro" },
];

// Cap the visible text we send so a huge page can't run up the token bill. A few
// thousand characters is plenty for the model to judge intent.
const MAX_TEXT_CHARS = 6000;

export type AiProvider = "claude" | "deepseek";

export type SocialEngineeringLevel = "low" | "medium" | "high";

// What the popup needs to render: the model's structured judgement.
export interface AiVerdict {
  // 0–100: how likely the page is a phishing attempt.
  phishingProbability: number;
  // The model's social-engineering / manipulation read.
  socialEngineering: SocialEngineeringLevel;
  // 0–100: overall content risk.
  contentRiskScore: number;
  // One or two sentences explaining the verdict, shown in the summary note.
  summary: string;
}

// What we feed the model: the page summary plus where it came from.
export interface AiInput {
  url: string;
  host: string;
  page: PageContent;
}

// A successful analysis carries a verdict; a failure carries a message-key the
// popup can show. Mirrors the never-throw contract of the other modules.
export type AiResult = { ok: true; verdict: AiVerdict } | { ok: false; error: string };

// ------------------------------- Prompting -------------------------------- //

// The system prompt: defines the analyst role and the exact JSON shape. The word
// "json" and a concrete example are included on purpose — DeepSeek's JSON mode
// requires both, and it keeps Claude's output equally well-formed.
const SYSTEM_PROMPT = [
  "You are a phishing and social-engineering detector for a browser security extension.",
  "You are given a summary of the web page the user is currently viewing.",
  "Judge how likely the page is a phishing or social-engineering attempt and how",
  "manipulative its content is. Base your judgement only on the evidence provided;",
  "do not assume malice from a brand name alone, and treat well-known legitimate",
  "sites as low risk unless the evidence says otherwise.",
  "",
  "Respond with ONLY a single JSON object, no markdown and no prose, in exactly",
  'this shape: {"phishingProbability": <integer 0-100>, "socialEngineering":',
  '"low"|"medium"|"high", "contentRiskScore": <integer 0-100>, "summary":',
  '"<one or two short sentences>"}.',
].join("\n");

// Build the user message: a compact, labelled context block. Keeping it small and
// structured helps the model and bounds token cost.
function buildUserContent(input: AiInput): string {
  const { url, host, page } = input;
  const forms = page.forms.filter((f) => f.hasPassword);
  const leaky = forms.filter((f) => f.crossOrigin || f.insecure).length;

  const formNote =
    forms.length === 0
      ? "none"
      : `${forms.length} password form(s), ${leaky} posting cross-domain or over HTTP`;

  const text = page.text.slice(0, MAX_TEXT_CHARS);

  return [
    `URL: ${url}`,
    `Host: ${host}`,
    `Title: ${page.title || "(none)"}`,
    `Password fields on page: ${page.passwordFields}`,
    `Password forms: ${formNote}`,
    "Visible page text (may be truncated):",
    text,
  ].join("\n");
}

// ------------------------------- Providers -------------------------------- //

// Call Claude's Messages API. output_config.format pins the response to our JSON
// schema so the body is a guaranteed-shape JSON string. The
// anthropic-dangerous-direct-browser-access header opts into browser-origin
// requests (the popup is an extension page, not a server). Returns the raw text
// of the first content block, or null on any HTTP error.
async function callClaude(apiKey: string, model: string, input: AiInput): Promise<string | null> {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
      "anthropic-dangerous-direct-browser-access": "true",
    },
    body: JSON.stringify({
      model,
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: buildUserContent(input) }],
      output_config: {
        format: {
          type: "json_schema",
          schema: VERDICT_SCHEMA,
        },
      },
    }),
  });
  if (!res.ok) return null;

  const data: { content?: { type?: string; text?: string }[] } = await res.json();
  return data.content?.find((b) => b.type === "text")?.text ?? null;
}

// Call DeepSeek's OpenAI-compatible chat completions endpoint. response_format
// json_object enables JSON mode (the prompt already contains "json" + an
// example, as that mode requires). Returns the message content, or null on any
// HTTP error.
async function callDeepseek(apiKey: string, model: string, input: AiInput): Promise<string | null> {
  const res = await fetch("https://api.deepseek.com/chat/completions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      max_tokens: 1024,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: buildUserContent(input) },
      ],
    }),
  });
  if (!res.ok) return null;

  const data: { choices?: { message?: { content?: string } }[] } = await res.json();
  return data.choices?.[0]?.message?.content ?? null;
}

// JSON Schema for Claude's structured output. Kept within the supported subset
// (types + enum only; no numeric min/max, which structured outputs don't allow —
// the values are clamped on our side instead).
const VERDICT_SCHEMA = {
  type: "object",
  properties: {
    phishingProbability: { type: "integer" },
    socialEngineering: { type: "string", enum: ["low", "medium", "high"] },
    contentRiskScore: { type: "integer" },
    summary: { type: "string" },
  },
  required: ["phishingProbability", "socialEngineering", "contentRiskScore", "summary"],
  additionalProperties: false,
} as const;

// ------------------------------- Parsing ---------------------------------- //

// Clamp a value to an integer in 0–100. Non-numeric input falls back to 0.
function clampScore(value: unknown): number {
  const n = Math.round(Number(value));
  if (!Number.isFinite(n)) return 0;
  return Math.min(100, Math.max(0, n));
}

function normalizeLevel(value: unknown): SocialEngineeringLevel {
  const v = String(value).toLowerCase();
  return v === "high" || v === "medium" || v === "low" ? v : "low";
}

// Turn the model's raw text into a verdict. Tolerant of code fences and leading
// prose: it pulls out the first {...} block before parsing, then clamps every
// field into range so a stray value can't break the UI. Returns null when there's
// no usable JSON object.
function parseVerdict(text: string | null): AiVerdict | null {
  if (!text) return null;

  // Grab the outermost JSON object, ignoring any ```json fences or stray prose.
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end <= start) return null;

  let raw: unknown;
  try {
    raw = JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object") return null;

  const obj = raw as Record<string, unknown>;
  const summary = typeof obj.summary === "string" ? obj.summary.trim() : "";

  return {
    phishingProbability: clampScore(obj.phishingProbability),
    socialEngineering: normalizeLevel(obj.socialEngineering),
    contentRiskScore: clampScore(obj.contentRiskScore),
    summary,
  };
}

// -------------------------------- Entry ----------------------------------- //

// Analyze a page with the chosen provider and model. Resolves to a verdict on
// success or a message-key on failure ("ai_err_noKey" / "ai_err_request" /
// "ai_err_parse"), never throwing.
export async function analyzeWithAi(
  provider: AiProvider,
  apiKey: string,
  model: string,
  input: AiInput,
): Promise<AiResult> {
  if (!apiKey) return { ok: false, error: "ai_err_noKey" };

  let text: string | null;
  try {
    text =
      provider === "deepseek"
        ? await callDeepseek(apiKey, model, input)
        : await callClaude(apiKey, model, input);
  } catch {
    // Network failure, DNS, CORS, aborted request, etc.
    return { ok: false, error: "ai_err_request" };
  }
  if (text === null) return { ok: false, error: "ai_err_request" };

  const verdict = parseVerdict(text);
  if (!verdict) return { ok: false, error: "ai_err_parse" };
  return { ok: true, verdict };
}
