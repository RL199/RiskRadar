// Trust score (1-100). Collapses the popup's five category verdicts into one
// headline number using a weighted average with hard caps ("Option D"):
//
//   1. base  = weighted average of the determinate category verdicts, with the
//              weights renormalized over whichever categories actually ran.
//   2. caps  = a confirmed-malicious signal pins the score deep in the red; a
//              strong phishing heuristic holds it no higher than the warning
//              band, regardless of how many other checks came back clean.
//
// The weighted average rewards a site that passes a breadth of checks, while the
// caps preserve the security guarantee of a worst-of roll-up: a single
// authoritative blocklist hit (or a cleartext credential form) can never be
// averaged away into a green score.

import type { RowStatus } from "./url-analysis";

export type SiteCategory = "url" | "reputation" | "content" | "links" | "ai";

// Per-category weight for the weighted average. Reputation dominates (it is the
// only category backed by authoritative threat intelligence), the AI model and
// page content come next, the URL's own structure is a lighter structural hint,
// and outbound links are the lightest signal. Weights need not sum to 1: the
// score divides by the total weight of the categories that actually ran, so a
// missing category (AI not run, or an unknown verdict) never skews the result.
export const CATEGORY_WEIGHTS: Record<SiteCategory, number> = {
  reputation: 0.4,
  ai: 0.2,
  content: 0.2,
  url: 0.15,
  links: 0.05,
};

// A determinate verdict's 0-100 contribution to the average. unknown/neutral
// return null so the caller leaves them out of the average entirely (rather than
// counting an un-run check as either safe or risky).
export function verdictPoints(status: RowStatus): number | null {
  switch (status) {
    case "good":
      return 100;
    case "warn":
      return 55;
    case "bad":
      return 10;
    default:
      return null; // unknown | neutral
  }
}

// Tiered signals that trigger the hard caps. Set by the category that detected
// them, independent of that category's averaged verdict, so a single critical
// finding caps the whole score.
export interface ScoreFlags {
  // A confirmed-malicious signal: an authoritative blocklist/malware hit
  // (Safe Browsing, VirusTotal, Sucuri, Phishing Database, a DNS sinkhole) or a
  // password form that submits credentials in cleartext.
  definitive?: boolean;
  // A strong phishing heuristic: a raw-IP host, a brand-new domain, brand
  // impersonation on a credential page, or the AI rating the page high-risk.
  strong?: boolean;
}

export interface ScoreInput {
  status: RowStatus;
  flags?: ScoreFlags;
}

// Score bands reuse the same warn/bad thirds the per-row statuses use, so the
// headline number and the category chips never disagree about colour.
export type ScoreBand = "good" | "warn" | "bad";

export interface TrustScore {
  score: number; // 1-100
  band: ScoreBand;
}

// A confirmed-malicious signal pins the score here (deep red); a strong phishing
// heuristic holds it no higher than this (top of the warning band).
export const DEFINITIVE_CAP = 15;
export const STRONG_CAP = 49;

export function scoreBand(score: number): ScoreBand {
  return score >= 67 ? "good" : score >= 34 ? "warn" : "bad";
}

// Collapse the per-category inputs into one 1-100 trust score. Returns null when
// nothing determinate ran (every category unknown/neutral), so the caller can
// show a muted "can't score this page" state instead of a misleading number.
export function computeTrustScore(
  inputs: Partial<Record<SiteCategory, ScoreInput>>,
): TrustScore | null {
  let weighted = 0;
  let totalWeight = 0;
  let definitive = false;
  let strong = false;

  for (const [category, input] of Object.entries(inputs) as [SiteCategory, ScoreInput][]) {
    // Caps apply regardless of whether this category contributed to the average,
    // so a critical finding still caps even on an otherwise-excluded category.
    if (input.flags?.definitive) definitive = true;
    if (input.flags?.strong) strong = true;

    const points = verdictPoints(input.status);
    if (points === null) continue;
    const weight = CATEGORY_WEIGHTS[category];
    weighted += points * weight;
    totalWeight += weight;
  }

  if (totalWeight === 0) return null;

  let score = weighted / totalWeight;
  if (definitive) score = Math.min(score, DEFINITIVE_CAP);
  else if (strong) score = Math.min(score, STRONG_CAP);

  score = Math.max(1, Math.min(100, Math.round(score)));
  return { score, band: scoreBand(score) };
}
