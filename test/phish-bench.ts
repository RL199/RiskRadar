// Offline benchmark of RiskRadar's URL judgement against real phishing feeds.
//
// It runs the exact code the extension ships: classifyAddressBarUrl() from
// scripts/shared/link-analysis (the heuristics behind the typed URL guard and
// the on page link marks) plus the same Phishing.Database ACTIVE domains list
// the background worker caches. A URL counts as "caught" when the guard would
// warn or block it, that is when the heuristics call it suspicious/redirect or
// its host is on the blocklist.
//
// Data sources (all free, fetched on demand and cached for a day under
// test/data/):
//   phishing  OpenPhish feed        https://openphish.com/feed.txt
//             Phishing.Database     phishing-links-ACTIVE.txt (streamed)
//             or any local file     one URL per line, or a PhishTank CSV
//   benign    Tranco top sites      https://tranco-list.eu (research ranking)
//             or any local file     one domain or URL per line
//
// Usage (from the repo root):
//   npm run bench:phish                          OpenPhish vs Tranco top 10k
//   npm run bench:phish -- --phish phishdb       Phishing.Database URL sample
//   npm run bench:phish -- --phish tank.csv      a downloaded PhishTank CSV
//   npm run bench:phish -- --benign none         skip the false positive half
//   npm run bench:phish -- --refresh             redownload cached feeds
//   npm run bench:phish -- --json                machine readable summary
//
// Interpreting the numbers: the heuristics are deliberately tuned for a low
// false positive rate (a stated project goal), so they alone are not expected
// to catch most phishing URLs; the blocklist provides the authoritative bulk.
// Note the circularity trap: when the phishing set is phishdb, the blocklist
// rate is near 100% by construction and only the heuristic rate is meaningful.

import { mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { classifyAddressBarUrl } from "../scripts/shared/link-analysis";
import { splitDomain } from "../scripts/shared/url-analysis";

const OPENPHISH_URL = "https://openphish.com/feed.txt";
const PHISHDB_LINKS_URL =
  "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt";
// Same file the background worker downloads daily (see background.ts).
const BLOCKLIST_URL =
  "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
const TRANCO_LATEST_API = "https://tranco-list.eu/api/lists/date/latest";

const DATA_DIR = join(process.cwd(), "test", "data");
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // mirror the extension's daily refresh

// Human labels for the reason keys classifyLink emits (see _locales for the
// user facing wording; these are for the report only).
const REASON_LABELS: Record<string, string> = {
  reason_link_redirectParam: "redirect parameter to another domain",
  reason_link_credentials: "credentials embedded in the URL",
  reason_link_ip: "IP address host",
  reason_link_punycode: "punycode host",
  reason_link_lookalike: "brand look-alike host",
  reason_link_shortener: "URL shortener",
  reason_link_manySub: "deeply nested subdomains",
  reason_link_keyword: "stacked phishing keywords",
};

// ------------------------------ CLI options ------------------------------- //

interface Options {
  phish: string; // "openphish" | "phishdb" | file path
  benign: string; // "tranco" | "none" | file path
  benignCount: number;
  limit: number; // 0 = no cap
  blocklist: boolean;
  refresh: boolean;
  json: boolean;
}

function parseArgs(argv: string[]): Options {
  const opts: Options = {
    phish: "openphish",
    benign: "tranco",
    benignCount: 10_000,
    limit: 0,
    blocklist: true,
    refresh: false,
    json: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--phish": opts.phish = argv[++i] ?? opts.phish; break;
      case "--benign": opts.benign = argv[++i] ?? opts.benign; break;
      case "--benign-count": opts.benignCount = Number(argv[++i]) || opts.benignCount; break;
      case "--limit": opts.limit = Number(argv[++i]) || 0; break;
      case "--no-blocklist": opts.blocklist = false; break;
      case "--refresh": opts.refresh = true; break;
      case "--json": opts.json = true; break;
      default: throw new Error(`Unknown argument: ${arg}`);
    }
  }
  // The full Phishing.Database links file is ~65 MB; sample it by default.
  if (opts.phish === "phishdb" && opts.limit === 0) opts.limit = 20_000;
  return opts;
}

// ------------------------------ Downloading -------------------------------- //

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

// Stream a large text file and keep only the first maxLines lines, then hang
// up, so sampling the 65 MB Phishing.Database links file stays cheap.
async function fetchFirstLines(url: string, maxLines: number): Promise<string> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok || !res.body) throw new Error(`${url}: HTTP ${res.status}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const lines: string[] = [];
  let buf = "";
  while (lines.length < maxLines) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0 && lines.length < maxLines) {
      lines.push(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
    }
  }
  await reader.cancel().catch(() => undefined);
  if (lines.length < maxLines && buf.trim()) lines.push(buf);
  return lines.join("\n");
}

// Fetch through a small on disk cache so repeated runs don't hammer the feeds.
async function cached(name: string, refresh: boolean, load: () => Promise<string>): Promise<string> {
  const file = join(DATA_DIR, name);
  if (!refresh) {
    try {
      const info = await stat(file);
      if (Date.now() - info.mtimeMs < CACHE_TTL_MS) return await readFile(file, "utf8");
    } catch {
      // no cache yet
    }
  }
  const text = await load();
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(file, text, "utf8");
  return text;
}

// ------------------------------ Input parsing ------------------------------ //

// Minimal CSV field splitter (quoted fields, doubled quote escapes), enough
// for the PhishTank export.
function csvFields(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else quoted = false;
      } else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

// Pull URLs out of feed text: one URL per line, or a CSV with a "url" column
// (the PhishTank format).
function parseUrlList(text: string, isCsv: boolean): string[] {
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (lines.length === 0) return [];
  if (isCsv) {
    const header = csvFields(lines[0].toLowerCase());
    const urlCol = header.indexOf("url");
    if (urlCol >= 0) {
      return lines.slice(1).map((l) => csvFields(l)[urlCol] ?? "").filter((u) => /^https?:\/\//i.test(u));
    }
  }
  return lines.filter((l) => /^https?:\/\//i.test(l));
}

// Benign inputs may be bare domains (Tranco: "rank,domain") or full URLs.
function parseBenignList(text: string): string[] {
  const urls: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (/^https?:\/\//i.test(line)) { urls.push(line); continue; }
    const domain = line.includes(",") ? line.slice(line.indexOf(",") + 1).trim() : line;
    if (domain && !domain.includes("/")) urls.push(`https://${domain}/`);
  }
  return urls;
}

async function loadPhishingUrls(opts: Options): Promise<{ label: string; urls: string[] }> {
  if (opts.phish === "openphish") {
    const text = await cached("openphish-feed.txt", opts.refresh, () => fetchText(OPENPHISH_URL));
    return { label: "OpenPhish feed", urls: parseUrlList(text, false) };
  }
  if (opts.phish === "phishdb") {
    const text = await cached(`phishdb-links-${opts.limit}.txt`, opts.refresh, () =>
      fetchFirstLines(PHISHDB_LINKS_URL, opts.limit),
    );
    return { label: "Phishing.Database active links (sample)", urls: parseUrlList(text, false) };
  }
  const text = await readFile(opts.phish, "utf8");
  return {
    label: opts.phish,
    urls: parseUrlList(text, extname(opts.phish).toLowerCase() === ".csv"),
  };
}

async function loadBenignUrls(opts: Options): Promise<{ label: string; urls: string[] } | null> {
  if (opts.benign === "none") return null;
  if (opts.benign === "tranco") {
    const text = await cached(`tranco-top-${opts.benignCount}.csv`, opts.refresh, async () => {
      const meta = JSON.parse(await fetchText(TRANCO_LATEST_API)) as { list_id?: string };
      if (!meta.list_id) throw new Error("Tranco API returned no list_id");
      return fetchText(`https://tranco-list.eu/download/${meta.list_id}/${opts.benignCount}`);
    });
    return { label: `Tranco top ${opts.benignCount} sites`, urls: parseBenignList(text) };
  }
  const text = await readFile(opts.benign, "utf8");
  return { label: opts.benign, urls: parseBenignList(text) };
}

async function loadBlocklist(opts: Options): Promise<Set<string> | null> {
  if (!opts.blocklist) return null;
  const text = await cached("phishing-domains-ACTIVE.txt", opts.refresh, () => fetchText(BLOCKLIST_URL));
  // Same parsing the background worker applies (parseDomains in background.ts).
  const set = new Set<string>();
  for (const raw of text.split("\n")) {
    const line = raw.trim().toLowerCase();
    if (line && !line.startsWith("#")) set.add(line);
  }
  return set;
}

// -------------------------------- Evaluation ------------------------------- //

// Same two lookups the background worker's listedAmong() performs: the host
// itself, then its registrable domain (a listed domain covers its subdomains).
function isListed(host: string, blocklist: Set<string>): boolean {
  const h = host.toLowerCase();
  const { registrable } = splitDomain(h);
  return blocklist.has(h) || (registrable !== h && blocklist.has(registrable));
}

interface SetReport {
  label: string;
  evaluated: number;
  skipped: number;
  heuristic: number;
  listed: number;
  either: number;
  reasons: Record<string, number>;
  samples: string[]; // misses for the phishing set, hits for the benign set
}

function evaluate(label: string, urls: string[], blocklist: Set<string> | null, collectMisses: boolean): SetReport {
  const report: SetReport = {
    label,
    evaluated: 0,
    skipped: 0,
    heuristic: 0,
    listed: 0,
    either: 0,
    reasons: {},
    samples: [],
  };
  const seen = new Set<string>();
  for (const url of urls) {
    if (seen.has(url)) continue;
    seen.add(url);

    const cl = classifyAddressBarUrl(url);
    if (cl.verdict === "ignore") { report.skipped++; continue; }
    report.evaluated++;

    const heurFlag = cl.verdict === "suspicious" || cl.verdict === "redirect";
    const host = new URL(url).hostname;
    const listedFlag = blocklist ? isListed(host, blocklist) : false;

    if (heurFlag) {
      report.heuristic++;
      const reason = REASON_LABELS[cl.reasonKey ?? ""] ?? cl.reasonKey ?? "other";
      report.reasons[reason] = (report.reasons[reason] ?? 0) + 1;
    }
    if (listedFlag) report.listed++;
    if (heurFlag || listedFlag) {
      report.either++;
      // For the benign set the interesting samples are the false positives.
      if (!collectMisses && report.samples.length < 15) {
        const reason = listedFlag ? "on the phishing blocklist" : REASON_LABELS[cl.reasonKey ?? ""] ?? "";
        report.samples.push(`${host}  (${reason})`);
      }
    } else if (collectMisses && report.samples.length < 10) {
      report.samples.push(url.length > 100 ? `${url.slice(0, 100)}...` : url);
    }
  }
  return report;
}

// --------------------------------- Report ---------------------------------- //

function pct(n: number, d: number): string {
  return d === 0 ? "n/a" : `${((100 * n) / d).toFixed(1)}%`;
}

function printSet(r: SetReport, kind: "phishing" | "benign"): void {
  const d = r.evaluated;
  console.log(`\n${kind === "phishing" ? "Phishing detection" : "Benign false positives"}: ${r.label}`);
  console.log(`  evaluated            ${d} URLs (${r.skipped} skipped: unparseable or non http)`);
  console.log(`  heuristics flagged   ${r.heuristic} (${pct(r.heuristic, d)})`);
  if (r.listed || r.either !== r.heuristic) {
    console.log(`  blocklist flagged    ${r.listed} (${pct(r.listed, d)})`);
    console.log(`  either (guard fires) ${r.either} (${pct(r.either, d)})`);
  }
  if (kind === "phishing") console.log(`  missed               ${d - r.either} (${pct(d - r.either, d)})`);

  const reasons = Object.entries(r.reasons).sort((a, b) => b[1] - a[1]);
  if (reasons.length) {
    console.log("  heuristic reasons:");
    for (const [reason, count] of reasons) console.log(`    ${String(count).padStart(6)}  ${reason}`);
  }
  if (r.samples.length) {
    console.log(kind === "phishing" ? "  sample missed URLs:" : "  flagged benign hosts:");
    for (const s of r.samples) console.log(`    ${s}`);
  }
}

// ---------------------------------- Main ----------------------------------- //

const opts = parseArgs(process.argv.slice(2));

const [phish, benign, blocklist] = await Promise.all([
  loadPhishingUrls(opts),
  loadBenignUrls(opts),
  loadBlocklist(opts),
]);

const phishUrls = opts.limit > 0 ? phish.urls.slice(0, opts.limit) : phish.urls;
const phishReport = evaluate(phish.label, phishUrls, blocklist, true);
const benignReport = benign ? evaluate(benign.label, benign.urls, blocklist, false) : null;

if (opts.json) {
  console.log(JSON.stringify({ phishing: phishReport, benign: benignReport }, null, 2));
} else {
  console.log("RiskRadar phishing benchmark (classifyAddressBarUrl + Phishing.Database blocklist)");
  console.log(blocklist ? `Blocklist: ${blocklist.size} active phishing domains` : "Blocklist: disabled (--no-blocklist)");
  if (opts.phish === "phishdb" && blocklist) {
    console.log("Note: this phishing set and the blocklist share a source, so the blocklist");
    console.log("rate is close to 100% by construction; only the heuristic rate is informative.");
  }
  printSet(phishReport, "phishing");
  if (benignReport) printSet(benignReport, "benign");
  console.log("");
}
