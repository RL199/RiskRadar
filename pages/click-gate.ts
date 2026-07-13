// Click-gate interstitial. When the link-click reputation scan runs in one of
// the wait modes (settings.linkClickScanMode "warn" or "block"), the
// background worker parks the tab here instead of letting the clicked site
// load. This page shows the same two rows the corner overlay shows (the
// clicked link and the final destination, passed in the query string), asks
// the worker to run the reputation checks (the clickgate-scan message), and
// then acts on the verdicts: a click that passes enters the site on its own;
// one that fails is offered behind a "Continue anyway" button in "warn" mode
// and refused outright in "block" mode. Before navigating, the destination is
// registered with the worker (the clickgate-approve message) so the resulting
// navigation is not sent back to this gate.

import { loadSettings, type Settings } from "../scripts/shared/settings";
import { applyTheme } from "../scripts/shared/theme";
import { applyI18n, loadMessages, type Dict } from "../scripts/shared/i18n";
import type { ClickScanStatus } from "../scripts/shared/click-scan";

// The worker's answer to a clickgate-scan message: one overlay-style status
// per judged URL ("start" is absent when the click never changed URL), or an
// error when the target could not be judged at all.
interface GateScanResponse {
  status: "ok" | "error";
  start?: ClickScanStatus;
  finish?: ClickScanStatus;
}

const titleEl = document.getElementById("title") as HTMLElement;
const noteEl = document.getElementById("note") as HTMLElement;
const rowsEl = document.getElementById("rows") as HTMLElement;
const backBtn = document.getElementById("back") as HTMLButtonElement;
const continueBtn = document.getElementById("continue") as HTMLButtonElement;

let dict: Dict = {};

// Dictionary lookup with the page's built-in English as the fallback, matching
// how the worker builds the overlay rows.
function msg(key: string, fallback: string): string {
  return dict[key] ?? fallback;
}

function verdictText(status: ClickScanStatus): string {
  switch (status) {
    case "good":
      return msg("verdict_safe", "Safe");
    case "warn":
      return msg("verdict_caution", "Caution");
    case "bad":
      return msg("verdict_danger", "Dangerous");
    default:
      return msg("val_unknown", "Unknown");
  }
}

// Draw one address line: its label, its hostname, and a spinner while the
// checks run or the verdict once they finish.
function renderRow(label: string, host: string, status: ClickScanStatus | null): HTMLElement {
  const row = document.createElement("div");
  row.className = "gate-row";
  const labelEl = document.createElement("span");
  labelEl.className = "gate-row__label";
  labelEl.textContent = label;
  const hostEl = document.createElement("span");
  hostEl.className = "gate-row__host";
  hostEl.textContent = host;
  row.append(labelEl, hostEl);
  if (status === null) {
    const spin = document.createElement("span");
    spin.className = "gate-spin";
    row.append(spin);
  } else {
    const verdict = document.createElement("span");
    verdict.className = `gate-row__verdict is-${status}`;
    verdict.textContent = verdictText(status);
    row.append(verdict);
  }
  return row;
}

function drawRows(start: URL | null, finish: URL, statuses: { start?: ClickScanStatus; finish?: ClickScanStatus } | null): void {
  const rows: HTMLElement[] = [];
  if (start) {
    rows.push(renderRow(msg("linkscan_start", "Clicked link"), start.hostname, statuses?.start ?? (statuses ? "unknown" : null)));
  }
  rows.push(renderRow(msg("linkscan_end", "Final destination"), finish.hostname, statuses ? statuses.finish ?? "unknown" : null));
  rowsEl.replaceChildren(...rows);
}

function parseHttpUrl(raw: string | null): URL | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === "http:" || url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}

// Leave the gate without entering the site. The worker swapped the gate into
// the checked site's history entry, so one step back lands on the page the
// click started from; a gate in a fresh tab (a middle-clicked link) has no
// history to return to, so its tab is closed instead.
async function goBack(): Promise<void> {
  if (history.length > 1) {
    history.back();
    return;
  }
  const tab = await chrome.tabs.getCurrent();
  if (typeof tab?.id === "number") await chrome.tabs.remove(tab.id);
}

// Enter the destination: register it with the worker first so the navigation
// is let through, then replace this gate's history entry with the site's.
async function enter(target: string): Promise<void> {
  backBtn.disabled = true;
  continueBtn.disabled = true;
  await chrome.runtime.sendMessage({ type: "clickgate-approve", url: target });
  location.replace(target);
}

function showError(): void {
  titleEl.textContent = msg("gate_error_title", "Couldn't check this link");
  noteEl.textContent = msg("gate_error_note", "This address could not be checked. You can go back to the previous page.");
}

async function init(): Promise<void> {
  const settings: Settings = await loadSettings();
  dict = await loadMessages(settings.lang);
  applyTheme(settings.theme);
  applyI18n(settings.lang, dict);

  backBtn.addEventListener("click", () => void goBack());

  const params = new URLSearchParams(location.search);
  // Navigate with the raw parameter string, not the parsed URL's re-serialized
  // form: the worker compares the approved URL to the committed one literally,
  // and the raw string is the committed URL it captured.
  const targetRaw = params.get("target");
  const finish = parseHttpUrl(targetRaw);
  if (!finish || targetRaw === null) {
    showError();
    return;
  }
  let start = parseHttpUrl(params.get("start"));
  if (start && start.href === finish.href) start = null;

  continueBtn.addEventListener("click", () => void enter(targetRaw));

  drawRows(start, finish, null);

  let response: GateScanResponse;
  try {
    response = (await chrome.runtime.sendMessage({
      type: "clickgate-scan",
      target: targetRaw,
      start: start ? start.href : undefined,
    })) as GateScanResponse;
  } catch {
    response = { status: "error" };
  }
  if (response?.status !== "ok" || !response.finish) {
    showError();
    return;
  }

  drawRows(start, finish, response);

  // "Not safe" mirrors the overlay's stays-on-screen rule: any warning or
  // risky verdict on either end of the click. Unknown never holds a site
  // hostage; with no keys configured every verdict can be unknown.
  const statuses = [response.finish, ...(response.start ? [response.start] : [])];
  const unsafe = statuses.some((s) => s === "warn" || s === "bad");

  if (!unsafe) {
    titleEl.textContent = msg("gate_safe_title", "The link passed the reputation check");
    noteEl.textContent = msg("gate_safe_note", "Taking you to the site…");
    await enter(targetRaw);
    return;
  }

  titleEl.textContent = msg("gate_unsafe_title", "This site failed the reputation check");
  if (settings.linkClickScanMode === "block") {
    noteEl.textContent = msg(
      "gate_block_note",
      "This website is blocked. Blocking unsafe sites is turned on in the settings, so Risk Radar will not open it.",
    );
  } else {
    noteEl.textContent = msg(
      "gate_warn_note",
      "You can go back to safety, or continue to the site at your own risk.",
    );
    continueBtn.hidden = false;
  }
}

void init();
