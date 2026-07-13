// Link-click reputation overlay. When "Check the reputation of links I click" is on
// (settings.linkClickScan), the background worker judges both ends of a link
// click, the URL the click started from and the URL it finally landed on, with
// the same reputation checks the popup's Reputation view runs. This module
// holds the small JSON payload the worker builds and the self-contained
// overlay renderer it injects into the tab (chrome.scripting.executeScript),
// following the same pattern as the injected helpers in link-analysis.ts.

// One scanned URL's state: "loading" while its checks are in flight, then the
// reputation category's verdict.
export type ClickScanStatus = "loading" | "good" | "warn" | "bad" | "unknown";

// One line of the overlay. Every text arrives already localized (the worker
// owns the dictionary), so the injected renderer stays free of i18n.
export interface ClickScanRow {
  // "Clicked link" / "Final destination" label.
  label: string;
  // The hostname being judged, shown beside the label.
  host: string;
  status: ClickScanStatus;
  // Verdict text ("Safe", "Caution"...); empty while loading.
  text: string;
}

export interface ClickScanPayload {
  title: string;
  // Accessible label for the close button.
  close: string;
  // Text direction of the localized texts; also picks which page corner the
  // overlay sits in.
  dir: "ltr" | "rtl";
  // True once every check has finished. A finished overlay with nothing
  // suspicious hides itself after a few seconds; one with a warning or a risky
  // verdict stays until closed.
  done: boolean;
  rows: ClickScanRow[];
}

// Injected into the tab to draw or update the overlay in the corner of the
// page. Runs in the extension's isolated world and must be fully
// self-contained: it touches only the DOM. The overlay lives in a shadow root
// so page CSS can't restyle it, and repeated injections (the loading state,
// then the verdicts, or a fresh click) replace the previous content in place.
export function renderClickScanOverlay(payload: ClickScanPayload): void {
  const HOST_ID = "riskradar-clickscan";
  const AUTO_HIDE_MS = 6000;
  // Status colours, mirroring the auto-scan badge palette in background.ts.
  const COLORS: Record<ClickScanStatus, string> = {
    good: "#16a34a",
    warn: "#d97706",
    bad: "#dc2626",
    unknown: "#6b7280",
    loading: "#6b7280",
  };

  const existing = document.getElementById(HOST_ID);
  // A pending auto-hide belongs to the previous render; a new one is armed
  // below if this render calls for it.
  if (existing?.dataset.hideTimer) {
    clearTimeout(Number(existing.dataset.hideTimer));
    delete existing.dataset.hideTimer;
  }
  const host = existing ?? document.createElement("div");
  if (!existing) {
    host.id = HOST_ID;
    host.style.position = "fixed";
    host.style.bottom = "16px";
    host.style.zIndex = "2147483647";
    host.attachShadow({ mode: "open" });
    (document.body ?? document.documentElement).appendChild(host);
  }
  // Bottom right for LTR, bottom left for RTL.
  host.style.right = payload.dir === "rtl" ? "" : "16px";
  host.style.left = payload.dir === "rtl" ? "16px" : "";

  const root = host.shadowRoot;
  if (!root) return;
  root.replaceChildren();

  const style = document.createElement("style");
  style.textContent = [
    '.card{min-width:260px;max-width:340px;padding:12px 14px;border:1px solid rgba(255,255,255,.14);',
    "border-radius:12px;background:#161b22;color:#e6edf3;box-shadow:0 8px 28px rgba(0,0,0,.45);",
    'font:12.5px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}',
    ".head{display:flex;align-items:center;gap:8px;margin-bottom:8px}",
    ".title{flex:1;font-weight:600}",
    ".close{flex:none;padding:2px 6px;border:0;border-radius:6px;background:transparent;",
    "color:#8b949e;font-size:14px;line-height:1;cursor:pointer}",
    ".close:hover{background:rgba(255,255,255,.08);color:#e6edf3}",
    ".row{display:flex;align-items:center;gap:7px;padding:3px 0}",
    ".dot{flex:none;width:8px;height:8px;border-radius:50%}",
    ".spin{flex:none;width:9px;height:9px;border-radius:50%;border:2px solid rgba(255,255,255,.2);",
    "border-top-color:#e6edf3;animation:rr-spin .8s linear infinite}",
    ".label{flex:none;color:#8b949e}",
    ".host{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr}",
    ".verdict{margin-inline-start:auto;flex:none;font-weight:600}",
    "@keyframes rr-spin{to{transform:rotate(1turn)}}",
  ].join("");
  root.appendChild(style);

  const card = document.createElement("div");
  card.className = "card";
  card.dir = payload.dir;

  const head = document.createElement("div");
  head.className = "head";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = payload.title;
  const close = document.createElement("button");
  close.className = "close";
  close.type = "button";
  close.textContent = "✕";
  close.title = payload.close;
  close.setAttribute("aria-label", payload.close);
  close.addEventListener("click", () => host.remove());
  head.append(title, close);
  card.appendChild(head);

  for (const row of payload.rows) {
    const line = document.createElement("div");
    line.className = "row";
    const marker = document.createElement("span");
    if (row.status === "loading") {
      marker.className = "spin";
    } else {
      marker.className = "dot";
      marker.style.background = COLORS[row.status];
    }
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = row.label;
    const hostName = document.createElement("span");
    hostName.className = "host";
    hostName.textContent = row.host;
    const verdict = document.createElement("span");
    verdict.className = "verdict";
    verdict.textContent = row.text;
    verdict.style.color = COLORS[row.status];
    line.append(marker, label, hostName, verdict);
    card.appendChild(line);
  }

  root.appendChild(card);

  // A clean finished check dismisses itself; anything suspicious stays until
  // the user closes it.
  if (payload.done && !payload.rows.some((r) => r.status === "bad" || r.status === "warn")) {
    const timer = window.setTimeout(() => host.remove(), AUTO_HIDE_MS);
    host.dataset.hideTimer = String(timer);
  }
}
