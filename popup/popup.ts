// Popup entry point. Compiled to popup.js by esbuild and loaded from popup.html.

async function getActiveTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

async function init(): Promise<void> {
  const status = document.getElementById("status");
  if (!status) return;

  const tab = await getActiveTab();
  if (!tab?.url) {
    status.textContent = "No page to analyze.";
    return;
  }

  // Placeholder until the scoring pipeline is implemented.
  const { hostname } = new URL(tab.url);
  status.textContent = `Ready to analyze ${hostname}`;
}

init();
