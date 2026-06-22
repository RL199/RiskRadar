import type { ThemePref } from "./settings";

// Resolves the theme preference (honoring the OS setting for "system") and
// applies it via a data-theme attribute that the CSS variables key off of.
export function applyTheme(theme: ThemePref): void {
  const resolved =
    theme === "system"
      ? window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark"
      : theme;
  document.documentElement.dataset.theme = resolved;
}
