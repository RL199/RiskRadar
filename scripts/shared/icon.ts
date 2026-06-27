// Recolours the toolbar action icon to match a trust-score band, so the icon in
// the toolbar reflects the same verdict colour the popup shows: green for a good
// score, amber for caution, red for danger.
//
// The packaged icons are the green radar shield. Rather than ship a separate set
// of coloured PNGs (or re-rasterise the SVG, which createImageBitmap cannot do in
// a service worker), each opaque pixel of the green PNG is hue-shifted to the
// band's hue at runtime, keeping its saturation, lightness and transparency. That
// preserves the shield's shading and the radar sweep while changing only the hue.
// PNG decoding via createImageBitmap works in both the popup (a document) and the
// background service worker, so this one helper serves both callers.

// The trust-score bands that map onto a colour. "good" reuses the icon's own
// green, so it (and the no-score reset) just restores the packaged icon.
export type IconBand = "good" | "warn" | "bad";

// Sizes Chrome may request for the toolbar; supplying all four keeps the icon
// crisp across display densities.
const SIZES = [16, 32, 48, 128] as const;

// Path to each packaged green icon, also used to restore the default appearance.
const DEFAULT_PATHS: Record<number, string> = Object.fromEntries(
  SIZES.map((size) => [size, `assets/icons/icon-${size}.png`]),
);

// Target hue (HSL degrees) for the bands that differ from the native green. Amber
// sits at ~38 and red at 0, matching the popup's --amber / --red status colours.
const BAND_HUE: Record<"warn" | "bad", number> = {
  warn: 38,
  bad: 0,
};

// The source PNGs never change, so each band's recoloured ImageData set is
// computed once and reused for every later paint.
const recolourCache = new Map<string, Record<number, ImageData>>();

function hue2rgb(p: number, q: number, t: number): number {
  if (t < 0) t += 1;
  if (t > 1) t -= 1;
  if (t < 1 / 6) return p + (q - p) * 6 * t;
  if (t < 1 / 2) return q;
  if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
  return p;
}

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  if (s === 0) {
    const v = Math.round(l * 255);
    return [v, v, v];
  }
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  return [
    Math.round(hue2rgb(p, q, h + 1 / 3) * 255),
    Math.round(hue2rgb(p, q, h) * 255),
    Math.round(hue2rgb(p, q, h - 1 / 3) * 255),
  ];
}

// Shift every opaque pixel to `hue` (0-360), keeping its saturation, lightness
// and alpha. Recolours the green artwork to amber/red without flattening its
// shading; near-grey edge pixels (low saturation) stay neutral.
function shiftHue(image: ImageData, hue: number): void {
  const px = image.data;
  const h = hue / 360;
  for (let i = 0; i < px.length; i += 4) {
    if (px[i + 3] === 0) continue; // fully transparent: nothing to recolour
    const r = px[i] / 255;
    const g = px[i + 1] / 255;
    const b = px[i + 2] / 255;
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const l = (max + min) / 2;
    const d = max - min;
    const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
    const [nr, ng, nb] = hslToRgb(h, s, l);
    px[i] = nr;
    px[i + 1] = ng;
    px[i + 2] = nb;
  }
}

// Build (or reuse) the hue-shifted icon set for a band, one ImageData per size.
async function recolouredIcon(band: "warn" | "bad"): Promise<Record<number, ImageData>> {
  const cached = recolourCache.get(band);
  if (cached) return cached;

  const set: Record<number, ImageData> = {};
  for (const size of SIZES) {
    const res = await fetch(chrome.runtime.getURL(DEFAULT_PATHS[size]));
    const bitmap = await createImageBitmap(await res.blob());
    const canvas = new OffscreenCanvas(size, size);
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) {
      bitmap.close();
      continue;
    }
    ctx.drawImage(bitmap, 0, 0, size, size);
    bitmap.close();
    const image = ctx.getImageData(0, 0, size, size);
    shiftHue(image, BAND_HUE[band]);
    set[size] = image;
  }
  recolourCache.set(band, set);
  return set;
}

// Paint the toolbar icon for one tab to match a trust-score band: amber for
// "warn", red for "bad", and the packaged green icon for "good" or when there is
// no score yet (band null). Failures are swallowed, so a closed tab just keeps
// whatever icon it had.
export async function setActionIcon(tabId: number, band: IconBand | null): Promise<void> {
  try {
    if (band === "warn" || band === "bad") {
      await chrome.action.setIcon({ tabId, imageData: await recolouredIcon(band) });
    } else {
      await chrome.action.setIcon({ tabId, path: DEFAULT_PATHS });
    }
  } catch {
    // Tab closed mid-scan, or the icon could not be set: keep the current icon.
  }
}
