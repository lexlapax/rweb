# rweb logo

A prompt in a window: a dark rounded tile with a white `›` chevron and a green block cursor. The logo is
the project's own and is covered by its [MIT licence](../../LICENSE).

## Files

| File | Use |
| --- | --- |
| `icon.svg` | The app icon, 48 px and larger. |
| `icon-small.svg` | The same mark drawn for 16 to 32 px: no window dots, heavier chevron and cursor. Favicons and the page header. |
| `icon-square.svg` | `icon.svg` without the rounded tile, full-bleed, for platforms that round the corners themselves (the apple-touch-icon). |
| `icon-maskable.svg` | The mark at 80 %, inside the central safe zone, on a full-bleed tile colour: Android's maskable icon. |
| `icon-mono.svg`, `icon-mono-light.svg` | One colour: white on `#181818`, and `#181818` on white. For places that cannot show the accent. |
| `wordmark.svg`, `wordmark-light.svg` | The name alone: light letters for dark backgrounds, dark letters for light ones. |
| `lockup.svg`, `lockup-light.svg` | Icon and name side by side, for dark and light backgrounds (the README's heading). |
| `social-preview.png` | 1280 × 640: the lockup centred on `#181818`, for the repository's social preview. |
| `png/icon-16.png`, `png/icon-32.png`, `png/icon-48.png` | The favicon's three sizes (16 and 32 from `icon-small.svg`, 48 from `icon.svg`). |
| `build.sh`, `ico.py` | Export every raster from the SVGs (see below). |

The page serves its icons from [`src/bridge/web/icons/`](../../src/bridge/web/icons/): `favicon.svg`
(a copy of `icon-small.svg`), `favicon.ico` (16, 32 and 48 px), `apple-touch-icon.png` (180 px),
`icon-192.png`, `icon-512.png` and `icon-maskable-512.png`, named by
[`manifest.webmanifest`](../../src/bridge/web/manifest.webmanifest).

## Colours

| Role | Hex |
| --- | --- |
| Tile | `#181818` |
| Foreground (chevron, letters on dark) | `#ececec` |
| Accent (cursor) | `#3fb950` |
| Tile edge | `#2e2e2e` |
| Window dots | `#474747` |

Do not recolour the logo. The only other colourings are the monochrome variants, `icon-mono.svg` and
`icon-mono-light.svg`, and the light wordmark and lockup, whose letters are `#181818`.

## Size and spacing

- Minimum sizes: `icon-small.svg` 16 px; `icon.svg` 48 px (below that, use `icon-small.svg`); the
  wordmark 16 px tall; the lockup 24 px tall.
- Clear space: keep empty space around the logo at least a quarter of the icon's height on every side
  (128 px for the 512 px icon, 32 px around a 128 px tall lockup). Nothing else goes inside it.
- Scale it evenly; do not stretch, rotate, outline or add effects.

## Rebuilding the rasters

```sh
assets/logo/build.sh
```

It draws each SVG at its exact pixel size with headless Google Chrome (scale factor 1, transparent
background except the social preview), checks each image's size with `sips`, and builds `favicon.ico`
with `ico.py` (PNG entries; Python standard library only). It needs macOS with Chrome installed
(`CHROME=/path/to/chrome` for another one); the same Chrome gives byte-identical files. Run it after
changing any SVG and commit the results with it.
