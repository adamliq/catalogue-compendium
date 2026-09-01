# catalogue-compendium

A single entry point for [`Winevent-catalogue`](https://github.com/adamliq/Winevent-catalogue)
(4,737 Windows Event Log events),
[`linuxevent-catalogue`](https://github.com/adamliq/linuxevent-catalogue)
(77 Linux security/system events), and
[`Threat-detection-library`](https://github.com/adamliq/Threat-detection-library)
(4,017 platform-specific threat detections across fourteen catalogues),
merged into one self-contained web app with a menu to switch between them.

## Web lookup

`index.html` is a single, self-contained page (no build step) — open it
directly in a browser. A menu bar at the top switches between **Windows
Events**, **Linux Events**, **Threat Detection**, and **Search**; the first
three are the exact lookup tool from their source repo (search, filters,
detail views, reference tables, and so on), running independently side by
side on the same page. Your last-chosen tab is remembered (`localStorage`)
across visits.

**Search** is a fourth, compendium-only pill: a single box that searches
Windows events, Linux events, and every Threat Detection entry (detections
and validations) at once, grouped by source with up to 40 results per
source. It's a thin layer on top of the three apps, not a fourth schema —
each app exposes a small `{items, open}` index (id, title, a short meta
line, and a lowercased haystack of its own already-existing fields) on
`window.__compHub` for this to search over; clicking a result switches to
that catalogue's own tab and calls back into its own existing
selection/detail-opening code (`jumpToEvent`-style for Windows/Linux,
`openDetail`/`openValidationDetail` for Threat Detection) to actually show
it there — so results render exactly like they do from that app's own
search, because they *are* that app's own render path.

The three catalogues are **not** merged at the data level: they keep their
own ID schemes, column schemas, and reference tables exactly as authored in
their source repos (see each repo's README for the full field reference).
This page only merges the *presentation* — one URL, one menu — not the
underlying schemas.

The Threat Detection tab's **Heat Coverage** sub-tab fetches its eleven
`mitre-attack-*.json` files at runtime (from `threat-detection/data/`, see
below) rather than embedding them — the one place this page isn't fully
"no external requests." Like the source repo, it degrades gracefully under
`file://` (browsers block `fetch()` of local files) with an explanatory
message; serve the repo over http(s) (GitHub Pages, `python3 -m http.server`,
etc.) for that sub-tab specifically. Everything else, including the other
4,017 detections, works identically either way.

### How the merge was built

All three source `index.html` files embed their app (styles, markup, data)
in one file, and reuse a lot of the same generic naming (`.panel`, `.card`,
`.tab`, ids like `search`/`list`/`detail`/`tabs`, etc.) — Winevent-catalogue
and linuxevent-catalogue deliberately share UI conventions, and
Threat-detection-library independently converges on the same common
patterns. Concatenating them naively would collide: matching CSS selectors
would bleed across apps, and shared `id="..."` values would make
`getElementById` return the wrong app's element.

So each app was mechanically namespaced before merging:

- Every element `id`/`for` gets a `win-`/`lnx-`/`td-` prefix (covering
  static HTML attributes and every dynamic `getElementById`/`querySelector`
  reference, including ones built via string concatenation or template
  literals — and, for Threat-detection-library, the `id="..."` on each of
  its 19 `<script type="application/json">` data blobs).
- Each app's `<style>` block is scoped by rewriting every selector to be a
  descendant of that app's own container (`#app-win` / `#app-lnx` /
  `#app-td`), including `:root` and `html`/`body` (so each app's CSS custom
  properties/theme variables stay independent, and compound selectors like
  `body.heat-active .search-wrap` still hit the right element once `body`
  becomes the container).
- Each app's script runs inside its own IIFE (so top-level `const`/`let`/
  `function` names in one app never collide with another's), and every
  `document.querySelector(All)` call is scoped to that app's own container
  element — otherwise a class-based query like `.panel` (used by more than
  one app's tab-switching logic) would also match and mutate *another*
  app's hidden DOM.
- The handful of functions invoked from inline `onclick="..."` attributes
  (which run in global scope, not inside the IIFE) are renamed and
  explicitly exported on `window` under their namespaced names.
- Threat-detection-library specifically: its dark/light theme toggle
  operates on the real `<html>`/`<body>` elements
  (`document.documentElement.setAttribute("data-theme", …)`,
  `document.body.classList.toggle("heat-active", …)`) — since this repo
  rescopes `:root`/`body` to `#app-td`, those calls are redirected to the
  container element too, or the toggle (and the Heat/Validations
  view-mode classes) would silently do nothing. Its eleven
  `data/mitre-attack-*.json` fetch paths are also repointed at
  `threat-detection/data/…` to match this repo's layout (see Structure).

Every app's script, and the merged file as a whole, was verified with
`node --check` and exercised end-to-end in headless Chromium (search,
filters, detail views, reference tables, combo boxes, the auditd/
fapolicyd subpanels, the Windows schema-explorer field modal, cross-link
jump buttons, dark-mode theming, the Threat Detection Heat Coverage
matrix and Validations tab, and repeated tab-switching in every direction)
to confirm none of the three apps leaks into or interferes with the
others.

## Structure

- `index.html` — the merged lookup page described above.
- `windows/` — `Winevent-catalogue`'s data and docs, unchanged:
  `data/events.csv`/`.json`, `data/cloud_logs.csv`/`.json`,
  `data/reference/*`, `docs/*`, and its own `README.md` (the full field
  reference for every column).
- `linux/` — `linuxevent-catalogue`'s data and docs, unchanged:
  `data/events.csv`/`.json`, `data/reference/*`, `docs/*`, and its own
  `README.md`.
- `threat-detection/` — `Threat-detection-library`'s data, docs, schema,
  and build tooling, unchanged: `data/*.json` (the fourteen detection
  catalogues plus the MITRE technique files the Heat Coverage tab fetches
  at runtime), `docs/*`, `schema/*.schema.json`, `tools/*.py`, and its own
  `README.md`, `CHANGELOG.md`, `VERSION`.

These directories are kept for anyone who wants the raw data (e.g. to load
into Splunk, or to extend a catalogue — see each source repo's README for
how). `index.html` doesn't read from `windows/` or `linux/` at runtime
(each of those apps' data is already embedded in the page); it does read
from `threat-detection/data/` for the Heat Coverage fetches described
above.

## Source repos

- [`Winevent-catalogue`](https://github.com/adamliq/Winevent-catalogue)
- [`linuxevent-catalogue`](https://github.com/adamliq/linuxevent-catalogue)
- [`Threat-detection-library`](https://github.com/adamliq/Threat-detection-library)

To extend any catalogue, edit the source repo the normal way, then
regenerate this compendium's `index.html` from its updated `index.html`
export.
