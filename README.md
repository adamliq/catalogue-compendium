# catalogue-compendium

A single entry point for [`Winevent-catalogue`](https://github.com/adamliq/Winevent-catalogue)
(4,737 Windows Event Log events) and
[`linuxevent-catalogue`](https://github.com/adamliq/linuxevent-catalogue)
(77 Linux security/system events), merged into one self-contained web app
with a menu to switch between them.

## Web lookup

`index.html` is a single, self-contained page (no build step, no external
requests) — open it directly in a browser. A menu bar at the top switches
between **Windows Events** and **Linux Events**; each is the exact lookup
tool from its source repo (search, log/category filters, reference tables,
schema explorer, pivot explorer, cloud logs, auditd/fapolicyd rule
browsers, and so on), running independently side by side on the same page.
Your last-chosen tab is remembered (`localStorage`) across visits.

The two catalogues are **not** merged at the data level: they keep their
own event-ID schemes, column schemas, and reference tables exactly as
authored in their source repos (see each repo's README for the full field
reference). This page only merges the *presentation* — one URL, one menu —
not the underlying schemas.

### How the merge was built

Both source `index.html` files embed their entire app (styles, markup, and
a large inline `DATA` blob) in one file, and both reuse a lot of the same
generic naming (`.panel`, `.combo`, `.tab`, ids like `search`/`list`/
`detail`/`tabs`, etc.) since the Linux catalogue was deliberately built to
mirror the Windows one's UI conventions. Concatenating them naively would
collide: matching CSS selectors would bleed across apps, and shared
`id="..."` values would make `getElementById` return the wrong app's
element.

So each app was mechanically namespaced before merging:

- Every element `id`/`for` gets a `win-`/`lnx-` prefix (covering static
  HTML attributes and every dynamic `getElementById`/`querySelector`
  reference, including ones built via string concatenation or template
  literals).
- Each app's `<style>` block is scoped by rewriting every selector to be a
  descendant of that app's own container (`#app-win` / `#app-lnx`),
  including `:root` (→ the container itself, so each app's CSS custom
  properties/theme variables stay independent) and `html`/`body`.
- Each app's script runs inside its own IIFE (so top-level `const`/`let`/
  `function` names in one app never collide with the other's), and every
  `document.querySelector(All)` call is scoped to that app's own container
  element — otherwise a class-based query like `.panel` (used by both
  apps' tab-switching logic) would also match and mutate the *other*
  app's hidden DOM.
- The handful of functions invoked from inline `onclick="..."` attributes
  (which run in global scope, not inside the IIFE) are renamed and
  explicitly exported on `window` under their namespaced names.

Both apps' scripts, and the merged file as a whole, were verified with
`node --check` and exercised end-to-end in headless Chromium (search,
filters, detail views, reference tables, combo boxes, the auditd/
fapolicyd subpanels, the schema-explorer field modal, cross-links like
"opposite outcome"/MITRE/CIM jump links, dark-mode theming, and repeated
tab-switching) to confirm neither app leaks into or interferes with the
other.

## Structure

- `index.html` — the merged lookup page described above.
- `windows/` — `Winevent-catalogue`'s data and docs, unchanged:
  `data/events.csv`/`.json`, `data/cloud_logs.csv`/`.json`,
  `data/reference/*`, `docs/*`, and its own `README.md` (the full field
  reference for every column).
- `linux/` — `linuxevent-catalogue`'s data and docs, unchanged:
  `data/events.csv`/`.json`, `data/reference/*`, `docs/*`, and its own
  `README.md`.

These directories are kept for anyone who wants the raw data (e.g. to load
into Splunk, or to extend a catalogue — see each source repo's README for
how). `index.html` doesn't read from them at runtime; each app's data is
already embedded in the page.

## Source repos

- [`Winevent-catalogue`](https://github.com/adamliq/Winevent-catalogue)
- [`linuxevent-catalogue`](https://github.com/adamliq/linuxevent-catalogue)

To extend either catalogue, edit the source repo the normal way, then
regenerate this compendium's `index.html` from its updated `index.html`
export.
