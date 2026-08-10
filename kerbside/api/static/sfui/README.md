# sfui: Shaken Fist web UI components

This is the design system for Shaken Fist web interfaces. The
canonical copy lives at https://github.com/shakenfist/sfui, and
each project with a web UI vendors a copy (the same pattern as
shakenfist/development's `templates/shared-blocks/`: canonical
copy in one repo, synced copies downstream, a consistency audit
to catch drift). If you are reading this inside another
repository's static assets, you are looking at a vendored copy:
never edit it in place -- change the canonical repository and
re-vendor (see Vendoring into a consumer).

sfui is deliberately self-contained: nothing in here imports from
or knows about any host application, there is no build step, and
no JavaScript toolchain is required to consume it.

## Layout

    tokens.css        Design tokens: the shared visual vocabulary
    sf.css            Shared page styles: the .sf-* page
                      primitives (see Page styles)
    sf-theme.js       Theme boot script: page infrastructure, not
                      a component (see Page infrastructure)
    shakenfist-logo.svg  Brand asset: the canonical Shaken Fist
                      logo with the viewBox tightened to the globe
                      mark (the embedded wordmark is dark teal and
                      unreadable on the dark theme; pages supply
                      their own heading text)
    lit-core.min.js   Vendored Lit runtime (see Vendored
                      dependencies)
    morphdom-umd.js   Vendored morphdom library (see Vendored
                      dependencies)
    components/       One file per component, named after its
                      element

The canonical repository additionally carries `tools/` (the
vendor script), `docs/`, and `demo.html` (see Page styles); those
are not part of the vendored set. A vendored copy instead carries
`.sfui-commit`, the source commit it was vendored from.

## Design tokens

`tokens.css` defines every color as a CSS custom property with an
`--sf-` prefix, together with the *meaning* of each token. Tokens
are the theming contract: pages link the stylesheet, and components
reference the tokens from inside their shadow DOM, which custom
properties pierce by design.

Rules:

- Every color in a Shaken Fist web UI comes from a token. No
  hardcoded colors in pages or components, with one exception:
  a component may repeat a token's dark default as a `var()`
  fallback (`var(--sf-red, #f87171)`) so it degrades sanely on a
  page that forgot the stylesheet. Fallbacks must match the
  `:root` (dark) values in `tokens.css` exactly.
- A page needing a translucent tint of a token (badge and banner
  fills) derives it with `color-mix(in srgb, var(--sf-*) N%,
  transparent)`, never by restating the color as an `rgba()`
  literal, so tints follow the active palette automatically.
- Choose tokens by meaning, not appearance: `--sf-red` because the
  thing is broken, never because red looks right next to the thing
  beside it. The semantics are documented in `tokens.css`.
- New tokens are added rarely and deliberately; a new color that is
  really "amber, but for my panel" is the existing token.

## Page styles

`sf.css` is the shared page-level stylesheet: the primitives a
Shaken Fist page is built from -- chrome (`.sf-page`,
`.sf-container`, `.sf-header`, `.sf-footer`, `.sf-status-line`),
content (`.sf-section`, `.sf-card`, `.sf-table`, `.sf-btn`,
`.sf-badge`, `.sf-code`, `.sf-banner`, `.sf-empty`,
`.sf-footnote`), disclosures and form controls. It exists so two
projects do not write a table style twice and then drift. It is
not a framework: no grid system, no utility vocabulary, no
JavaScript, and no opinion about layout beyond a centered
container.

Everything in it lives in the `sfui` cascade layer, in the
sub-layers `sfui.reset`, `sfui.base`, `sfui.components` and
`sfui.utilities`. Unlayered rules beat layered ones whatever
their specificity, so **a page's own styles always win over
`sf.css`**, with no `!important` and no specificity contest.
That is what makes adoption incremental: a page takes one
primitive at a time and keeps local overrides for the rest.

Nothing in it applies until `<body>` carries the `sf-page` class.
The reset and the element-level base rules are gated on that
class, so linking the stylesheet changes nothing until a page
opts in -- which is what lets a consumer vendor the file long
before any of its pages is ready to use it. Without the gate,
`* { margin: 0; padding: 0 }` would flatten every page that
merely linked it.

Naming, matching the element and event conventions:

- Component classes are single `.sf-*` classes with BEM-style
  `--` modifiers: `.sf-btn`, `.sf-btn--danger`, `.sf-btn--sm`. A
  modifier never styles anything on its own; it augments the base
  class. A component may reach its own structural children by
  element name (`.sf-table th`, `.sf-header h1`), and nothing
  else.
- A class never shares a name with an sfui custom element:
  differing from the element by only a leading dot is a
  readability trap, so `.sf-tabs` and `.sf-theme-toggle` are
  reserved and unused. Where those elements need page-level
  placement the rule is written against the element
  (`:where(.sf-page) :where(sf-tabs)`).
- Element-level base rules take the `:where(.sf-page) :where(a)`
  form, i.e. zero specificity, so even a bare `a {}` in a page
  overrides them.
- No `!important`, no id selectors, and no color that is not a
  token or a `color-mix()` of one. Every tinted fill in the
  stylesheet -- badges, banners -- is the same 15% mix, so a new
  primitive has one strength to match rather than a choice to
  make.

The non-color custom properties live in `sf.css` rather than
`tokens.css`: that file's remit is color, and its central
invariant -- every token defined in both palettes -- is
meaningless for a font stack, so putting one there would weaken
an audit rule that currently has teeth. `sf.css` therefore
defines `--sf-font-sans`, `--sf-font-mono` and the radius scale
`--sf-radius-sm` / `--sf-radius` / `--sf-radius-lg` (4px / 6px /
8px, which the components use too), plus four documented knobs:

    --sf-container-max     .sf-container's max width; 1100px by
                           default, set it to 100% for a
                           full-bleed page
    --sf-page-pad          .sf-page's padding; the default drops
                           from 2rem to 1rem under 700px
    --sf-code-max-height   how tall .sf-code grows before it
                           scrolls
    --sf-table-cell-pad    .sf-table's th and td padding

Per-page tuning is by knob first, unlayered override second. All
of them are declared on `:root`, so a page overrides one for the
whole page or sets it on a subtree for one component.

A page opts in by including, in this order in `<head>`:

    <script src="/static/sfui/sf-theme.js"></script>
    <link rel="stylesheet" href="/static/sfui/tokens.css">
    <link rel="stylesheet" href="/static/sfui/sf.css">

and putting `sf-page` on `<body>`. The order matters: the theme
script stamps `data-theme` before first paint, `tokens.css`
defines the colors `sf.css` consumes, and a page's own styles
come after both.

`demo.html`, at the repository root, renders every class and
modifier `sf.css` defines, plus the `sf-tabs` and
`sf-theme-toggle` components, so the stylesheet can be reviewed
in both palettes without a consumer application. It is the
canonical repository's safety net against an unreviewed
primitive -- there is no CI here and nothing lints CSS -- and it
is **not** part of the distributable set: like `docs/` and
`tools/`, consumers do not carry it. Because its components are
ES modules, it must be served over HTTP rather than opened as a
`file://` URL:

    python3 -m http.server

from the repository root.

## Theming

sfui is two-theme: `tokens.css` defines the dark palette as the
`:root` default and a light palette under
`:root[data-theme="light"]`, behind the same semantic token
names. Every token must be defined in both palettes. The light
palette is a re-tuning, not an inversion -- the dark values are
bright pastels chosen against a near-black background, so each
light status color is a darker weight of the same hue, holding
WCAG AA contrast against the light surfaces for text-sized uses.

There are deliberately no `prefers-color-scheme` media queries in
`tokens.css`: the theme boot script (`sf-theme.js`, see Page
infrastructure) resolves the user's preference -- an `sf-theme`
cookie holding `light` or `dark`, or absent meaning "follow the
operating system" -- and always stamps a concrete `data-theme` on
the document element before first paint. The CSS therefore has
exactly two states and no media-query palette copy to drift.

A page opts in by including, in this order in `<head>`:

    <script src="/static/sfui/sf-theme.js"></script>
    <link rel="stylesheet" href="/static/sfui/tokens.css">

and typically offers an `<sf-theme-toggle>` wired to
`window.sfTheme` for the user to change the preference.

Branding is part of theming: `--sf-brand` (the Shaken Fist teal)
lives in the page chrome -- logo lockup, header accents -- and
never carries meaning in the content area, where the semantic
tokens own color. Subtle is the intent; the logo plus a teal
accent in the header is usually all a page needs. The reference
treatment is the conductor dashboard header: the globe mark
(`shakenfist-logo.svg`) sits beside the page heading, and the
header's bottom rule mixes the brand teal into the border color
(`color-mix(in srgb, var(--sf-brand) 45%, var(--sf-border))`).

## Page infrastructure

Not everything in sfui is a component. `sf-theme.js` is page-level
infrastructure: a small classic (non-module) script that pages
include with a synchronous `<script>` tag in `<head>`, before the
tokens stylesheet. It reads the `sf-theme` preference cookie,
resolves the "auto" state against `prefers-color-scheme`, and
stamps a concrete `data-theme` on the document element before
first paint, so there is no flash of the wrong theme. It exposes
`window.sfTheme` (`preference`, `set()`) for pages to wire theme
controls to; the contract is documented in the file header.

The distinction matters for the component contract below:
infrastructure may touch cookies and the document element
precisely because components never do. A component that wants to
change the theme emits an event; the page calls `sfTheme.set()`.

## Component contract

Components are standard Web Components built with Lit, and every
one of them follows these rules:

1. **Data in, events out.** Input arrives through properties
   (complex values as properties, not attributes); output leaves as
   `CustomEvent`s. Components never fetch, never read or write
   `location`, `history` or storage, and never contain application
   judgement. What a badge *means*, which panel a tab *shows*, what
   is *actionable* -- that is host-page policy, computed by the
   page and handed to the component as data. This split is what
   makes a component reusable across dashboards whose semantics
   differ.
2. **Names are namespaced.** Elements are `sf-*` (one component per
   file, the file named after the element), and dispatched events
   are `sf-*` too.
3. **Shadow DOM, styled by tokens.** Components render into shadow
   DOM and take all colors from design tokens (with matching
   fallbacks, per the token rules). Corner radii work the same
   way: `var(--sf-radius, 6px)` rather than a literal, with the
   fallback matching `sf.css`'s value exactly, so a component
   follows the page's radius scale where one is loaded and looks
   unchanged where it is not. Other sizing and spacing may be
   local, but should stay visually consistent with the existing
   components.
4. **The contract is documented in the file header:** properties,
   events, and anything the host page is expected to do. A reader
   should be able to use the component without reading its
   implementation.
5. **Accessible by default.** Appropriate ARIA roles and keyboard
   operation are part of the component, not the host page's
   problem.
6. **No dependencies beyond Lit** (and other sfui components). A
   component that needs a library is a design smell to discuss
   first.

## Auditing for consistency

The point of the rules is that they are mechanically checkable.
An audit (by hand or by an agent) should confirm:

- No hex colors outside `tokens.css`, except `var()` fallbacks
  whose values match `tokens.css` exactly:
  `grep -rn '#[0-9a-f]\{6\}' components/ sf.css` and compare.
  `sf.css` carries no fallbacks, so its share of that grep is
  zero matches.
- No `var(--` references to tokens that `tokens.css` or `sf.css`
  does not define (a typo'd token silently falls back).
- Every custom element and every dispatched event name starts with
  `sf-`: `grep -rn 'customElements.define\|CustomEvent' components/`.
- No component imports anything but `../lit-core.min.js` or a
  sibling component, and none references `fetch`, `location`,
  `history`, `localStorage` or host-page element ids.
- Host pages set component state only through documented
  properties, and react only to documented events.
- Every token is defined in both palettes: the custom property
  names in the `:root` block of `tokens.css` and in its
  `[data-theme="light"]` block are identical sets.
- No `rgba()` or hex color literals in `sf.css` or in host pages
  either -- translucent tints are `color-mix()` on tokens:
  `grep -n 'rgba(\|#[0-9a-f]\{6\}' sf.css <page>` should return
  nothing at all for `sf.css`, and for a page only `var()`
  fallbacks whose values match the dark defaults.
- `--sf-brand` appears only in page chrome (headers, logo
  lockups), never on content-area elements whose color conveys
  state. `sf.css`'s `.sf-header` is chrome by definition and is
  the one place in the stylesheet the token appears.

## Vendored dependencies

- `lit-core.min.js`: Lit 3.3.1 core bundle, BSD-3-Clause,
  unmodified from
  https://cdn.jsdelivr.net/gh/lit/dist@3.3.1/core/lit-core.min.js.
  Single-file ES module; no npm, no build step, which is a
  property to preserve -- consumers of sfui should never need a
  JavaScript toolchain to ship.
- `morphdom-umd.js`: morphdom 2.7.7, MIT, unmodified from
  https://unpkg.com/morphdom@2.7.7/dist/morphdom-umd.js. Consumers
  use it directly for poll-and-morph page refresh -- fetching a
  fresh fragment and morphing it into the live DOM so scroll
  position, focus and open disclosures survive a refresh. Like Lit,
  a single file with no npm and no build step, a property to
  preserve.

## Vendoring into a consumer

A consumer keeps a vendored copy of the distributable set (the
Layout list above) in its static assets, conventionally at a
path ending in `sfui/`. From a checkout of this repository:

    tools/vendor.sh <consumer>/static/sfui

copies the distributable files into the target and records the
source commit in `<target>/.sfui-commit`. The same script checks
an existing copy for drift without writing anything:

    tools/vendor.sh --check <consumer>/static/sfui

which exits non-zero on any difference, so consumers can wire it
into CI or a pre-commit hook. The rule matches shared-blocks:
never edit a vendored copy directly -- fix the canonical file
here and re-vendor, otherwise the next sync silently discards
the local change.

Current consumers:

- private-ci: the conductor dashboard, vendored at
  `conductor/static/sfui/`. Its header is the reference brand
  treatment (see Theming).
- kerbside: expected next, when its admin UI converts to sfui.

## Components

- `sf-tabs`: tab strip with notification badges. See the file
  header in `components/sf-tabs.js` for the contract.
- `sf-theme-toggle`: three-state (auto/light/dark) theme
  preference control, wired by the host page to `sf-theme.js`.
  See the file header in `components/sf-theme-toggle.js` for the
  contract.
