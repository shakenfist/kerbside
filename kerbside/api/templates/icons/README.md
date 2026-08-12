The following material designs icons are used here:

* audit: "event list" (https://fonts.google.com/icons?selected=Material%20Symbols%20Outlined%3Aevent_list%3AFILL%400%3Bwght%40400%3BGRAD%400%3Bopsz%4048)
* sessions: "group" (https://fonts.google.com/icons?selected=Material%20Symbols%20Outlined%3Agroup%3AFILL%400%3Bwght%40400%3BGRAD%400%3Bopsz%4048)
* tokens: "key" (https://fonts.google.com/icons?selected=Material%20Symbols%20Outlined%3Akey%3AFILL%400%3Bwght%40400%3BGRAD%400%3Bopsz%4048)

These SVGs are included inline as Jinja templates
(`{% include 'icons/audit.svg' %}` and so on) rather than served as
static `<img>` assets. An SVG loaded through `<img>` is rendered as an
isolated document: its `currentColor` resolves against that document's
own root, not the surrounding page, so a `fill="currentColor"` glyph
loaded that way stays whatever color it was authored with and can
never follow the page's light/dark palette. Included inline, the same
markup becomes part of the page's own DOM, so `currentColor` resolves
against the enclosing element and the glyph takes the surrounding text
color in both palettes.

Each root `<svg>` here carries `fill="currentColor"`, a 21px
`width`/`height` (the size used everywhere these icons appear), and
`aria-hidden="true"` — every use sits beside text or inside a labelled
control, so announcing the icon to assistive technology would only
duplicate that label.
