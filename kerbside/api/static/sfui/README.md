# sfui: Shaken Fist web UI components

This is the design system for Shaken Fist web interfaces: CSS
design tokens with dark and light palettes, a shared page
stylesheet of `.sf-*` primitives, a theme boot script, the brand
asset, and Lit web components. It is deliberately self-contained:
nothing in here imports from or knows about any host application,
there is no build step, and no JavaScript toolchain is required
to consume it.

The canonical copy lives at https://github.com/shakenfist/sfui,
and each project with a web UI vendors a copy. **If you are
reading this inside another repository's static assets, you are
looking at a vendored copy: never edit it in place** -- change
the canonical repository and re-vendor, otherwise the next sync
silently discards your change.

## Who it is for

Shaken Fist projects with a web UI (the private-ci conductor
dashboard and the kerbside admin UI today). It is not a
general-purpose framework: no grid system, no utility classes,
and a component only exists once two dashboards needed it.

## Using it

Vendor the distributable files into your static assets from a
checkout of this repository:

    tools/vendor.sh <consumer>/static/sfui

Then opt a page in by including, in this order in `<head>`:

    <script src="/static/sfui/sf-theme.js"></script>
    <link rel="stylesheet" href="/static/sfui/tokens.css">
    <link rel="stylesheet" href="/static/sfui/sf.css">

and putting `sf-page` on `<body>`. Nothing applies until a page
opts in, so vendoring is safe long before any page converts.
`tools/vendor.sh --check <target>` reports drift in an existing
copy, and the fleet-wide `sfui-vendor` audit does the same daily.

To review the system itself, serve the repository root
(`python3 -m http.server`) and open `demo.html`, which renders
every primitive and component in both palettes.

## Documentation

The full specification lives in `docs/` in the canonical
repository:

- [Design tokens and theming](https://github.com/shakenfist/sfui/blob/develop/docs/design-tokens.md)
  -- the token vocabulary, the two palettes, and the branding
  rules.
- [Page styles](https://github.com/shakenfist/sfui/blob/develop/docs/page-styles.md)
  -- the `.sf-*` primitives, cascade layering, naming rules, and
  the tuning knobs.
- [Components](https://github.com/shakenfist/sfui/blob/develop/docs/components.md)
  -- the component contract ("data in, events out") and the page
  infrastructure that surrounds it.
- [Vendoring](https://github.com/shakenfist/sfui/blob/develop/docs/vendoring.md)
  -- the distributable set, the vendored Lit and morphdom
  libraries, and how consumers stay current.
- [Consistency auditing](https://github.com/shakenfist/sfui/blob/develop/docs/consistency-audit.md)
  -- the mechanical rules the design system is held to.
- [Testing](https://github.com/shakenfist/sfui/blob/develop/docs/testing.md)
  -- running the linters and the Playwright test suite locally.

Contributor notes for AI assistants are in
[AGENTS.md](https://github.com/shakenfist/sfui/blob/develop/AGENTS.md),
and the repository structure is described in
[ARCHITECTURE.md](https://github.com/shakenfist/sfui/blob/develop/ARCHITECTURE.md).

## License

Apache 2.0, except the vendored `lit-core.min.js` (BSD-3-Clause)
and `morphdom-umd.js` (MIT), which are unmodified upstream
single-file bundles.
