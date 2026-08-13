#!/usr/bin/env python3

"""Render a converted sfui template through the Flask test client, so a
reviewer can screenshot it in both palettes without deploying kerbside.

sfui has no CI of its own and nothing in kerbside's tox lanes lints
templates or CSS, so the only safety net for the chrome a phase of the
sfui conversion ships is a human looking at rendered pixels. This script
does the part of that which does not need a browser: it drives the page
through kerbside.api's own test client (so routing, context and Jinja
rendering are exactly what a real request would produce), writes the
body next to a symlink of the real static tree (templates use
root-relative asset paths like /static/sfui/..., so the output directory
has to look like the app's document root), and prints the two commands
that turn that into a screenshot.

Only pages that have actually been converted onto base-sfui.html are
listed in PAGES below -- this script must never invent fixtures for a
page that has not been converted yet. Today that is 'login' and
'consoles': login is an unauthenticated GET / that renders directly, no
database and no JWT needed; consoles needs both mocked. Phase 6 converts
the sessions, sources and audit pages, each of which needs authentication
and one or more kerbside.db calls mocked; add them as further entries in
PAGES, each carrying whatever list of (target, patch kwargs) pairs its
route needs, rather than restructuring this script.
"""

import argparse
import copy
import os
import sys
from unittest import mock

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, REPO_ROOT)

try:
    from kerbside import api  # noqa: E402
    from kerbside.tests.unit.test_api_html import CONSOLE  # noqa: E402
except ImportError as e:
    # kerbside's dependencies are not installed system wide, so a bare
    # system python3 gets a bare ModuleNotFoundError here. Say which
    # interpreter to use instead, rather than making the reader work it
    # out from the name of whichever import happened to fail first.
    raise SystemExit(
        'cannot import kerbside (%s).\n\n'
        'This script needs an interpreter with kerbside\'s dependencies '
        'installed.\nAfter a tox run that is .tox/py3/bin/python:\n\n'
        '    .tox/py3/bin/python %s ...\n' % (e, sys.argv[0]))


# Each entry is keyed by the page name accepted on the command line, and
# maps to a dict with:
#
#   'route': the URL to GET with an 'Accept: text/html' header.
#   'patches': a list of (dotted target, mock.patch kwargs) pairs applied
#       for the duration of the request, innermost last. Empty for a page
#       that needs neither authentication nor the database, like login.
#
# A future authenticated page looks like:
#
#   'source': {
#       'route': '/source',
#       'patches': [
#           ('kerbside.api.verify_jwt_in_request',
#            {'return_value': (None, {})}),
#           ('kerbside.api.db.get_sources', {'return_value': [...]}),
#       ],
#   },
#
# The consoles entry below follows that shape, reusing the smoke test's
# CONSOLE fixture rather than duplicating it -- a second, no-sessions
# variant sits alongside it so one screenshot shows both terminate
# states: the disclosure of two-step buttons, and the dim zero badge.
QUIET_CONSOLE = copy.deepcopy(CONSOLE)
QUIET_CONSOLE.update({
    'name': 'quietvm', 'uuid': 'u-5678', 'sessions': [], 'token_count': 0,
    'audit': [],
})

PAGES = {
    'login': {
        'route': '/',
        'patches': [],
    },
    'consoles': {
        'route': '/console',
        'patches': [
            ('kerbside.api.verify_jwt_in_request',
             {'return_value': (None, {})}),
            ('kerbside.api.db.get_consoles',
             {'return_value': [copy.deepcopy(CONSOLE), QUIET_CONSOLE]}),
        ],
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Render a converted sfui template through the Flask test '
            'client and write it, alongside a symlink of the real static '
            'tree, so it can be served and screenshotted in both '
            'palettes without a deployed kerbside.'))
    parser.add_argument(
        'page', choices=sorted(PAGES.keys()),
        help='Which converted page to render.')
    parser.add_argument(
        'output_dir',
        help='Directory to write <page>.html and the static/ symlink into. '
             'Created if it does not exist.')
    return parser.parse_args()


def render(page, output_dir):
    spec = PAGES[page]

    patches = [
        mock.patch(target, **kwargs) for target, kwargs in spec['patches']]
    for patch in patches:
        patch.start()
    try:
        api.app.config['TESTING'] = True
        resp = api.app.test_client().get(
            spec['route'], headers={'Accept': 'text/html'})
        assert resp.status_code == 200, (
            'expected 200 rendering %s, got %s' % (
                spec['route'], resp.status_code))
        body = resp.get_data(as_text=True)
    finally:
        for patch in patches:
            patch.stop()

    os.makedirs(output_dir, exist_ok=True)

    page_path = os.path.join(output_dir, '%s.html' % page)
    with open(page_path, 'w') as f:
        f.write(body)

    # Templates reference their assets as root-relative absolute paths
    # (/static/sfui/...), so the output directory needs a static/ entry
    # that resolves the same way a deployed kerbside's document root
    # would. Re-point the symlink if one is already there -- this script
    # is meant to be re-run as a page is iterated on.
    static_link = os.path.join(output_dir, 'static')
    if os.path.islink(static_link):
        os.unlink(static_link)
    elif os.path.exists(static_link):
        raise SystemExit(
            '%s exists and is not a symlink; refusing to remove it' %
            static_link)
    os.symlink(api.app.static_folder, static_link)

    return page_path


def main():
    args = parse_args()

    page_path = render(args.page, args.output_dir)

    print('wrote %s' % page_path)
    print('static/ symlinked to %s' % api.app.static_folder)
    print()
    print('Serve it over HTTP -- not file://, the components are ES '
          'modules -- and screenshot with headless Chromium:')
    print()
    print('    (cd %s && python3 -m http.server 8099) &' % args.output_dir)
    print()
    print('    chromium --headless --disable-gpu --no-sandbox \\')
    print('        --hide-scrollbars --window-size=1280,1000 \\')
    print('        --virtual-time-budget=4000 \\')
    print('        --screenshot=/tmp/%s-dark.png \\' % args.page)
    print('        http://localhost:8099/%s.html' % args.page)
    print()
    print('Add --blink-settings=preferredColorScheme=2 for the light '
          'palette -- headless Chromium reports prefers-color-scheme: '
          'dark by default.')


if __name__ == '__main__':
    main()
