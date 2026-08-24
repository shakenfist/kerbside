import os
import re
import subprocess

import testtools


def _repo_root():
    """Return the repository root, or None outside a checkout.

    Markdown is repository data, not package data: nothing under docs/
    is beneath a package directory, so setuptools_scm's file finder
    does not contribute it and no wheel contains it. Walk up from
    __file__ for the same reason test_demo_stack.py does.
    """
    path = os.path.dirname(os.path.abspath(__file__))
    while path != '/':
        # os.path.exists, not os.path.isdir: in a git worktree .git is
        # a file holding a gitdir pointer, and this repository is
        # routinely developed in worktrees.
        if os.path.exists(os.path.join(path, '.git')):
            return path
        path = os.path.dirname(path)
    return None


class MarkdownLinkTestCase(testtools.TestCase):
    """Every relative markdown link between our own .md files resolves.

    This is the markdown counterpart of StaticAssetReferenceTestCase in
    test_api_html.py, and it exists for the same reason: nothing but a
    human clicking the link would otherwise notice that a document
    points at a file which is not there. On GitHub a dangling relative
    link renders as live and 404s on click.

    The case that prompted it is the plan directory. `docs/plans/`
    cross-references heavily -- a master plan links each of its phase
    files, and index.md links all of them again -- and the convention
    is that a phase file lands in the same commit as the row which
    references it. A phase row written ahead of its file breaks both
    links at once, and PR #366 did exactly that.

    Deliberately not a markdown parser. The invariant is about the link
    targets the file actually emits, and a regex over the source cannot
    be fooled into resolving a path a reader would not see.
    """

    # ](target) with no whitespace in the target. Reference-style links
    # and bare autolinks are not matched: neither appears in this tree,
    # and a matcher for them would be guessing at syntax we do not use.
    LINK_RE = re.compile(r'\]\(([^)\s]+?)\)')

    def _markdown_files(self, root):
        """Tracked .md files, so a developer's scratch notes are exempt."""
        try:
            out = subprocess.check_output(
                ['git', 'ls-files', '-z', '*.md'], cwd=root, text=True)
        except (OSError, subprocess.CalledProcessError) as e:
            raise self.skipException('cannot list tracked files: %s' % e)
        return [f for f in out.split('\0') if f]

    def test_relative_markdown_links_resolve(self):
        root = _repo_root()
        if root is None:
            raise self.skipException(
                'no checkout above %s; markdown does not ship in the '
                'wheel' % os.path.abspath(__file__))

        files = self._markdown_files(root)

        checked = 0
        dangling = []
        for relpath in files:
            source = os.path.join(root, relpath)
            with open(source, encoding='utf-8') as f:
                body = f.read()

            for target in self.LINK_RE.findall(body):
                # Leave external links, in-page anchors and mail links
                # to a link checker with a network. This test is about
                # the tree on disk.
                if '://' in target or target.startswith(('#', 'mailto:')):
                    continue

                # Strip an anchor or query before hitting the
                # filesystem, and only claim to check .md targets --
                # a link to a directory or an image is a different
                # invariant with different failure modes.
                path = target.split('#')[0].split('?')[0]
                if not path.endswith('.md'):
                    continue

                checked += 1
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(source), path))
                if not os.path.isfile(resolved):
                    dangling.append(
                        '%s links to %s, which does not resolve (looked '
                        'for %s)' % (relpath, target,
                                     os.path.relpath(resolved, root)))

        # A tree that produced no links at all would otherwise pass
        # vacuously, which is the failure this test is here to catch.
        self.assertNotEqual(
            0, checked, 'no relative .md links found in %d markdown '
            'files; the matcher has stopped matching' % len(files))

        self.assertEqual([], dangling, '\n'.join(dangling))
